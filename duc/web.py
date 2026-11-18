"""Unprivileged web UI with mandatory TOTP, CSRF, and agent-over-Unix-socket."""
import hashlib
import hmac
import ipaddress
import io
import json
import os
import pathlib
import secrets
import time
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
import httpx
from pydantic import BaseModel

from . import mfa

AUTH_PATH = pathlib.Path(os.environ.get('DUC_WEB_AUTH', '/etc/dns-unified/web-auth.json'))
MFA_PATH = pathlib.Path(os.environ.get('DUC_MFA_PATH', str(mfa.DEFAULT_PATH)))
SOCKET = os.environ.get('DUC_AGENT_SOCKET', '/run/dns-unified-agent.sock')
STATIC = pathlib.Path(__file__).resolve().parent.parent / 'web'
COOKIE_SECURE = os.getenv('DUC_COOKIE_SECURE', '0') == '1'
TRUST_LOCAL_PROXY = os.getenv('DUC_TRUST_LOCAL_PROXY', '0') == '1'
SESSIONS = {}
ATTEMPTS = defaultdict(list)
SESSION_MAX = 4 * 3600
IDLE_MAX = 30 * 60
PREAUTH_MAX = 10 * 60
app = FastAPI(title='DNS Unified Control', docs_url=None, redoc_url=None, openapi_url=None)


class LoginBody(BaseModel):
    password: str


class MfaBody(BaseModel):
    code: str


@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


def _ip(request):
    ip = request.client.host if request.client else 'unknown'
    if TRUST_LOCAL_PROXY and ip in ('127.0.0.1', '::1'):
        proxy_ip = request.headers.get('X-DUC-Client-IP', '')
        try:
            ip = str(ipaddress.ip_address(proxy_ip))
        except ValueError:
            pass
    return ip


def _rate(key, max_attempts=8, duration=600):
    now = time.time()
    ATTEMPTS[key] = [t for t in ATTEMPTS[key] if now-t < duration]
    if len(ATTEMPTS[key]) >= max_attempts:
        raise HTTPException(429, 'Too many attempts, try later')
    ATTEMPTS[key].append(now)


def _rate_clear(key):
    ATTEMPTS.pop(key, None)


def _session(request, allowed=('full',)):
    sid = request.cookies.get('duc_session', '')
    now = time.time()
    for key, info in list(SESSIONS.items()):
        if now > info['exp'] or now-info['last'] > IDLE_MAX:
            SESSIONS.pop(key, None)
    s = SESSIONS.get(sid) if sid else None
    if not s or s['stage'] not in allowed or (s['stage'] == 'full' and not s.get('mfa_checked')):
        raise HTTPException(401, 'Sign in and complete two-factor verification')
    # Fail closed if MFA was externally reset: existing sessions must re-login.
    if s['stage'] == 'full':
        try:
            same_generation = hmac.compare_digest(s.get('mfa_generation', ''), mfa.generation(MFA_PATH))
        except (OSError, KeyError, ValueError, TypeError):
            same_generation = False
        if not same_generation:
            SESSIONS.pop(sid, None)
            raise HTTPException(401, 'MFA configuration changed, sign in again')
    s['last'] = now
    return s


def current_session(request):
    return _session(request, ('full',))


def guard(request, write=False):
    s = current_session(request)
    if write:
        _csrf(request, s)
    return s


def _csrf(request, session):
    if not hmac.compare_digest(request.headers.get('X-CSRF-Token', ''), session['csrf']):
        raise HTTPException(403, 'Invalid CSRF token')


def _set_cookie(response, sid, max_age):
    response.set_cookie('duc_session', sid, httponly=True, secure=COOKIE_SECURE,
                        samesite='strict', max_age=max_age, path='/')


def _create_session(response, stage, mfa_checked=False):
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = time.time()
    ttl = SESSION_MAX if stage == 'full' else PREAUTH_MAX
    SESSIONS[sid] = {'csrf': csrf, 'exp': now+ttl, 'last': now,
                     'stage': stage, 'mfa_checked': mfa_checked,
                     'mfa_generation': mfa.generation(MFA_PATH) if mfa_checked else None}
    _set_cookie(response, sid, ttl)
    return {'logged_in': stage == 'full', 'stage': stage, 'csrf': csrf}


def _elevate(request, response):
    _rate_clear('password:' + _ip(request))
    _rate_clear('password:account')
    SESSIONS.pop(request.cookies.get('duc_session', ''), None)
    # All old pre-MFA sessions are invalidated on enrollment.
    return _create_session(response, 'full', mfa_checked=True)


@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')


@app.get('/app.js')
def js():
    return FileResponse(STATIC / 'app.js', media_type='text/javascript')


@app.get('/app.css')
def css():
    return FileResponse(STATIC / 'app.css', media_type='text/css')


@app.get('/api/session')
def session(request: Request):
    try:
        s = _session(request, ('full', 'challenge', 'enroll'))
        return {'logged_in': s['stage'] == 'full', 'stage': s['stage'], 'csrf': s['csrf']}
    except HTTPException:
        return {'logged_in': False, 'stage': 'login'}


@app.post('/api/login')
def login(body: LoginBody, request: Request, response: Response):
    ip = _ip(request)
    _rate('password:' + ip)
    _rate('password:account', max_attempts=40)
    try:
        auth = json.loads(AUTH_PATH.read_text())
    except (OSError, ValueError):
        raise HTTPException(503, 'Password authentication is not configured')
    candidate = hashlib.pbkdf2_hmac('sha256', body.password.encode(),
                                   bytes.fromhex(auth['salt']), 600000)
    if not hmac.compare_digest(candidate.hex(), auth['hash']):
        raise HTTPException(401, 'Invalid credentials')
    SESSIONS.pop(request.cookies.get('duc_session', ''), None)
    stage = 'challenge' if mfa.configured(MFA_PATH) else 'enroll'
    # A password alone can NEVER grant full access.
    return _create_session(response, stage)


@app.post('/api/mfa/setup')
def mfa_setup(request: Request):
    s = _session(request, ('enroll',))
    _csrf(request, s)
    if mfa.configured(MFA_PATH):
        raise HTTPException(409, 'MFA already configured')
    if 'pending_secret' not in s:
        s['pending_secret'] = mfa.new_secret()
    return {'secret': s['pending_secret'], 'otpauth_uri': mfa.provisioning_uri(s['pending_secret']),
            'qr_path': '/api/mfa/qr'}


@app.get('/api/mfa/qr')
def mfa_qr(request: Request):
    s = _session(request, ('enroll',))
    if mfa.configured(MFA_PATH) or not s.get('pending_secret'):
        raise HTTPException(404, 'No pending enrollment')
    import qrcode
    import qrcode.image.svg
    uri = mfa.provisioning_uri(s['pending_secret'])
    qr = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=6, border=3)
    buf = io.BytesIO()
    qr.save(buf)
    from fastapi import Response as FastResponse
    return FastResponse(buf.getvalue(), media_type='image/svg+xml',
                        headers={'Content-Disposition': 'inline; filename="totp-setup.svg"',
                                 'X-Content-Type-Options': 'nosniff'})


@app.post('/api/mfa/activate')
def mfa_activate(body: MfaBody, request: Request, response: Response):
    s = _session(request, ('enroll',))
    _csrf(request, s)
    if mfa.configured(MFA_PATH):
        raise HTTPException(409, 'MFA already configured')
    secret = s.get('pending_secret')
    if not secret:
        raise HTTPException(400, 'Start enrollment first')
    _rate('mfa:' + _ip(request), max_attempts=6)
    _rate('mfa:account', max_attempts=12)
    step = mfa.matched_step(secret, body.code)
    if step is None:
        raise HTTPException(401, 'Invalid verification code')
    codes = mfa.generate_recovery_codes()
    try:
        mfa.activate(MFA_PATH, secret, step, codes)
    except ValueError:
        raise HTTPException(409, 'MFA already configured')
    _rate_clear('mfa:' + _ip(request))
    _rate_clear('mfa:account')
    elevated = _elevate(request, response)
    return {**elevated, 'recovery_codes': codes}


@app.post('/api/mfa/verify')
def mfa_verify(body: MfaBody, request: Request, response: Response):
    s = _session(request, ('challenge',))
    _csrf(request, s)
    _rate('mfa:' + _ip(request), max_attempts=6)
    _rate('mfa:account', max_attempts=12)
    if not mfa.configured(MFA_PATH):
        raise HTTPException(409, 'MFA was reset; sign in again')
    result = mfa.use_code(MFA_PATH, body.code.strip())
    if not result:
        raise HTTPException(401, 'Invalid or already used verification code')
    _rate_clear('mfa:' + _ip(request))
    _rate_clear('mfa:account')
    elevated = _elevate(request, response)
    return {**elevated, 'used_recovery': result == 'recovery'}


@app.get('/api/mfa/status')
def mfa_status(request: Request):
    guard(request)
    return {'enabled': True, 'recovery_codes_remaining': mfa.recovery_count(MFA_PATH),
            'period_seconds': mfa.STEP_SECONDS}


@app.post('/api/mfa/recovery/rotate')
def mfa_rotate(body: MfaBody, request: Request):
    guard(request, True)
    _rate('rotate:' + _ip(request), max_attempts=6)
    codes = mfa.rotate_recovery(MFA_PATH, body.code)
    if not codes:
        raise HTTPException(401, 'A fresh authenticator code is required')
    _rate_clear('rotate:' + _ip(request))
    # Revokes all other sessions when emergency access credentials change.
    SESSIONS[request.cookies.get('duc_session', '')]['mfa_generation'] = mfa.generation(MFA_PATH)
    return {'recovery_codes': codes}


@app.post('/api/logout')
def logout(request: Request, response: Response):
    s = _session(request, ('full', 'challenge', 'enroll'))
    _csrf(request, s)
    SESSIONS.pop(request.cookies.get('duc_session'), None)
    response.delete_cookie('duc_session', path='/')
    return {'ok': True}


async def agent_request(method, path, data=None, timeout=38):
    try:
        transport = httpx.AsyncHTTPTransport(uds=SOCKET)
        async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
            r = await client.request(method, 'http://agent'+path, json=data)
            r.raise_for_status()
            return r.json()
    except httpx.HTTPStatusError as exc:
        raise HTTPException(exc.response.status_code, exc.response.text[:1000])
    except (OSError, httpx.RequestError) as exc:
        raise HTTPException(503, 'Privileged agent unavailable: '+type(exc).__name__)


@app.get('/api/dns/check')
async def check_dns(request: Request):
    guard(request)
    return await agent_request('GET', '/dns/check')


@app.get('/api/status')
async def status(request: Request):
    guard(request)
    return await agent_request('GET', '/status')


@app.get('/api/metrics')
async def metrics(request: Request):
    guard(request)
    return await agent_request('GET', '/metrics')


@app.get('/api/logs/{engine}')
async def logs(engine: str, request: Request):
    guard(request)
    if engine not in ('master','slipstream','dnstt','noizdns','vaydns','soar','iodine','dns2tcp','xdns'):
        raise HTTPException(404, 'Unknown engine')
    return await agent_request('GET', '/logs/'+engine)


@app.post('/api/profile/{engine}')
async def profile(engine: str, request: Request):
    guard(request, True)
    if engine not in ('master','slipstream','dnstt','noizdns','vaydns','soar','iodine','dns2tcp','xdns'):
        raise HTTPException(404, 'Unknown engine')
    body = await request.json()
    return await agent_request('POST', '/profile/'+engine, body)


@app.post('/api/switch')
async def switch(request: Request):
    guard(request, True)
    body = await request.json()
    if body.get('engine') not in ('master','slipstream','dnstt','noizdns','vaydns','soar','iodine','dns2tcp','xdns','none') or type(body.get('restart', False)) is not bool:
        raise HTTPException(422, 'Unknown engine')
    return await agent_request('POST', '/switch', body)


@app.get('/api/dns/plan')
async def dns_plan(request: Request):
    guard(request)
    return await agent_request('GET', '/dns/plan')




@app.get('/api/workflow/readiness')
async def workflow_readiness(request:Request):
    guard(request)
    return await agent_request('GET','/workflow/readiness')


@app.get('/api/workflow/overview')
async def workflow_overview(request:Request):
    guard(request)
    return await agent_request('GET','/workflow/overview')

@app.get('/api/workflow/soar/status')
async def soar_status(request: Request):
    guard(request)
    return await agent_request('GET','/workflow/soar/status')

@app.get('/api/workflow/shared-socks/status')
async def shared_socks_status(request:Request):
    guard(request)
    return await agent_request('GET','/workflow/shared-socks/status')

@app.post('/api/workflow/shared-socks/activate')
async def shared_socks_activate(request:Request):
    guard(request,True)
    body=await request.json()
    if (not isinstance(body,dict) or set(body) not in ({'mode','engines','confirm'}, {'mode','engines','confirm','target'}) or
        body.get('mode') not in ('dante','custom','restore') or
        body.get('confirm')!='shared-socks:'+body.get('mode','') or
        not isinstance(body.get('engines'),list)):
        raise HTTPException(422,'Invalid shared backend parameters or confirmation')
    return await agent_request('POST','/workflow/shared-socks/activate',body,timeout=80)

@app.get('/api/workflow/advanced')
async def workflow_advanced(request:Request):
    guard(request)
    return await agent_request('GET','/workflow/advanced')

@app.get('/api/workflow/telemetry')
async def workflow_telemetry(request:Request):
    guard(request)
    return await agent_request('GET','/workflow/telemetry')

@app.post('/api/workflow/telemetry')
async def workflow_import_telemetry(request:Request):
    guard(request,True)
    if int(request.headers.get('content-length','0') or '0')>16000:
        raise HTTPException(413,'Client report too large')
    body=await request.json()
    if not isinstance(body,dict) or set(body)!={'report'} or not isinstance(body['report'],dict):
        raise HTTPException(422,'Expected one report object')
    return await agent_request('POST','/workflow/telemetry',body,timeout=15)


@app.get('/api/workflow/dante/status')
async def dante_status(request:Request):
    guard(request)
    return await agent_request('GET','/workflow/dante/status')

@app.post('/api/workflow/dante/activate')
async def dante_activate(request:Request):
    guard(request,True)
    body=await request.json()
    if body.get('mode') not in ('socks5','ssh') or body.get('confirm')!='activate:'+body.get('mode',''):
        raise HTTPException(422,'Invalid Dante mode or confirmation')
    return await agent_request('POST','/workflow/dante/activate',body,timeout=70)

@app.get('/api/workflow/preflight/slipstream')
async def slipstream_hardware_preflight(request:Request):
    guard(request)
    return await agent_request('GET','/workflow/preflight/slipstream')

@app.get('/api/workflow/guide/{engine}')
async def workflow_guide(engine:str,request:Request,resolver:str='1.1.1.1:53',port:int=2080):
    guard(request)
    from .catalog import ENGINES
    from urllib.parse import urlencode
    if engine not in ENGINES:raise HTTPException(404,'Unknown engine')
    return await agent_request('GET','/workflow/guide/'+engine+'?'+urlencode({'resolver':resolver,'port':port}))

@app.get('/api/workflow/jobs/{action}/{engine}')
async def workflow_job_status(action:str,engine:str,request:Request):
    guard(request)
    from . import jobs
    if action not in jobs.ACTIONS or engine not in jobs.ACTIONS[action]:
        raise HTTPException(404,'Unknown job')
    return await agent_request('GET',f'/workflow/jobs/{action}/{engine}')

@app.post('/api/workflow/jobs/{action}/{engine}')
async def workflow_job_start(action:str,engine:str,request:Request):
    guard(request,True)
    from . import jobs
    if action not in jobs.ACTIONS or engine not in jobs.ACTIONS[action]:
        raise HTTPException(422,'Unsupported operation')
    body=await request.json()
    if not isinstance(body,dict) or body.get('confirm')!=f'{action}:{engine}':
        raise HTTPException(422,'Explicit confirmation required')
    allowed={'confirm','resolver','port'} if action in ('build-client','build-alternate') else {'confirm'}
    if set(body)-allowed or (action in ('build-client','build-alternate') and
            ('resolver' in body and not isinstance(body['resolver'],str) or
             'port' in body and type(body['port']) is not int)):
        raise HTTPException(422,'Invalid build parameters')
    return await agent_request('POST',f'/workflow/jobs/{action}/{engine}',body)

@app.get('/api/workflow/client/options/{engine}')
async def client_options(engine:str,request:Request):
    guard(request)
    from .catalog import ENGINES
    if engine not in ENGINES:raise HTTPException(404,'Unknown engine')
    return await agent_request('GET','/workflow/client/options/'+engine)

@app.get('/api/workflow/client/alternate-download/{engine}')
async def alternate_download(engine:str,request:Request):
    guard(request)
    from . import jobs
    from fastapi.responses import Response
    if engine not in jobs.ACTIONS['build-alternate']:
        raise HTTPException(404,'Unsupported alternate client')
    try:
        transport=httpx.AsyncHTTPTransport(uds=SOCKET)
        async with httpx.AsyncClient(transport=transport,timeout=60) as client:
            r=await client.get('http://agent/workflow/client/alternate-download/'+engine)
            if r.status_code!=200:raise HTTPException(r.status_code,'Alternate client unavailable')
            if len(r.content)>80_000_000:raise HTTPException(413,'Package too large')
            return Response(content=r.content,media_type='application/zip',headers={
                'Content-Disposition':f'attachment; filename="{engine}-alternate-linux-amd64.zip"',
                'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    except (OSError,httpx.RequestError):raise HTTPException(503,'Agent download unavailable')

@app.get('/api/workflow/client/download/{engine}')
async def workflow_download(engine:str,request:Request):
    guard(request)
    from . import jobs
    from fastapi.responses import Response
    if engine not in jobs.BUILDABLE:raise HTTPException(404,'Unsupported download')
    try:
        transport=httpx.AsyncHTTPTransport(uds=SOCKET)
        async with httpx.AsyncClient(transport=transport,timeout=60) as client:
            r=await client.get('http://agent/workflow/client/download/'+engine)
            if r.status_code!=200:raise HTTPException(r.status_code,'Client package unavailable')
            if len(r.content)>80_000_000:raise HTTPException(413,'Package too large')
            return Response(content=r.content,media_type='application/zip',headers={
                'Content-Disposition':f'attachment; filename="{engine}-linux-amd64.zip"',
                'Cache-Control':'no-store',
                'X-Content-Type-Options':'nosniff'})
    except (OSError,httpx.RequestError):
        raise HTTPException(503,'Agent download unavailable')



@app.post('/api/workflow/cloudflare')
async def workflow_cloudflare(request:Request):
    guard(request,True)
    body=await request.json()
    # Filter unknown keys and never echo token in a response.
    if set(body)-{'token','domain','ipv4','dry_run','confirm'}:
        raise HTTPException(422,'Unexpected fields')
    return await agent_request('POST','/workflow/cloudflare',body,timeout=180)

@app.get('/api/workflow/client/guide-zip/{engine}')
async def workflow_guide_zip(engine:str,request:Request,resolver:str='1.1.1.1:53',port:int=2080):
    guard(request)
    from urllib.parse import urlencode
    from .catalog import ENGINES
    from fastapi.responses import Response
    if engine not in ENGINES:raise HTTPException(404,'Unknown engine')
    transport=httpx.AsyncHTTPTransport(uds=SOCKET)
    try:
        async with httpx.AsyncClient(transport=transport,timeout=30) as client:
            r=await client.get('http://agent/workflow/client/guide-zip/'+engine+'?'+urlencode({'resolver':resolver,'port':port}))
            if r.status_code!=200:raise HTTPException(r.status_code,'Guide ZIP unavailable')
            if len(r.content)>3_000_000:raise HTTPException(413,'Guide too large')
            return Response(content=r.content,media_type='application/zip',headers={
                'Content-Disposition':f'attachment; filename="{engine}-client-guide.zip"',
                'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    except (OSError,httpx.RequestError):raise HTTPException(503,'Agent unavailable')

# DUC_MULTI_ADDON_0101
from ducmulti.api import install_web_routes as _duc_multi_web
_duc_multi_web(app,guard,agent_request,STATIC)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8088)
