"""Privileged localhost-only service. Exposed exclusively through a group-owned Unix socket."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any
from . import core
app=FastAPI(title='DNS Unified privileged agent',docs_url=None,redoc_url=None,openapi_url=None)

class ProfilePatch(BaseModel):
    values: dict[str,Any]
class SwitchBody(BaseModel):
    engine: str
    restart: bool = False

@app.get('/status')
def status():
    p=core.profiles()
    return {'catalog':core.META, 'engines': {e:{'name':core.NAMES[e],'config':p[e],
             'unit':core.unit_status(e),'preflight':core.check_ready(e,p[e])} for e in core.ENGINES},
            'active':core.list_active(),'exclusive_healthy':len(core.list_active())<=1,'audit':core.audit_tail(12)}

@app.get('/metrics')
def metrics(): return core.system_metrics()

@app.get('/logs/{engine}')
def logs(engine:str):
    try:return {'lines':core.journal(engine)}
    except ValueError as exc: raise HTTPException(404,str(exc))

@app.post('/profile/{engine}')
def profile(engine:str,body:ProfilePatch):
    try:
        with core.switch_lock():return {'config':core.update_profile(engine,body.values), 'restart_required':core.is_active(engine)}
    except ValueError as exc:raise HTTPException(422,str(exc))

@app.post('/switch')
def switch(body:SwitchBody):
    try:return core.switch(body.engine, body.restart)
    except ValueError as exc:raise HTTPException(422,str(exc))
    except Exception as exc:
        core.audit('error',core.list_active(),[body.engine],type(exc).__name__)
        raise HTTPException(500,'Switch failed; inspect service journal')

@app.get('/dns/check')
def dns_check():
    from .dnscheck import check_all
    return check_all(core.profiles())

@app.get('/dns/plan')
def dns_plan():
    from .catalog import LABELS
    data=core.profiles()
    return {'engines':[{'engine':e,'name':core.NAMES[e], 'domain':data[e]['domain'],
                        'label':LABELS[e], 'category':core.FAMILIES[e]} for e in core.ENGINES],
            'cloudflare': 'Configure via CLI: python -m duc.cloudflare_dns --domain DOMAIN --ip IPV4',
            'mode':'distinct-subdomain-per-engine','verified':False}


# v0.6 - fixed-action workflow; the web service never receives raw root keys.
@app.get('/workflow/readiness')
def workflow_readiness():
    from .readiness import snapshot
    return snapshot()


@app.get('/workflow/overview')
def workflow_overview():
    from . import jobs, workflow, provision
    report=provision.report_data()
    return {'health':workflow.snapshot(),
            'provision':{'completed':report.get('completed'), 'engines':report.get('engines',{})},
            'capabilities':{e:{'client':workflow.CLIENT_CAPABILITIES[e][0],
                               'installable':e in jobs.INSTALLABLE,
                               'buildable':e in jobs.BUILDABLE,
                               'docs':workflow.DOCS[e]} for e in core.ENGINES}}

@app.get('/workflow/soar/status')
def soar_status():
    from .soar_secure import status
    return status()

# v0.8 — shared backend and public, SECRET-FREE client bundle.
@app.get('/workflow/shared-socks/status')
def shared_socks_status():
    from . import unified
    return unified.status()

class SharedSocksBody(BaseModel):
    mode: str
    engines: list[str]
    confirm: str
    target: str | None = None

@app.post('/workflow/shared-socks/activate')
def shared_socks_activate(body: SharedSocksBody):
    from . import unified
    if body.mode not in ('dante','custom','restore') or body.confirm != 'shared-socks:'+body.mode:
        raise HTTPException(422, 'Explicit shared backend confirmation required')
    try:return unified.configure(body.mode, body.engines, body.target)
    except ValueError as exc:raise HTTPException(422,str(exc))
    except RuntimeError as exc:raise HTTPException(503,str(exc))

@app.get('/workflow/advanced')
def workflow_advanced():
    from .advanced import registry
    return {'engines':registry(), 'version':__import__('pathlib').Path(__file__).resolve().parent.parent.joinpath('VERSION').read_text().strip()}

@app.get('/workflow/telemetry')
def workflow_telemetry():
    from .telemetry import snapshot
    return snapshot()

class TelemetryBody(BaseModel):
    report: dict[str,Any]

@app.post('/workflow/telemetry')
def workflow_import_telemetry(body:TelemetryBody):
    from .telemetry import save
    try:return save(body.report)
    except ValueError as exc:raise HTTPException(422,str(exc))


@app.get('/workflow/dante/status')
def dante_status():
    from . import dante
    return dante.status()

class DanteActivation(BaseModel):
    mode: str
    confirm: str

@app.post('/workflow/dante/activate')
def dante_activate(body:DanteActivation):
    from . import dante
    if body.mode not in ('socks5','ssh') or body.confirm!='activate:'+body.mode:
        raise HTTPException(422,'Explicit backend change confirmation required')
    try:return dante.activate(body.mode)
    except ValueError as exc:raise HTTPException(422,str(exc))
    except RuntimeError as exc:raise HTTPException(503,str(exc))

@app.get('/workflow/preflight/slipstream')
def slipstream_hardware_preflight():
    from .slipstream_ali import preflight
    return preflight()

@app.get('/workflow/guide/{engine}')
def workflow_guide(engine:str, resolver:str='1.1.1.1:53', port:int=2080):
    from . import workflow
    try:return workflow.build_client_guide(engine,resolver,port)
    except ValueError as exc:raise HTTPException(422,str(exc))

@app.get('/workflow/jobs/{action}/{engine}')
def workflow_job_status(action:str,engine:str):
    from . import jobs
    try:return jobs.info(action,engine)
    except ValueError as exc:raise HTTPException(404,str(exc))

class WorkflowJobBody(BaseModel):
    confirm:str
    resolver: str | None = None
    port: int | None = None

@app.post('/workflow/jobs/{action}/{engine}')
def workflow_job_start(action:str,engine:str,body:WorkflowJobBody):
    from . import jobs
    if body.confirm!=f'{action}:{engine}':
        raise HTTPException(422,'Explicit confirmation required')
    params={k:v for k,v in {'resolver':body.resolver,'port':body.port}.items() if v is not None}
    if params and action not in ('build-client','build-alternate'):
        raise HTTPException(422,'Build parameters are only allowed for client build jobs')
    try:return jobs.initiate(action,engine,params)
    except ValueError as exc:raise HTTPException(422,str(exc))
    except RuntimeError as exc:raise HTTPException(503,str(exc))

@app.get('/workflow/client/options/{engine}')
def client_options(engine:str):
    from .client_catalog import options
    try:return options(engine)
    except ValueError as exc:raise HTTPException(404,str(exc))

@app.get('/workflow/client/alternate-download/{engine}')
def alternate_client_download(engine:str):
    from . import jobs
    from fastapi.responses import FileResponse
    try:path=jobs.alternate_artifact_path(engine)
    except ValueError as exc:raise HTTPException(404,str(exc))
    state=jobs.info('build-alternate',engine)
    if (not path.is_file() or not 1000<=path.stat().st_size<=80_000_000 or
        state.get('state')!='succeeded' or state.get('artifact')!=path.name):
        raise HTTPException(404,'Alternate client package has not been built successfully')
    return FileResponse(path,filename=path.name,media_type='application/zip',
                        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

@app.get('/workflow/client/download/{engine}')
def workflow_client_download(engine:str):
    from . import jobs
    from fastapi.responses import FileResponse
    try:path=jobs.artifact_path(engine)
    except ValueError as exc:raise HTTPException(404,str(exc))
    if not path.is_file() or not 1000<=path.stat().st_size<=80_000_000:
        raise HTTPException(404,'No validated client package. Build it first.')
    state=jobs.info('build-client',engine)
    if state.get('state')!='succeeded' or state.get('artifact')!=path.name:
        raise HTTPException(404,'Client package is not confirmed complete')
    return FileResponse(path,filename=path.name,media_type='application/zip',
                        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


class CloudflareWorkflowBody(BaseModel):
    token:str
    domain:str
    ipv4:str
    dry_run:bool=True
    confirm:str=''

@app.post('/workflow/cloudflare')
def workflow_cloudflare(body:CloudflareWorkflowBody):
    from .cloudflare_dns import CF,clean_domain,clean_ip,apply_all,ProvisionError
    try:
        domain=clean_domain(body.domain)
        ip=clean_ip(body.ipv4)
        if len(body.token)<12 or len(body.token)>512 or any(c.isspace() for c in body.token):
            raise ValueError('Invalid API token')
        if not body.dry_run and body.confirm!='APPLY_CLOUDFLARE_DNS':
            raise ValueError('Confirm creating/updating the 10 records')
        with core.switch_lock():
            if not body.dry_run:
                data=core.profiles()
                old=core.list_active()
                from .catalog import LABELS
                if old and any(data[e]['domain']!=f'{LABELS[e]}.{domain}' for e in core.ENGINES):
                    raise ValueError('Stop active engine first; zone migration cannot change a running engine')
            result=apply_all(CF(body.token),domain,ip,dry_run=body.dry_run)
            if not body.dry_run:
                from .catalog import LABELS
                data=core.profiles()
                for e in core.ENGINES: data[e]['domain']=f'{LABELS[e]}.{domain}'
                core.atomic_json(core.ROOT/'profiles.json',data)
                core.audit('cloudflare',[],[],f'updated delegated zone {domain}')
        return {'dry_run':body.dry_run,'results':result,'records':len(result),
                'profile_updated':not body.dry_run,
                'note':'Authoritative DNS propagation and client transport are separate checks. Token not stored.'}
    except (ProvisionError,ValueError) as exc:raise HTTPException(422,str(exc))


@app.get('/workflow/client/guide-zip/{engine}')
def workflow_guide_zip(engine:str,resolver:str='1.1.1.1:53',port:int=2080):
    from . import workflow
    from fastapi.responses import Response
    try: data=workflow.create_public_guide_bundle(engine,resolver,port)
    except ValueError as exc:raise HTTPException(422,str(exc))
    return Response(content=data,media_type='application/zip',headers={
        'Content-Disposition':f'attachment; filename="{engine}-client-guide.zip"',
        'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

# DUC_MULTI_ADDON_0101
from ducmulti.api import install_agent_routes as _duc_multi_agent
_duc_multi_agent(app)
