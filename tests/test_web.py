import hashlib, json, os
from fastapi.testclient import TestClient
from duc import web

def test_web_requires_login_and_csrf(tmp_path,monkeypatch):
    pw='this-is-a-long-test-password'
    salt=os.urandom(16)
    path=tmp_path/'auth.json'
    path.write_text(json.dumps({'salt':salt.hex(),'hash':hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,600000).hex()}))
    monkeypatch.setattr(web,'AUTH_PATH',path)
    monkeypatch.setattr(web,'MFA_PATH',tmp_path/'mfa.json')
    web.SESSIONS.clear(); web.ATTEMPTS.clear()
    async def mock_agent(method,path,data=None):
        return {'ok':True, 'method':method,'path':path,'data':data}
    monkeypatch.setattr(web,'agent_request',mock_agent)
    with TestClient(web.app) as client:
        assert client.get('/api/status').status_code==401
        assert client.post('/api/login',json={'password':'wrong'}).status_code==401
        r=client.post('/api/login',json={'password':pw})
        assert r.status_code==200 and r.json()['stage']=='enroll'
        csrf=r.json()['csrf']
        assert client.get('/api/status').status_code==401
        assert client.post('/api/switch',json={'engine':'master'}).status_code==401
        from duc import mfa
        setup=client.post('/api/mfa/setup',headers={'X-CSRF-Token':csrf},json={}).json()
        import time
        code=mfa.otp(setup['secret'],int(time.time())//30)
        done=client.post('/api/mfa/activate',headers={'X-CSRF-Token':csrf},json={'code':code})
        assert done.status_code==200
        csrf=done.json()['csrf']
        assert 'HttpOnly' in done.headers.get('set-cookie','')
        assert client.get('/api/status').status_code==200
        assert client.post('/api/switch',json={'engine':'master'}).status_code==403
        assert client.post('/api/switch',headers={'X-CSRF-Token':csrf},json={'engine':'bad'}).status_code==422
        r=client.post('/api/switch',headers={'X-CSRF-Token':csrf},json={'engine':'master'})
        assert r.status_code==200
        assert r.json()['data']['engine']=='master'
        assert client.get('/app.js').status_code==200
