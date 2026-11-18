import hashlib,json,os,time
from fastapi.testclient import TestClient
from duc import web,mfa


def test_workflow_auth_and_csrf(tmp_path,monkeypatch):
    salt=os.urandom(16);pw='unique-test-password-123456'
    auth=tmp_path/'auth.json';auth.write_text(json.dumps({'salt':salt.hex(),
        'hash':hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,600000).hex()}))
    monkeypatch.setattr(web,'AUTH_PATH',auth)
    monkeypatch.setattr(web,'MFA_PATH',tmp_path/'mfa.json')
    web.SESSIONS.clear();web.ATTEMPTS.clear()
    async def mock_agent(method,path,data=None):
        return {'ok':True,'method':method,'path':path,'data':data}
    monkeypatch.setattr(web,'agent_request',mock_agent)
    with TestClient(web.app) as client:
        assert client.get('/api/workflow/overview').status_code==401
        assert client.post('/api/workflow/jobs/build-client/dnstt',json={'confirm':'build-client:dnstt'}).status_code==401
        r=client.post('/api/login',json={'password':pw})
        assert r.status_code==200
        csrf=r.json()['csrf']
        assert client.get('/api/workflow/overview').status_code==401
        setup=client.post('/api/mfa/setup',json={},headers={'X-CSRF-Token':csrf}).json()
        code=mfa.otp(setup['secret'],int(time.time())//30)
        activated=client.post('/api/mfa/activate',json={'code':code},headers={'X-CSRF-Token':csrf})
        csrf=activated.json()['csrf']
        assert client.get('/api/workflow/overview').status_code==200
        assert client.get('/api/workflow/guide/dnstt?resolver=8.8.8.8%3A53&port=2300').json()['path']=='/workflow/guide/dnstt?resolver=8.8.8.8%3A53&port=2300'
        assert client.post('/api/workflow/jobs/build-client/dnstt',json={'confirm':'build-client:dnstt'}).status_code==403
        assert client.post('/api/workflow/jobs/build-client/dnstt',headers={'X-CSRF-Token':csrf},json={'confirm':'wrong'}).status_code==422
        res=client.post('/api/workflow/jobs/build-client/dnstt',headers={'X-CSRF-Token':csrf},json={'confirm':'build-client:dnstt'})
        assert res.status_code==200 and res.json()['data']['confirm']=='build-client:dnstt'
        assert client.post('/api/workflow/jobs/install-server/xdns',headers={'X-CSRF-Token':csrf},json={'confirm':'install-server:xdns'}).status_code==422
