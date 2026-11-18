from fastapi.testclient import TestClient
from duc import agent,core


def test_cf_token_is_never_returned_and_preview_only(tmp_path,monkeypatch):
    monkeypatch.setattr(core,'ROOT',tmp_path/'config')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    monkeypatch.setattr(core,'list_active',lambda:[])
    from duc import cloudflare_dns
    called=[]
    class FakeCF:
        def __init__(self, token):called.append(('token',token))
    monkeypatch.setattr(cloudflare_dns,'CF',FakeCF)
    def apply(client, domain,ip,dry_run=False):
        called.append(('apply',dry_run))
        return [{'action':'create','type':'A','name':'ns.'+domain,'content':ip}]
    monkeypatch.setattr(cloudflare_dns,'apply_all',apply)
    with TestClient(agent.app) as client:
        body={'token':'EXAMPLE_TEST_TOKEN_NOT_REAL','domain':'m2m.diy','ipv4':'188.132.174.249',
              'dry_run':True}
        r=client.post('/workflow/cloudflare',json=body)
        assert r.status_code==200
        assert 'EXAMPLE_TEST_TOKEN_NOT_REAL' not in r.text
        assert ('apply',True) in called
        assert not (core.ROOT/'profiles.json').exists()
        bad=client.post('/workflow/cloudflare',json={**body,'dry_run':False})
        assert bad.status_code==422
        assert ('apply',False) not in called
        result=client.post('/workflow/cloudflare',json={**body,'dry_run':False,'confirm':'APPLY_CLOUDFLARE_DNS'})
        assert result.status_code==200
        assert ('apply',False) in called
        assert (core.ROOT/'profiles.json').exists()
        assert 'EXAMPLE_TEST_TOKEN_NOT_REAL' not in (core.ROOT/'profiles.json').read_text()
