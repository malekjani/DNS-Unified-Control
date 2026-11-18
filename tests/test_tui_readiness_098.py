"""v0.9.8: no live VPS actions; local Agent contract / TUI safety tests."""
import contextlib
import io
import json
import socket
import threading
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from duc import core, readiness, tui


def fake_ready():
    checks = {e:{'ready':e=='noizdns','issues':[] if e=='noizdns' else ['not installed']}
              for e in core.ENGINES}
    return readiness.assemble(
        active=['noizdns'], dante_state={'ready':True,'running':True,
                                       'auth_verified':True,'bind':'127.0.0.1:1080',
                                       'password':'DO_NOT_LEAK'},
        checks=checks,
        job_states={'noizdns':{'build-client':'succeeded','build-alternate':'not-started'}})


def test_readiness_pure_and_distinguishes_states():
    result=fake_ready()
    assert result['exclusive_healthy']
    assert result['engines']['noizdns']['server_ready']
    assert result['engines']['noizdns']['active']
    assert result['engines']['noizdns']['clients'][0]['build_state']=='succeeded'
    assert result['engines']['noizdns']['clients'][1]['build_state']=='not-started'
    assert result['dante']['auth_verified']
    assert 'DO_NOT_LEAK' not in json.dumps(result)
    assert 'live check' in result['evidence_policy']['field_tested']


def test_readiness_conflict_not_healthy():
    r=readiness.assemble(active=['noizdns','dnstt'],dante_state={},
        checks={e:{'ready':True,'issues':[]} for e in core.ENGINES},job_states={})
    assert r['exclusive_healthy'] is False
    assert r['engines']['dnstt']['active'] and r['engines']['noizdns']['active']


def test_agent_endpoint_contract(monkeypatch):
    from duc.agent import app
    monkeypatch.setattr(readiness,'snapshot',fake_ready)
    response=TestClient(app).get('/workflow/readiness')
    assert response.status_code==200 and response.json()['schema']==1


def test_web_requires_mfa(monkeypatch):
    from duc.web import app
    response=TestClient(app).get('/api/workflow/readiness')
    assert response.status_code==401


def test_tui_does_not_switch_without_exact_confirmation():
    class Fake:
        def __init__(self):self.posts=[]
        def get(self,path):
            assert path=='/workflow/readiness'
            return fake_ready()
        def post(self,path,data):
            self.posts.append((path,data));return {'ok':True}
    api=Fake()
    result=tui._switch(api,'noizdns',confirm_fn=lambda phrase:False)
    assert result['stage']=='cancelled' and not api.posts
    with pytest.raises(tui.AgentFailure):
        tui._switch(api,'dnstt',confirm_fn=lambda phrase:True)
    assert not api.posts
    result=tui._switch(api,'noizdns',confirm_fn=lambda phrase:phrase=='SWITCH noizdns')
    assert result['ok'] and api.posts==[('/switch',{'engine':'noizdns','restart':False})]


def test_tui_job_safeguard_and_variant_mapping():
    class Fake:
        def __init__(self):self.posts=[]
        def get(self,path):
            from duc.client_catalog import options
            return options(path.rsplit('/',1)[-1])
        def post(self,path,data):
            self.posts.append((path,data));return {'state':'queued'}
    api=Fake()
    assert tui._build(api,'noizdns','slipnet','8.8.8.8:53',2222,
                      confirm_fn=lambda phrase:False)['state']=='cancelled'
    assert not api.posts
    tui._build(api,'noizdns','dnstt','8.8.8.8:53',2222,confirm_fn=lambda p:True)
    assert api.posts==[('/workflow/jobs/build-alternate/noizdns',
                         {'confirm':'build-alternate:noizdns','resolver':'8.8.8.8:53','port':2222})]
    with pytest.raises(ValueError):
        tui._build(api,'noizdns','untrusted','1.1.1.1:53',2080,confirm_fn=lambda p:True)


def test_tui_unix_socket_roundtrip(tmp_path):
    """Actual Unix socket HTTP exchange, not a mocked network transport."""
    path=str(tmp_path/'agent.sock')
    ready=threading.Event()
    results=[]
    def server():
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.bind(path);sock.listen(1);ready.set()
            with sock.accept()[0] as conn:
                request=conn.recv(4096).decode()
                results.append(request.splitlines()[0])
                body=b'{"schema":1,"active":[]}'
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                             +f'Content-Length: {len(body)}\r\n\r\n'.encode()+body)
    thread=threading.Thread(target=server,daemon=True);thread.start()
    assert ready.wait(2)
    assert tui.Agent(path).get('/workflow/readiness')['schema']==1
    thread.join(timeout=2)
    assert results==['GET /workflow/readiness HTTP/1.1']


def test_tui_json_flag_rejects_mutations():
    with pytest.raises(SystemExit) as ex:
        tui.main(['--json','switch','noizdns'])
    assert ex.value.code==2


def test_tui_conflict_allows_only_emergency_stop():
    class Conflicted:
        def __init__(self):self.posts=[]
        def get(self,path):
            data=fake_ready()
            data['exclusive_healthy']=False
            return data
        def post(self,path,body):
            self.posts.append((path,body))
            return {'ok':True,'stage':'stopped'}
    api=Conflicted()
    with pytest.raises(tui.AgentFailure):
        tui._switch(api,'noizdns',confirm_fn=lambda _:True)
    assert not api.posts
    assert tui._switch(api,'none',confirm_fn=lambda phrase: phrase=='STOP DNS')['stage']=='stopped'
    assert api.posts==[('/switch',{'engine':'none','restart':False})]

def test_tui_no_write_without_real_terminal(monkeypatch):
    monkeypatch.setattr(tui.sys.stdin,'isatty',lambda:False)
    assert tui._confirm('SWITCH noizdns') is False


def test_tui_confirm_abort_on_eof():
    def cancel(_): raise EOFError()
    assert tui._confirm('BUILD noizdns slipnet',input_fn=cancel) is False


def test_authenticated_web_route_proxies_agent(monkeypatch):
    from duc import web
    monkeypatch.setattr(web,'guard',lambda *args,**kwargs:None)
    paths=[]
    async def proxy(method,path,**kwargs):
        paths.append((method,path));return fake_ready()
    monkeypatch.setattr(web,'agent_request',proxy)
    r=TestClient(web.app).get('/api/workflow/readiness')
    assert r.status_code==200 and r.json()['schema']==1
    assert paths==[('GET','/workflow/readiness')]


def test_tui_launcher_independent_of_working_directory(tmp_path):
    import os,subprocess,pathlib,sys
    root=pathlib.Path(__file__).resolve().parents[1]
    launcher=root/'scripts/duc-tui.sh'
    assert subprocess.run(['bash','-n',str(launcher)]).returncode==0
    # Source tree on test runner has no venv: the script must fail closed.
    result=subprocess.run(['bash',str(launcher),'--help'],cwd=str(tmp_path),
                          capture_output=True,text=True)
    assert result.returncode in (0,1)
    if result.returncode==1: assert 'Python venv not found' in result.stderr
