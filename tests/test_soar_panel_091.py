"""Soar panel lifecycle: shared Dante is the *only* reachable backend."""
import base64
import copy
import pathlib
import re
from contextlib import nullcontext
import pytest
from duc import core, jobs, runner, soar_secure, worker, workflow, advanced

SRC=pathlib.Path(__file__).resolve().parents[1]

def test_fixed_dante_server_rejects_open_destinations():
    go=(SRC/'soar-src/server.go').read_text()
    assert 'addr != onlyBackend' in go and 'network != "tcp"' in go
    assert 'return dialer.DialContext(ctx, "tcp", onlyBackend)' in go
    assert 'allow-private' in go  # only as an explicitly disabled mode in comment
    assert '-allow-ports' not in go
    assert 'MaxSessions: 256' in go
    assert '127.0.0.1:1080' in go


def test_go_client_single_executable_and_loopback_only():
    go=(SRC/'soar-src/client.go').read_text()
    assert 'net.Listen("tcp", *listen)' in go
    assert 'soar.NewClient(' in go
    assert '*forward != "127.0.0.1:1080"' in go
    assert 'host != "127.0.0.1"' in go
    assert not (SRC/'client/duc_socks_gateway.py').exists()


def test_backend_profile_mode_and_runner(monkeypatch):
    c=copy.deepcopy(core.DEFAULTS['soar']); c['domain']='s.m2m.diy'
    monkeypatch.setattr(runner.shutil,'which',lambda s:'/usr/local/bin/duc-soar-server')
    cmd=runner.cmd_for('soar',c)
    assert cmd==['/usr/local/bin/duc-soar-server','-zone','s.m2m.diy',
                 '-key-file',str(core.ROOT/'keys/soar.key'),
                 '-listen',':53','-backend','127.0.0.1:1080']
    c['target']='127.0.0.1:22'
    with pytest.raises(ValueError):runner.cmd_for('soar',c)
    assert 'soar' in jobs.BUILDABLE and 'soar' not in jobs.INSTALLABLE
    assert 'target' in advanced.SCOPE['soar']['server']


def test_key_generation_preserves_identity_and_verifies_public(monkeypatch,tmp_path):
    import subprocess
    monkeypatch.setattr(core,'ROOT',tmp_path)
    raw=b'a'*32; pub=b'b'*32
    encoded=base64.b64encode(raw).decode()
    pubkey=base64.b64encode(pub).decode()
    calls=[]
    def fake_run(args,**kwargs):
        calls.append(args)
        if args[1]=='keygen':return subprocess.CompletedProcess(args,0,stdout='private '+encoded+'\npublic '+pubkey+'\n')
        if args[1]=='pubkey':return subprocess.CompletedProcess(args,0,stdout=pubkey+'\n')
        raise AssertionError(args)
    monkeypatch.setattr(soar_secure.subprocess,'run',fake_run)
    assert soar_secure.ensure_keys()['public_key_ready']
    assert soar_secure.public_key()==pubkey
    assert (tmp_path/'keys/soar.key').stat().st_mode & 0o077 == 0
    assert (tmp_path/'keys/soar.pub').stat().st_mode & 0o777 == 0o644
    assert soar_secure.ensure_keys()['public_key_ready']
    assert sum(1 for x in calls if x[1]=='keygen')==1
    (tmp_path/'keys/soar.pub').write_text(base64.b64encode(b'c'*32).decode())
    with pytest.raises(RuntimeError,match='mismatch'):soar_secure.ensure_keys()


def test_guide_is_direct_and_confidential(monkeypatch):
    cfg=copy.deepcopy(core.DEFAULTS)
    cfg['soar']['domain']='s.m2m.diy'
    monkeypatch.setattr(core,'profiles',lambda:cfg)
    monkeypatch.setattr(soar_secure,'public_key',lambda:base64.b64encode(b'0'*32).decode())
    guide=workflow.build_client_guide('soar')
    cmd=guide['example_command']
    assert './soar-client' in cmd and '-forward 127.0.0.1:1080' in cmd
    assert '127.0.0.1:2080' in cmd
    assert 'Gateway' not in cmd and 'json' not in cmd
    assert 'duc-socks' not in cmd  # do not leak credentials in downloadable bundle
    assert 'curl' in guide['verification_command']


def test_package_copy_go_build_and_web_status_wired():
    install=(SRC/'install.sh').read_text()
    assert 'cp -R ./duc ./web ./scripts ./client ./docs ./soar-src' in install
    assert 'soar-src' in (SRC/'upgrade.sh').read_text()
    assert "if engine=='soar':" in (SRC/'duc/worker.py').read_text()
    assert "build_soar_dedicated(src,'server.go'" in (SRC/'duc/worker.py').read_text()
    assert "build_soar_dedicated(src,'client.go'" in (SRC/'duc/worker.py').read_text()
    assert '/api/workflow/soar/status' in (SRC/'duc/web.py').read_text()
    assert '/workflow/soar/status' in (SRC/'duc/agent.py').read_text()
    js=(SRC/'web/app.js').read_text()
    assert 'id="soar-install"' not in js and 'id="soar-build"' in js
    assert 'selected===\'soar\'?api(\'/api/workflow/soar/status\')' in js
