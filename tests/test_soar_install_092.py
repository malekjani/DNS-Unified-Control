"""Soar installer integration and assets verification regression checks."""
from pathlib import Path
import base64
import os
import stat
import subprocess
import types
from duc import core, install_soar, provision, soar_secure, jobs

SRC=Path(__file__).resolve().parents[1]


def test_install_entrypoints_include_mandatory_soar_server_stage():
    install=(SRC/'install.sh').read_text()
    upgrade=(SRC/'upgrade.sh').read_text()
    assert 'python -m duc.install_soar' in install
    assert "if ! env PYTHONPATH=/opt/dns-unified-control" in install
    assert 'exit 1' in install[install.index('python -m duc.install_soar'):install.index('python -m duc.install_soar')+500]
    assert 'DUC_SKIP_WIZARD=1 DUC_INSTALL_ENGINES=0 bash ./install.sh' in upgrade
    assert 'install.sh automatically installs/verifies Soar' in upgrade
    assert 'install-server' in jobs.ACTIONS
    assert 'soar' not in jobs.INSTALLABLE and 'soar' in jobs.BUILDABLE
    assert 'soar-client' in (SRC/'soar-src/client.go').read_text()
    js=(SRC/'web/app.js').read_text()
    assert 'id="soar-build"' in js and 'id="soar-install"' not in js
    assert 'selected===\'soar\'?' in js
    assert 'id="wf-install"' in js  # other engines only


def test_asset_inspection_rejects_public_identity_mismatch(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    binary=tmp_path/'duc-soar-server'
    binary.write_bytes(b'\x7fELF'+b'\0'*50)
    binary.chmod(0o755)
    monkeypatch.setattr(install_soar,'BINARY',binary)
    keys=tmp_path/'keys';keys.mkdir()
    (keys/'soar.key').write_text(base64.b64encode(b'a'*32).decode()+'\n')
    (keys/'soar.key').chmod(0o600)
    pub=base64.b64encode(b'b'*32).decode()
    (keys/'soar.pub').write_text(pub+'\n')
    def fake_subprocess(args,**kwargs):
        assert args == [str(binary),'pubkey',str(keys/'soar.key')]
        return subprocess.CompletedProcess(args,0,stdout=pub+'\n')
    monkeypatch.setattr(install_soar.subprocess,'run',fake_subprocess)
    result=install_soar.inspect_server_assets()
    assert result['ok'] is True
    assert result['private_key_mode_ok'] and result['public_key_ready']
    # Detect stale public key without mutating the private key, even if all file modes are valid.
    monkeypatch.setattr(install_soar.subprocess,'run',lambda args,**kwargs:subprocess.CompletedProcess(args,0,stdout=base64.b64encode(b'c'*32).decode()+'\n'))
    result=install_soar.inspect_server_assets()
    assert result['ok'] is False
    assert any('does not match' in e for e in result['issues'])
    assert stat.S_IMODE((keys/'soar.key').stat().st_mode)==0o600
    (keys/'soar.key').chmod(0o644)
    assert install_soar.inspect_server_assets()['ok'] is False


def test_bootstrap_validates_assets_and_preserves_active_engine(monkeypatch):
    monkeypatch.setattr(install_soar.os,'geteuid',lambda:0)
    monkeypatch.setattr(core,'list_active',lambda:['slipstream'])
    calls=[]
    def fake_provision(**kwargs):
        calls.append(kwargs)
        return {'engines':{'soar':{'state':'installed-needs-config','readiness':{'ready':False,'issues':['domain unconfigured']},'message':'Installed'}}}
    monkeypatch.setattr(provision,'execute',fake_provision)
    assets={'ok':True,'issues':[],'binary':'/usr/local/bin/duc-soar-server','private_key_present':True,'private_key_mode_ok':True,'public_key_ready':True}
    monkeypatch.setattr(install_soar,'inspect_server_assets',lambda:assets)
    r=install_soar.bootstrap()
    assert r['active_dns']==['slipstream']
    assert r['installation']=='installed-needs-config' # not a server-asset failure
    assert calls==[{'only':('soar',)}]
    monkeypatch.setattr(install_soar,'inspect_server_assets',lambda:dict(assets,ok=False,issues=['bad key']))
    import pytest
    with pytest.raises(RuntimeError,match='bad key'):
        install_soar.bootstrap()


def test_server_installer_preserves_identity_and_no_client_gateway():
    assert 'ensure_keys()' in (SRC/'duc/worker.py').read_text()
    assert 'soar_secure.ensure_keys()' in (SRC/'duc/provision.py').read_text()
    assert not (SRC/'client/duc_socks_gateway.py').exists()
    assert 'ctx context.Context' in (SRC/'soar-src/server.go').read_text()
    assert 'addr != onlyBackend' in (SRC/'soar-src/server.go').read_text()
