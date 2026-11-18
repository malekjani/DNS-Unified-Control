"""NoizDNS server auto-install regression tests; no live GitHub/DNS access."""
from contextlib import nullcontext
import json
from pathlib import Path
import stat
import subprocess
import pytest
from duc import core, jobs, provision, install_noizdns, worker, unified, workflow, runner, noiz_provenance

ROOT=Path(__file__).resolve().parents[1]


def test_entrypoints_and_server_source_are_separate():
    install=(ROOT/'install.sh').read_text()
    upgrade=(ROOT/'upgrade.sh').read_text()
    assert 'python -m duc.install_noizdns' in install
    assert 'python -m duc.install_soar' in install
    assert 'exit 1' in install[install.index('python -m duc.install_noizdns'):][:350]
    assert 'bash ./install.sh' in upgrade
    assert worker.REPOS['noizdns']==('anonvector/dnstt','./dnstt-server','noizdns-server')
    assert worker.REPOS['dnstt'][2]=='dnstt-server'
    assert provision.STRATEGIES['noizdns'].kind=='go'
    assert 'noizdns' in jobs.BUILDABLE  # v0.9.4 now packages real native SlipNet 'sayedns' Stealth CLI.
    assert 'noizdns' not in jobs.INSTALLABLE # Installer handles server, client UI doesn't.
    assert core.DEFAULTS['noizdns']['target']=='127.0.0.1:1080'
    assert 'noizdns' in unified.TCP_ENGINES
    assert not (ROOT/'client/duc_socks_gateway.py').exists()


def test_public_key_derivation_rfc7748():
    priv='77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
    expected='8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
    assert install_noizdns._x25519_pub_from_private(priv)==expected


def test_identity_preservation_and_public_recovery(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    key_dir=tmp_path/'keys';key_dir.mkdir()
    priv=key_dir/'noizdns.key';pub=key_dir/'noizdns.pub'
    raw='77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
    priv.write_text(raw+'\n'); priv.chmod(0o644)
    derived=install_noizdns.ensure_identity()
    assert priv.read_text().strip()==raw
    assert stat.S_IMODE(priv.stat().st_mode)==0o600
    assert derived==pub.read_text().strip()
    assert stat.S_IMODE(pub.stat().st_mode)==0o644
    assert install_noizdns.ensure_identity()==derived
    pub.write_text('f'*64+'\n')
    with pytest.raises(RuntimeError,match='does not match'):
        install_noizdns.ensure_identity()
    assert priv.read_text().strip()==raw
    pub.unlink()
    priv.unlink()
    pub.write_text(derived+'\n')
    with pytest.raises(RuntimeError,match='Orphaned'):
        install_noizdns.ensure_identity()


def test_identity_rejects_symlinks(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    folder=tmp_path/'keys'; folder.mkdir()
    (folder/'noizdns.key').symlink_to(tmp_path/'sensitive')
    with pytest.raises(RuntimeError,match='symlinks'):
        install_noizdns.ensure_identity()


def test_asset_inspection_with_elf_help_and_matching_key(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    binary=tmp_path/'noizdns-server'; binary.write_bytes(b'\x7fELF'+b'0'*200)
    binary.chmod(0o755)
    monkeypatch.setattr(install_noizdns,'BINARY',binary)
    key_dir=tmp_path/'keys';key_dir.mkdir()
    priv='77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
    (key_dir/'noizdns.key').write_text(priv+'\n');(key_dir/'noizdns.key').chmod(0o600)
    (key_dir/'noizdns.pub').write_text(install_noizdns._x25519_pub_from_private(priv)+'\n')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    noiz_provenance.save(binary,'a'*40)
    monkeypatch.setattr(install_noizdns.subprocess,'run',lambda *args,**kwargs:subprocess.CompletedProcess(args,2,'', 'Flags: -udp -gen-key'))
    assert install_noizdns.inspect_server_assets()['ok']
    (key_dir/'noizdns.key').chmod(0o644)
    assert not install_noizdns.inspect_server_assets()['ok']


def test_backend_migration_only_when_legacy(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    monkeypatch.setattr(unified,'BACKUP',tmp_path/'shared-backend-previous.json')
    monkeypatch.setattr(core,'switch_lock',lambda:nullcontext())
    monkeypatch.setattr(core,'is_active',lambda e:False)
    original=core.profiles();original['noizdns']['target']='127.0.0.1:22'
    core.atomic_json(tmp_path/'profiles.json',original)
    assert install_noizdns.migrate_default_backend().startswith('migrated')
    changed=core.profiles()
    assert changed['noizdns']['target']=='127.0.0.1:1080'
    assert changed['soar']==original['soar']
    assert changed['dnstt']==original['dnstt']
    assert json.loads(unified.BACKUP.read_text())['noizdns']=='127.0.0.1:22'
    assert install_noizdns.migrate_default_backend()=='already-default-or-custom'
    changed['noizdns']['target']='127.0.0.1:1090'
    core.atomic_json(tmp_path/'profiles.json',changed)
    assert install_noizdns.migrate_default_backend()=='already-default-or-custom'
    assert core.profiles()['noizdns']['target']=='127.0.0.1:1090'


def test_install_preserves_active_soar_and_dante(monkeypatch,tmp_path):
    monkeypatch.setattr(install_noizdns.os,'geteuid',lambda:0)
    monkeypatch.setattr(core,'list_active',lambda:['soar'])
    monkeypatch.setattr(provision,'execute',lambda **kwargs:{'engines':{'noizdns':{'state':'installed-ready'}}})
    monkeypatch.setattr(install_noizdns,'ensure_identity',lambda:'a'*64)
    monkeypatch.setattr(install_noizdns,'inspect_server_assets',lambda:{'ok':True,'issues':[]})
    monkeypatch.setattr(install_noizdns,'migrate_default_backend',lambda:'already-default-or-custom')
    monkeypatch.setattr(core,'profiles',lambda:{'noizdns':{'target':'127.0.0.1:1080'}})
    result=install_noizdns.bootstrap()
    assert result['active_dns']==['soar']
    assert result['backend']=='127.0.0.1:1080'


def test_runner_noizdns_native_cli_dante(monkeypatch):
    monkeypatch.setattr(runner.shutil,'which',lambda name:'/usr/local/bin/noizdns-server')
    config=dict(core.DEFAULTS['noizdns'],domain='n.m2m.diy')
    command=runner.cmd_for('noizdns',config)
    assert command[:2]==['/usr/local/bin/noizdns-server','-udp']
    assert command[-2:]==['n.m2m.diy','127.0.0.1:1080']
    guide=workflow.build_client_guide('noizdns')
    assert guide['example_command'] is None  # key isn't available in this isolated test
    assert guide['can_build'] is True


def test_provenance_detects_tampering(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'STATE',tmp_path)
    binary=tmp_path/'noizdns-server';binary.write_bytes(b'\x7fELF'+b'x'*200)
    assert not noiz_provenance.check(binary)
    noiz_provenance.save(binary,'f'*40)
    assert noiz_provenance.check(binary)
    binary.write_bytes(b'\x7fELF'+b'x'*199+b'y')
    assert not noiz_provenance.check(binary)


def test_unverified_existing_binary_rebuilt_without_active_switch(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'is_active',lambda engine:False)
    monkeypatch.setattr(provision.shutil,'which',lambda name:'/usr/local/bin/noizdns-server')
    monkeypatch.setattr(provision,'readiness',lambda engine:{'ready':False,'issues':['provenance'],'binary':'/usr/local/bin/noizdns-server'})
    monkeypatch.setattr(noiz_provenance,'check',lambda path:False)
    called=[]
    monkeypatch.setattr(provision,'install_go',lambda engine:(called.append(engine) or {'source_commit':'a'*40}))
    result=provision.observe('noizdns',dry_run=True)
    assert result['state']=='would-rebuild'
    result=provision.observe('noizdns')
    assert called==['noizdns']
    assert result['state']=='installed-needs-config'
