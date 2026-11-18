"""v0.10.3 side-effect-free lifecycle tests (no VPS or live DNS changes)."""
from __future__ import annotations

import json
from pathlib import Path
import os
import pytest
import subprocess
import tarfile
import threading
import socket

from duc import lifecycle

I = {'instance_id':'8dd979b3-c59b-46f6-9c99-c78f751be53c',
     'domain':'m2m.diy','public_ipv4':'13.39.238.230'}


def test_detect_fresh_resume_upgrade_repair():
    assert lifecycle.decide('0.10.3', None, None, None, app_exists=False) == 'fresh'
    assert lifecycle.decide('0.10.3', None, I, None, app_exists=False) == 'resume_fresh'
    assert lifecycle.decide('0.10.3', '0.10.2', I, None, app_exists=True) == 'upgrade'
    assert lifecycle.decide('0.10.3', '0.10.3', I, None, app_exists=True) == 'repair'
    assert lifecycle.decide('0.10.3', '0.10.2', None, None, app_exists=True) == 'legacy_upgrade'
    with pytest.raises(lifecycle.LifecycleError, match='downgrade'):
        lifecycle.decide('0.10.3', '0.10.4', I, None, app_exists=True)


def test_resume_existing_failed_without_reset():
    x = lifecycle.new_state('upgrade', '0.10.3', I, {})
    x['status'] = 'failed'
    x['steps']['snapshot'] = {'status':'completed'}
    assert lifecycle.decide('0.10.3', '0.10.2', I, x, app_exists=True) == 'resume'
    x['instance_id'] = 'f00f0e88-0000-4000-8000-000000000000'
    with pytest.raises(lifecycle.LifecycleError, match='different instance'):
        lifecycle.decide('0.10.3', '0.10.2', I, x, app_exists=True)
    x['instance_id'] = I['instance_id']
    x['release'] = '0.10.1'
    assert lifecycle.decide('0.10.3', '0.10.2', I, x, app_exists=True) == 'upgrade'


def test_partial_different_release_no_invisible_overwrite():
    x = lifecycle.new_state('fresh', '0.10.2', None, {'domain':'example.net','ip':'13.39.238.230'})
    x['status'] = 'failed'
    with pytest.raises(lifecycle.LifecycleError, match='Unfinished'):
        lifecycle.decide('0.10.3', None, None, x, app_exists=False)


def test_atomic_state_private_permissions(tmp_path):
    state = lifecycle.new_state('fresh','0.10.3',None,{'domain':'example.org','ip':'13.39.238.230'})
    dest = tmp_path / 'rootonly' / 'state.json'
    lifecycle.write_state(state, dest)
    assert lifecycle.load_state(dest) == state
    assert (dest.stat().st_mode & 0o777) == 0o600
    assert (dest.parent.stat().st_mode & 0o777) == 0o700
    assert 'token' not in dest.read_text().lower()
    lifecycle.mark(state, 'preflight', 'completed', store=lambda x:lifecycle.write_state(x, dest))
    assert lifecycle.load_state(dest)['steps']['preflight']['status']=='completed'
    dest.write_text('{bad')
    with pytest.raises(lifecycle.LifecycleError, match='corrupt'):
        lifecycle.load_state(dest)


def test_refuse_symlink_state(tmp_path):
    target = tmp_path / 'real.json'
    target.write_text('{}')
    link = tmp_path / 'state.json'
    link.symlink_to(target)
    with pytest.raises(lifecycle.LifecycleError, match='symlinked'):
        lifecycle.load_state(link)
    with pytest.raises(lifecycle.LifecycleError, match='symlinked'):
        lifecycle.write_state(lifecycle.new_state('fresh','0.10.3',None,{}),link)


def test_lock_blocks_parallel_execution(tmp_path):
    lock = tmp_path / 'lifecycle.lock'
    with lifecycle.exclusive_lock(lock):
        with pytest.raises(lifecycle.LifecycleError, match='already running'):
            with lifecycle.exclusive_lock(lock):
                pass
    with lifecycle.exclusive_lock(lock):
        pass


def test_checkpoint_skip_and_retry():
    state = lifecycle.new_state('repair','0.10.3',I,{})
    observed=[]
    persist=lambda s: None
    lifecycle._run_stage(state,'health',lambda:observed.append('first'),store=persist)
    lifecycle._run_stage(state,'health',lambda:observed.append('again'),validator=lambda:True,store=persist)
    assert observed==['first']
    lifecycle._run_stage(state,'health',lambda:observed.append('recheck'),validator=lambda:False,store=persist)
    assert observed==['first','recheck']
    def broken():
        raise RuntimeError('expected error')
    with pytest.raises(RuntimeError):
        lifecycle._run_stage(state,'apply',broken,store=persist)
    assert state['steps']['apply']['status']=='failed'
    # Stage error stores exception KIND only, not exception message (could contain secrets).
    assert state['steps']['apply']['note']=='RuntimeError'


def test_version_parser():
    assert lifecycle.version_tuple('0.10.3') > lifecycle.version_tuple('0.10.2')
    for bad in ('latest', 'v0.10.3', '0.10.3-a', '0'):
        with pytest.raises(lifecycle.LifecycleError):
            lifecycle.version_tuple(bad)


def test_upgrade_snapshot_and_nonsecret_code_rollback(tmp_path):
    app=tmp_path/'opt'/'dns-unified-control'
    (app/'.venv'/'bin').mkdir(parents=True)
    (app/'.venv'/'bin'/'python').symlink_to('python3')
    (app/'.venv'/'bin'/'python3').write_text('fake interpreter')
    (app/'VERSION').write_text('0.10.2')
    (app/'duc').mkdir()
    (app/'duc'/'web.py').write_text('original')
    units=tmp_path/'units'
    units.mkdir()
    (units/'dns-unified-web.service').write_text('original unit')
    backup=lifecycle.snapshot_code(tmp_path/'backups',app,units,I)
    assert (backup.stat().st_mode & 0o777)==0o600
    (app/'VERSION').write_text('0.10.3')
    (app/'duc'/'web.py').write_text('new broken code')
    (units/'dns-unified-web.service').write_text('broken unit')
    secret=tmp_path/'secret'
    secret.write_text('untouched')
    lifecycle.rollback_code(backup,app,units,restart=False)
    assert (app/'VERSION').read_text()=='0.10.2'
    assert (app/'duc'/'web.py').read_text()=='original'
    assert (app/'.venv'/'bin'/'python').is_symlink()
    assert (units/'dns-unified-web.service').read_text()=='original unit'
    assert secret.read_text()=='untouched'
    assert any(p.name.startswith('dns-unified-control.failed-upgrade') for p in app.parent.iterdir())


def test_snapshot_reject_invalid_archive(tmp_path):
    archive=tmp_path/'evil.tar.gz'
    with tarfile.open(archive,'w:gz') as tf:
        import io
        info=tarfile.TarInfo('../evil')
        info.size=4
        tf.addfile(info,io.BytesIO(b'evil'))
    with pytest.raises(lifecycle.LifecycleError, match='Unsafe'):
        lifecycle.rollback_code(archive,tmp_path/'app',tmp_path/'units',restart=False)


def test_installer_routes_through_lifecycle():
    root=Path(__file__).resolve().parents[1]
    installer=(root/'install.sh').read_text()
    assert 'python3 -m duc.lifecycle "$@"' in installer
    assert 'DUC_LIFECYCLE_SKIP_PROVISION' in installer
    assert 'systemctl restart dns-unified-web.service' in installer
    assert 'duc.lifecycle' in (root/'upgrade.sh').read_text() or 'install.sh' in (root/'upgrade.sh').read_text()


def test_source_has_no_automatic_cloudflare_cutover():
    src=Path(lifecycle.__file__).read_text()
    assert 'fresh-cloudflare-cutover.py' not in src
    assert 'setup-panel-https.sh' not in src
    assert 'core.switch(' not in src


def test_tls_readiness_marks_deferred_without_claiming_ready(monkeypatch):
    import types
    state = lifecycle.new_state('repair', '0.10.3', I, {})
    monkeypatch.setattr(lifecycle.subprocess, 'run', lambda *a, **kw:
                        types.SimpleNamespace(stdout='PANEL_HTTPS=DEFERRED fqdn=panel.m2m.diy\nPANEL_DNS=OTHER_OR_UNRESOLVED\n'))
    lifecycle.tls_readiness(state, store=lambda x: None)
    assert state['tls']=={'status':'DEFERRED','dns':'OTHER_OR_UNRESOLVED'}


def test_execute_upgrade_does_not_rebuild_engines_or_touch_keys(monkeypatch, tmp_path):
    from types import SimpleNamespace
    current=tmp_path/'app'
    current.mkdir()
    (current/'VERSION').write_text('0.10.2')
    (current/'duc').mkdir()
    (current/'duc'/'web.py').write_text('before')
    src=tmp_path/'install.sh'
    src.write_text('#!/bin/bash\n')
    backing=tmp_path/'backup.tar.gz'
    backing.write_bytes(b'code snapshot fake')
    monkeypatch.setattr(lifecycle,'APP',current)
    monkeypatch.setattr(lifecycle,'maintenance_preflight',lambda:None)
    monkeypatch.setattr(lifecycle,'snapshot_code',lambda identity:backing)
    monkeypatch.setattr(lifecycle,'health',lambda:None)
    monkeypatch.setattr(lifecycle,'_quick_health',lambda:False)
    monkeypatch.setattr(lifecycle,'_web_agent_ready',lambda:False)
    monkeypatch.setattr(lifecycle,'repair_web',lambda:None)
    monkeypatch.setattr(lifecycle,'tls_readiness',lambda state, store:state.update(
        {'tls':{'status':'DEFERRED','dns':'OTHER_OR_UNRESOLVED'}}))
    recorded=[]
    def fake_command(args, env=None):
        recorded.append((args,env))
        if args==['bash','./install.sh']:
            assert env['DUC_LIFECYCLE_SKIP_PROVISION']=='1'
            assert env['DUC_SKIP_WIZARD']=='1'
            (current/'VERSION').write_text('0.10.3')
    monkeypatch.setattr(lifecycle,'_cmd',fake_command)
    state=lifecycle.new_state('upgrade','0.10.3',I,{})
    lifecycle.execute(state,identity=I,installed='0.10.2',store=lambda s:None)
    assert state['status']=='partial'
    assert state['outcome']=='TUI_READY_WEB_INCOMPLETE'
    assert state['components']['web']['status']=='INCOMPLETE'
    assert state['steps']['snapshot']['status']=='completed'
    assert state['steps']['apply']['status']=='completed'
    assert not any('install-all-engines.sh' in ' '.join(x[0]) for x in recorded)


def test_resume_after_identity_commit_before_journal(monkeypatch, tmp_path):
    # Regression: instance.json was created but journal checkpoint was interrupted.
    from duc import instance
    identity_file=tmp_path/'instance.json'
    obj=instance.initialize('m2m.diy','13.39.238.230',path=identity_file)
    original=identity_file.read_bytes()
    monkeypatch.setattr(instance,'identity_path',lambda:identity_file)
    monkeypatch.setattr(lifecycle,'maintenance_preflight',lambda:None)
    # Simulate only first two stages and interrupt afterward.
    def interrupt(*a, **kw):
        raise RuntimeError('simulated interruption')
    monkeypatch.setattr(lifecycle,'_cmd',interrupt)
    state=lifecycle.new_state('fresh','0.10.3',None,{'domain':'m2m.diy','ip':'13.39.238.230'})
    state['steps']['preflight']={'status':'completed','time':'test'}
    with pytest.raises(RuntimeError):
        lifecycle.execute(state,identity=obj,installed=None,store=lambda s:None)
    assert state['instance_id']==obj['instance_id']
    assert identity_file.read_bytes()==original
    assert state['steps']['instance']['status']=='completed'
