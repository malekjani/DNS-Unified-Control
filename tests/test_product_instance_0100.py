"""Fresh-install identity portability, safe resume and no customer hardcoded runtime."""
from pathlib import Path
import importlib.util
import json
import os
import stat
import uuid

import pytest

from duc import fresh_setup, instance


def test_two_vps_independent_instances(tmp_path):
    a = instance.initialize('alpha.example.org', '1.1.1.1', path=tmp_path/'server-a.json')
    b = instance.initialize('beta.example.net', '8.8.8.8', path=tmp_path/'server-b.json')
    assert a['domain'] == 'alpha.example.org'
    assert b['domain'] == 'beta.example.net'
    assert a['public_ipv4'] != b['public_ipv4']
    assert uuid.UUID(a['instance_id']) != uuid.UUID(b['instance_id'])
    assert a['panel_fqdn'] == 'panel.alpha.example.org'
    assert b['nameserver_fqdn'] == 'ns.beta.example.net'
    assert stat.S_IMODE((tmp_path/'server-a.json').stat().st_mode) == 0o600


def test_resume_same_instance_only(tmp_path):
    path=tmp_path/'instance.json'
    original=instance.initialize('alpha.example.org','1.1.1.1',path=path)
    assert instance.initialize('alpha.example.org','1.1.1.1',resume=True,path=path)==original
    for domain, addr in [('alpha.example.org','8.8.8.8'),('other.example.org','1.1.1.1')]:
        with pytest.raises(instance.InstanceError,match='mismatch'):
            instance.initialize(domain,addr,resume=True,path=path)
    with pytest.raises(instance.InstanceError,match='already exists'):
        instance.initialize('alpha.example.org','1.1.1.1',path=path)
    assert instance.load(path)==original


def test_resume_without_prior_identity_fails_closed(tmp_path):
    with pytest.raises(instance.InstanceError,match='not initialized'):
        instance.initialize('alpha.example.org','1.1.1.1',resume=True,path=tmp_path/'missing')


def test_bad_identity_never_silently_reinitialized(tmp_path):
    path=tmp_path/'identity.json'
    path.write_text('{broken json',encoding='utf-8')
    with pytest.raises(instance.InstanceError,match='Corrupt'):
        instance.initialize('alpha.example.org','1.1.1.1',resume=True,path=path)


def test_symlink_identity_refused(tmp_path):
    original=tmp_path/'original'
    original.write_text('{}')
    link=tmp_path/'link'
    link.symlink_to(original)
    with pytest.raises(instance.InstanceError,match='symlink'):
        instance.load(link)


def test_cli_is_reusable_on_two_servers(tmp_path,capsys):
    path=tmp_path/'iid'
    assert instance.main(['init','--instance-file',str(path),'--domain','site.example.net','--ip','8.8.8.8'])==0
    result=json.loads(capsys.readouterr().out)
    assert result['domain']=='site.example.net'
    assert instance.main(['verify','--instance-file',str(path),'--domain','site.example.net','--ip','8.8.8.8'])==0
    capsys.readouterr()
    assert instance.main(['verify','--instance-file',str(path),'--domain','wrong.example.net'])==2
    assert 'mismatch' in capsys.readouterr().err


def test_os_release_fail_closed_unverified_distros():
    for os_text in ('ID=ubuntu\nVERSION_ID=22.04\n','ID=debian\nVERSION_ID=11\n','ID=fedora\nVERSION_ID=41\n'):
        report=fresh_setup.collect(domain='example.net',ip='1.1.1.1',os_text=os_text,
            mem_text='MemTotal: 2097152 kB\nSwapTotal: 1048576 kB\n',
            disk_free=12*fresh_setup.GIB,port_text='',existing=False,systemd=True,apt=True)
        assert not report['ready_for_base_install']
        assert next(c for c in report['checks'] if c['id']=='os')['status']=='block'


def test_audit_remedies_are_domain_scoped():
    report=fresh_setup.collect(domain='portable.example.net',ip='1.1.1.1',os_text='ID=debian\nVERSION_ID=13\n',
        mem_text='MemTotal: 2097152 kB\nSwapTotal: 1048576 kB\n',
        disk_free=12*fresh_setup.GIB,port_text='',existing=False,systemd=True,apt=True)
    assert report['ready_for_base_install']
    assert 'old_ip_example' not in report
    assert 'ns.portable.example.net' in next(c for c in report['checks'] if c['id']=='fresh_identity')['remedy']


def test_product_entrypoints_have_no_specific_customer_domain():
    root=Path(__file__).resolve().parents[1]
    for filename in ('scripts/fresh-install.sh','scripts/fresh-cloudflare-cutover.py','duc/fresh_setup.py','upgrade.sh'):
        text=(root/filename).read_text()
        assert 'm2m.diy' not in text
        assert '188.132.174.249' not in text
    assert 'required=True' in (root/'scripts/fresh-cloudflare-cutover.py').read_text()


def test_cloudflare_domain_validation_without_network():
    path=Path(__file__).resolve().parents[1]/'scripts/fresh-cloudflare-cutover.py'
    spec=importlib.util.spec_from_file_location('duc_cloudflare_cutover',path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.valid_domain('Example.ORG.')=='example.org'
    for bad in ('m2m.diy/../../../etc','example..org','localhost'):
        with pytest.raises(mod.GuardError):mod.valid_domain(bad)
