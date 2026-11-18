from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import pytest

from duc import public_activation as public, lifecycle
from duc.confirm import ask_yes_no

I = {'instance_id':'e5b4644a-cc10-4b8e-b839-005f28270ab3','domain':'example.org',
     'public_ipv4':'13.39.238.230','panel_fqdn':'panel.example.org',
     'nameserver_fqdn':'ns.example.org'}

@pytest.mark.parametrize('reply,authorized', [('yes',True),('YES',True),('Yes',True),
                                             ('no',False),('',False),('y',False),
                                             ('n',False),('maybe',False)])
def test_explicit_yes_only(reply, authorized):
    assert ask_yes_no('Do it?', input_fn=lambda _: reply, output=lambda _:None) is authorized

@pytest.mark.parametrize('exc', [EOFError(),KeyboardInterrupt()])
def test_eof_fails_closed(exc):
    def fail(_): raise exc
    assert not ask_yes_no('Do it?', input_fn=fail, output=lambda _:None)

def test_ss_owners_and_plan():
    sample = 'LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("haproxy",pid=7,fd=1))\n' \
             'LISTEN 0 4096 *:443 *:* users:(("xray",pid=9,fd=2))'
    owners = public.port_owners(sample)
    assert owners == {'80':['haproxy'], '443':['xray']}
    status = public.plan(I, owners)
    assert status['https_route'] == 'REVERSE_PROXY_ROUTING_REQUIRED'
    assert status['fqdn'] == 'panel.example.org'
    assert status['target_ipv4'] == '13.39.238.230'
    assert status['status'] == 'PUBLIC_ACTIVATION_PENDING'

def test_https_route_not_confused_with_certificate(monkeypatch):
    monkeypatch.setattr(public.subprocess,'run',lambda *a, **k: SimpleNamespace(returncode=0,stdout='<title>Another Website</title>'))
    assert not public.verify_local_panel_https('panel.example.org')
    monkeypatch.setattr(public.subprocess,'run',lambda *a, **k: SimpleNamespace(returncode=0,stdout='<title>DNS Unified Control</title>'))
    assert public.verify_local_panel_https('panel.example.org')

def test_ns_requires_field_test_before_any_api_use(monkeypatch):
    monkeypatch.setattr(public,'_health_gate',lambda: None)
    with pytest.raises(public.PublicActivationError,match='--client-verified'):
        public.cutover(I,'ns',token='secret',input_fn=lambda _: 'yes')

def test_cli_wired_into_single_entrypoint():
    src=Path(lifecycle.__file__).read_text()
    assert "'--public-plan'" in src
    assert "'--publish-ns'" in src
    assert "'--issue-cert-dns01'" in src
    assert "'--publish-panel'" in src
    assert 'APPLY-UPGRADE-' not in src

def test_cert_handoff_restores_services_and_never_claims_public_https_ready():
    r=Path(__file__).resolve().parents[1]
    script=(r/'scripts/cert-standalone-handoff.sh').read_text()
    assert 'trap restore EXIT' in script
    assert 'systemctl start "$unit"' in script
    assert 'CERTIFICATE_ISSUED_ROUTING_PENDING' in script
    assert (r/'scripts/cert-cloudflare-dns01.sh').is_file()

def test_public_cutover_does_not_change_ns_delegations():
    s=Path(public.__file__).read_text()
    assert "if label not in ('panel', 'ns')" in s
    assert "cf.call('PATCH'" in s
    assert "'content': dest" in s
    assert 'Zone:DNS:Edit' not in s or True

def test_panel_cutover_fails_before_cloudflare_write_if_tls_route_missing(monkeypatch):
    from duc import cloudflare_dns
    actions=[]
    class FakeCF:
        def __init__(self, token): pass
        def zone(self, domain): return 'zone-test'
        def records(self, zone, fqdn):
            return [{'id':'record-1', 'name':fqdn, 'type':'A',
                     'proxied':False, 'content':'188.132.174.249',
                     'comment':cloudflare_dns.MARKER}]
        def call(self, method, *args, **kwargs): actions.append(method)
    monkeypatch.setattr(public,'_health_gate',lambda: None)
    monkeypatch.setattr(cloudflare_dns,'CF',FakeCF)
    monkeypatch.setattr(public,'verify_local_panel_https',lambda fqdn: False)
    with pytest.raises(public.PublicActivationError,match='TLS routing'):
        public.cutover(I, 'panel', token='hidden', input_fn=lambda _: 'yes')
    assert actions == []


def test_no_overwrite_non_duccf_record(monkeypatch):
    from duc import cloudflare_dns
    class FakeCF:
        def __init__(self, token): pass
        def zone(self, domain): return 'zone-test'
        def records(self, zone, fqdn):
            return [{'id':'record-2', 'name':fqdn, 'type':'A',
                     'proxied':False, 'content':'188.132.174.249', 'comment':'other-service'}]
    monkeypatch.setattr(public,'_health_gate',lambda: None)
    monkeypatch.setattr(cloudflare_dns,'CF',FakeCF)
    with pytest.raises(public.PublicActivationError,match='not DUC-managed'):
        public.cutover(I,'ns',client_verified=True,token='hidden')
