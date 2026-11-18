"""Web certificate and routing are mandatory to mark Web installed."""
from pathlib import Path
from types import SimpleNamespace
from duc import web_install, lifecycle

I={'instance_id':'8dd979b3-c59b-46f6-9c99-c78f751be53c',
   'domain':'m2m.diy','public_ipv4':'13.39.238.230'}


def test_new_server_tui_ready_and_no_certificate_web_incomplete(tmp_path):
    cert=web_install.certificate_status('panel.example.org',live_dir=tmp_path/'live',renewal_dir=tmp_path/'renewal')
    assert cert == {'certificate':'MISSING','renewal':'NOT_CONFIGURED'}
    result=web_install.web_components({'status':'DEFERRED','dns':'OTHER_OR_UNRESOLVED'},cert)
    assert result['tui']['status']=='READY'
    assert result['web']['status']=='INCOMPLETE'


def test_issued_cert_but_missing_tmp_token_is_not_web_ready(tmp_path):
    cert=tmp_path/'live'/'panel.example.org'/'fullchain.pem'
    cert.parent.mkdir(parents=True)
    cert.write_text('mock cert, not actually trusted; openssl is stubbed')
    config=tmp_path/'renewal'/'panel.example.org.conf'
    config.parent.mkdir(parents=True)
    config.write_text('[renewalparams]\ndns_cloudflare_credentials = /run/deleted-certbot-dns01.ini\n')
    issued=web_install.certificate_status('panel.example.org',live_dir=tmp_path/'live',renewal_dir=tmp_path/'renewal',
        run=lambda *args,**kw:SimpleNamespace(returncode=0))
    assert issued == {'certificate':'VALID','renewal':'BROKEN'}
    result=web_install.web_components({'status':'VERIFIED','dns':'TARGET_IP'},issued)
    assert result['web']['status']=='INCOMPLETE'


def test_cert_with_configured_root_only_credential_and_route_is_ready(tmp_path):
    cert=tmp_path/'live'/'panel.example.org'/'fullchain.pem';cert.parent.mkdir(parents=True)
    cert.write_text('stub')
    creds=tmp_path/'cloudflare.ini';creds.write_text('secret=not-used');creds.chmod(0o600)
    config=tmp_path/'renewal'/'panel.example.org.conf';config.parent.mkdir(parents=True)
    config.write_text('[renewalparams]\ndns_cloudflare_credentials = '+str(creds)+'\n')
    issued=web_install.certificate_status('panel.example.org',live_dir=tmp_path/'live',renewal_dir=tmp_path/'renewal',
        run=lambda *args,**kw:SimpleNamespace(returncode=0))
    assert issued == {'certificate':'VALID','renewal':'CONFIGURED'}
    assert web_install.web_components({'status':'VERIFIED','dns':'TARGET_IP'}, issued)['web']['status']=='READY'
    creds.chmod(0o644)
    assert web_install.certificate_status('panel.example.org',live_dir=tmp_path/'live',renewal_dir=tmp_path/'renewal',
        run=lambda *args,**kw:SimpleNamespace(returncode=0))['renewal']=='BROKEN'


def test_certificate_does_not_finish_web_without_real_tls_and_dns():
    cert={'certificate':'VALID','renewal':'CONFIGURED'}
    assert web_install.web_components({'status':'PENDING','dns':'TARGET_IP'},cert)['web']['status']=='INCOMPLETE'
    assert web_install.web_components({'status':'VERIFIED','dns':'OTHER_OR_UNRESOLVED'},cert)['web']['status']=='INCOMPLETE'


def test_installer_fresh_and_upgrade_calls_internal_web_step():
    root=Path(__file__).parents[1]
    lifecycle_src=(root/'duc/lifecycle.py').read_text()
    assert 'onboard_web_certificate(state' in lifecycle_src
    assert 'execute(state, identity=identity, installed=installed, offer_web=True)' in lifecycle_src
    assert 'TUI_READY_WEB_INCOMPLETE' in lifecycle_src
    assert 'Certbot reconfigure' in (root/'scripts/cert-cloudflare-dns01.sh').read_text() or 'certbot reconfigure' in (root/'scripts/cert-cloudflare-dns01.sh').read_text()


def test_declined_certificate_is_web_partial_not_rollback(monkeypatch):
    record=lifecycle.new_state('repair','0.10.5',I,{})
    monkeypatch.setattr(web_install,'certificate_status',lambda fqdn:{'certificate':'MISSING','renewal':'NOT_CONFIGURED'})
    monkeypatch.setattr(lifecycle,'ask_yes_no',lambda _:False)
    lifecycle.onboard_web_certificate(record,store=lambda s:None)
    assert record['steps']['web_certificate']['status']=='skipped'
    assert web_install.web_components({'status':'DEFERRED','dns':'OTHER_OR_UNRESOLVED'},
        {'certificate':'MISSING','renewal':'NOT_CONFIGURED'})['web']['status']=='INCOMPLETE'


def test_certificate_script_never_edits_a_ns_or_stops_services():
    src=(Path(__file__).parents[1]/'scripts/cert-cloudflare-dns01.sh').read_text()
    assert 'systemctl stop' not in src
    assert 'dns_cloudflare_api_token' in src
    assert 'Cloudflare' in src
    assert 'root-only' in src
    assert 'reconfigure' in src
    assert '--force-renewal' not in src
