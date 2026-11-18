"""Regression tests for user-facing SlipStream client documentation.

No network or systemd changes are made by these tests.
"""
import io
import pathlib
import zipfile
from duc import core, workflow


def test_slipstream_tcp_verification_is_client_first(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'ROOT', tmp_path)
    guide = workflow.build_client_guide('slipstream', '1.1.1.1:53', 2080)
    assert 'SOCKS5' in guide['verification_command']
    assert 'Dante' in guide['verification_command']
    assert 'ssh-keyscan' not in guide['verification_command']
    assert '--resolver 1.1.1.1:53' in guide['example_command']
    assert '--domain r.example.com' in guide['example_command']
    assert '--tcp-listen-port 2080' in guide['example_command']
    assert '--cert ./slipstream-rust.crt' in guide['example_command']
    assert any('raw TCP' in line for line in guide['steps'])


def test_slipstream_guide_zip_includes_client_options_no_private_key(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'ROOT', tmp_path)
    keydir = tmp_path/'keys'
    keydir.mkdir()
    (keydir/'slipstream-rust.crt').write_text('PUBLIC_CERT_ONLY')
    (keydir/'slipstream-rust.key').write_text('PRIVATE_KEY_DO_NOT_INCLUDE')
    package = workflow.create_public_guide_bundle('slipstream', '1.1.1.1:53', 2080)
    with zipfile.ZipFile(io.BytesIO(package)) as z:
        assert 'SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md' in z.namelist()
        assert 'slipstream-rust.crt' in z.namelist()
        assert not any(n.endswith(('.key', '.pass')) for n in z.namelist())
        guide = z.read('SLIPSTREAM_CLIENT_OPTIONS_FA_EN.md').decode('utf-8')
        for required in ('Client Options', 'Using the Tunnel', 'SSH backend',
                         'SOCKS5 backend', 'Shadowsocks backend', '--gso',
                         '--authoritative 188.132.174.249:53', 'server_port": 2080'):
            assert required in guide
        assert 'PRIVATE_KEY_DO_NOT_INCLUDE' not in str(z.namelist())
        assert b'PRIVATE_KEY_DO_NOT_INCLUDE' not in package


def test_web_client_documentation_is_non_invasive():
    root = pathlib.Path(__file__).resolve().parents[1]
    script = (root/'web/app.js').read_text()
    assert 'renderSlipstreamClientHelp(status.engines.slipstream.config)' in script
    assert 'renderSlipstreamClientHelp(engine.config)' in script
    assert 'renderSlipstreamClientHelp(o.config)' in script
    assert 'ssh-keyscan/server-first may time out' in script
    assert 'Experimental / not fully implemented in Rust: left OFF' in script
    assert "['./slipstream-rust-client','--domain'" in script
    assert 'systemctl start danted' not in script
    assert 'iptables -t nat -A' not in script


def test_generated_slipstream_guide_does_not_pretend_tcp_forward_is_socks(tmp_path, monkeypatch):
    monkeypatch.setattr(core, 'ROOT', tmp_path)
    guide=workflow.build_client_guide('slipstream', '8.8.8.8:53', 2080)
    text='\n'.join(guide['steps'])
    assert 'not SOCKS5' in text
    assert 'SS' not in guide['example_command']
    assert '--gso' not in guide['example_command']
