from pathlib import Path
from duc import web
root=Path(__file__).resolve().parents[1]

def test_release_installs_multi_files_but_does_not_start_dns():
    script=(root/'install.sh').read_text()
    assert 'cp -R ./ducmulti /opt/dns-unified-control/' in script
    assert 'dns-unified-multi-router.service;do' in script
    assert 'systemctl start dns-unified-multi' not in script

def test_web_and_agent_register_multi_endpoints():
    from duc import agent
    assert any(r.path=='/api/multi/status' for r in web.app.routes)
    assert any(r.path=='/multi/status' for r in agent.app.routes)

def test_mode_switch_guard_and_lifecycle_snapshot():
    assert 'Use Multi-Engine panel/Agent to switch mode' in (root/'duc/core.py').read_text()
    assert 'dns-unified-multi-router.service' in (root/'duc/lifecycle.py').read_text()

def test_rollback_disposes_uncommitted_multi_units():
    life=(root/'duc/lifecycle.py').read_text()
    assert "elif unit in ('dns-unified-multi@.service', 'dns-unified-multi-router.service')" in life
