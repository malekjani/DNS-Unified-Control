"""Regression checks for panel-native SlipStream importer and no-stdin CLI."""
from pathlib import Path

from fastapi.testclient import TestClient
from duc import agent, jobs, slipstream_ali, worker


def test_web_preflight_read_only(monkeypatch):
    seen=[]
    marker={"engine":"slipstream","limited":True,"blocked":False,
            "binaries":{"server":{"state":"verified"},"client":{"state":"verified"}}}
    def fake_preflight():
        seen.append('read-only')
        return marker
    monkeypatch.setattr(slipstream_ali, 'preflight', fake_preflight)
    with TestClient(agent.app) as client:
        result=client.get('/workflow/preflight/slipstream')
        assert result.status_code==200
        assert result.json()==marker
        assert client.post('/workflow/jobs/install-server/slipstream',json={'confirm':'WRONG'}).status_code==422
    assert seen==['read-only']


def test_install_job_uses_only_pinned_importer(monkeypatch):
    assert 'slipstream' in jobs.ACTIONS['install-server']
    called=[]
    def fake_install():
        called.append('pinned-only')
        return {'repository':slipstream_ali.REPO,'tag':slipstream_ali.TAG}
    monkeypatch.setattr(slipstream_ali,'install',fake_install)
    result=worker.install_server('slipstream')
    assert called==['pinned-only']
    assert 'no activation' in result['message']
    assert result['source_commit']==slipstream_ali.TAG


def test_read_only_preflight_when_binaries_missing(monkeypatch,tmp_path):
    monkeypatch.setitem(slipstream_ali.BINARIES['server'],'target',tmp_path/'missing-server')
    monkeypatch.setitem(slipstream_ali.BINARIES['client'],'target',tmp_path/'missing-client')
    data=slipstream_ali.preflight()
    assert data['binaries']['server']['state']=='missing'
    assert data['binaries']['client']['state']=='missing'
    assert data['repository']==slipstream_ali.REPO
    assert data['tag']==slipstream_ali.TAG
    assert not list(tmp_path.iterdir())


def test_cli_has_no_interactive_yes_gate():
    path=Path(__file__).resolve().parents[1]/'scripts/install-slipstream-ali.sh'
    script=path.read_text()
    assert 'IFS= read -r confirmation' not in script
    assert 'Type exactly yes' not in script
    assert '[[ -t 0 ]]' not in script
    assert 'duc.slipstream_ali --install' in script
    assert 'systemctl start' not in script
    assert 'iptables -t nat -A' not in script
