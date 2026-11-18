import copy, datetime, importlib.util, json, pathlib, socket, socketserver, threading
from contextlib import nullcontext
import pytest
from duc import core, advanced, unified, telemetry, runner

CLIENT=pathlib.Path(__file__).resolve().parents[1]/'client/duc_socks_probe.py'
spec=importlib.util.spec_from_file_location('duc_socks_probe',CLIENT)
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class FakeDante(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request;s.settimeout(3)
        assert probe.recv_exact(s,3)==b'\x05\x01\x02'
        s.sendall(b'\x05\x02')
        auth=probe.recv_exact(s,2);u=probe.recv_exact(s,auth[1]);n=probe.recv_exact(s,1)[0];pw=probe.recv_exact(s,n)
        s.sendall(b'\x01\x00' if (u,pw)==(b'duc-socks',b'secret') else b'\x01\x01')
        if (u,pw)!=(b'duc-socks',b'secret'):return
        assert probe.recv_exact(s,4)==b'\x05\x01\x00\x03'
        name=probe.recv_exact(s,probe.recv_exact(s,1)[0]);port=probe.recv_exact(s,2)
        assert name==b'api.ipify.org' and port==b'\x01\xbb'
        s.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')


def test_native_client_authentication_over_raw_tcp():
    with socketserver.ThreadingTCPServer(('127.0.0.1',0),FakeDante) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        port=server.server_address[1]
        s,ms=probe.connect_socks('127.0.0.1',port,'duc-socks','secret','api.ipify.org',443,3)
        assert ms>=0;s.close()
        with pytest.raises(PermissionError):
            probe.connect_socks('127.0.0.1',port,'duc-socks','wrong','api.ipify.org',443,3)
        server.shutdown();t.join(2)


def test_no_client_gateway_and_backend_policy():
    assert unified.TCP_ENGINES==('slipstream','dnstt','vaydns','noizdns')
    assert 'dns2tcp' not in unified.TCP_ENGINES
    assert unified.MODES['master'][0]=='native-client-socks'
    assert not (CLIENT.parent/'duc_socks_gateway.py').exists()
    assert core.DEFAULTS['slipstream']['target']==unified.TARGET
    assert core.DEFAULTS['dnstt']['target']==unified.TARGET
    assert core.DEFAULTS['vaydns']['target']==unified.TARGET


def test_advanced_vaydns_flags_reflected_in_runner(monkeypatch):
    c=copy.deepcopy(core.DEFAULTS['vaydns'])
    c.update(domain='v.test.example',vay_idle_timeout=24,vay_keepalive=4,vay_kcp_window=40,
             vay_queue_overflow='block',vay_log_level='debug')
    monkeypatch.setattr(runner.shutil,'which',lambda s:'/tmp/vaydns-server')
    cmd=runner.cmd_for('vaydns',c)
    for key,value in [('idle-timeout','24s'),('keepalive','4s'),('kcp-window-size','40'),
                      ('queue-overflow','block'),('log-level','debug')]:
        flag='-'+key
        assert cmd[cmd.index(flag)+1]==value


def test_custom_per_engine_and_restore(monkeypatch,tmp_path):
    profiles=copy.deepcopy(core.DEFAULTS)
    profiles['dnstt']['target']='127.0.0.1:22'
    tmp_path.joinpath('root').mkdir()
    monkeypatch.setattr(unified,'BACKUP',tmp_path/'old.json')
    monkeypatch.setattr(core,'ROOT',tmp_path)
    monkeypatch.setattr(core,'profiles',lambda:copy.deepcopy(profiles))
    monkeypatch.setattr(core,'list_active',lambda:[])
    monkeypatch.setattr(core,'switch_lock',lambda:nullcontext())
    monkeypatch.setattr(unified.dante,'status',lambda:{'ready':True})
    def save(p,d):
        if p.name=='profiles.json':profiles.update(copy.deepcopy(d))
        else:p.write_text(json.dumps(d))
    monkeypatch.setattr(core,'atomic_json',save)
    assert unified.configure('dante',['dnstt'])['ok']
    assert profiles['dnstt']['target']=='127.0.0.1:1080'
    assert unified.configure('custom',['dnstt'],'127.0.0.1:1090')['ok']
    assert profiles['dnstt']['target']=='127.0.0.1:1090'
    assert unified.configure('restore',['dnstt'])['ok']
    assert profiles['dnstt']['target']=='127.0.0.1:22'
    with pytest.raises(ValueError):unified.configure('custom',['dnstt'],'8.8.8.8:443')
    with pytest.raises(ValueError):unified.configure('dante',['dns2tcp'])


def data():
    return {'schema':1,'engine':'slipstream',
       'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),
       'measurement':'real-client-socks5-https',
       'samples':4,'successful':3,'failed':1,'request_failure_pct':25.0,
       'socks_connect_rtt_ms':80.4,'http_ttfb_ms':150.0,'http_throughput_bps':1250.0,
       'exit_ip':'188.132.174.249','raw_dns_packet_loss_pct':None,
       'password':'THIS IS NOT STORED'}


def test_telemetry_validates_strips_secrets(monkeypatch,tmp_path):
    monkeypatch.setattr(telemetry,'FILE',tmp_path/'telemetry.json')
    monkeypatch.setattr(telemetry,'LOCK',tmp_path/'telemetry.lock')
    monkeypatch.setattr(core,'STATE',tmp_path)
    report=data()
    result=telemetry.save(report);assert result['stored']
    saved=json.loads(telemetry.FILE.read_text())
    assert saved[0]['request_failure_pct']==25
    assert 'password' not in str(saved)
    with pytest.raises(ValueError):telemetry.save(report)
    evil=data();evil['raw_dns_packet_loss_pct']=3
    with pytest.raises(ValueError):telemetry.validate(evil)
    evil=data();evil['request_failure_pct']=float('nan')
    with pytest.raises(ValueError):telemetry.validate(evil)
    assert telemetry.snapshot()['latest']['slipstream']['successful']==3


def test_missing_relay_is_not_claimed_to_be_tunnel_loss():
    r=probe.summary('dnstt',[{'ok':False,'error_type':'TimeoutError'},{'ok':True,'socks_connect_rtt_ms':200,
           'http_ttfb_ms':100,'http_body_bps':1000,'exit_ip':'188.132.174.249'}])
    assert r['request_failure_pct']==50
    assert r['raw_dns_packet_loss_pct'] is None
    assert r['socks_connect_rtt_ms']==200


def test_more_engine_options_truthful():
    registry=advanced.registry()
    assert len(registry)==9
    assert registry['noizdns']['server_operational']==['domain','udp_port','target']
    assert registry['xdns']['server_operational']==[]
    assert 'vay_keepalive' in registry['vaydns']['server_operational']


def test_backend_custom_validation():
    with pytest.raises(ValueError):unified.configure('custom',['dnstt','vaydns'],'127.0.0.1:1090')
    with pytest.raises(ValueError):unified.configure('custom',['dnstt'],'localhost:65536')


def test_vay_compat_preserves_upstream_compat_timers(monkeypatch):
    c=copy.deepcopy(core.DEFAULTS['vaydns']);c['dnstt_compat']=True
    monkeypatch.setattr(runner.shutil,'which',lambda s:'/tmp/vaydns-server')
    cmd=runner.cmd_for('vaydns',c)
    assert '-dnstt-compat' in cmd
    assert '-idle-timeout' not in cmd and '-keepalive' not in cmd
    c['vay_idle_timeout']=30;c['vay_keepalive']=5
    cmd=runner.cmd_for('vaydns',c)
    assert cmd[cmd.index('-idle-timeout')+1]=='30s'
    assert cmd[cmd.index('-keepalive')+1]=='5s'


def test_short_ip_check_not_misreported_as_throughput():
    sample=[{'ok':True,'socks_connect_rtt_ms':30.0,
             'http_ttfb_ms':41.0,'http_body_bps':None,'exit_ip':'188.132.174.249'}]
    record=probe.summary('slipstream',sample)
    assert record['http_throughput_bps'] is None
    assert record['request_failure_pct']==0
