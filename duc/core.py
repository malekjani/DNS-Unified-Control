"""Root-agent logic. No arbitrary user-supplied commands are ever executed."""
from __future__ import annotations
import copy, fcntl, ipaddress, json, os, pathlib, re, shutil, subprocess, time
from contextlib import contextmanager
from typing import Any

ROOT = pathlib.Path(os.getenv('DUC_CONFIG_DIR', '/etc/dns-unified'))
STATE = pathlib.Path(os.getenv('DUC_STATE_DIR', '/var/lib/dns-unified'))
from .catalog import ENGINES, NAMES, LABELS, FAMILIES, METHODS, BINARIES, META
DEFAULTS = {
 'master': {'domain':'m.example.com','udp_port':53,'arq_window':1000,'log_level':'INFO','encryption_method':2,'client_port':2080},
 'slipstream': {'domain':'r.example.com','udp_port':53,'target':'127.0.0.1:1080','dns_listen_host':'0.0.0.0','max_connections':256,'idle_timeout_seconds':60,'client_resolvers':'1.1.1.1:53,8.8.8.8:53','client_authoritative':'','client_port':2080,'client_keep_alive':400,'client_cc':'auto'},
 'dnstt': {'domain':'d.example.com','udp_port':53,'target':'127.0.0.1:1080'},
 'noizdns': {'domain':'n.example.com','udp_port':53,'target':'127.0.0.1:1080'},
 'vaydns': {'domain':'v.example.com','udp_port':53,'target':'127.0.0.1:1080','mtu':1232,'dnstt_compat':False,'record_type':'txt','queue_size':512,'vay_idle_timeout':10,'vay_keepalive':2,'vay_kcp_window':0,'vay_queue_overflow':'drop','vay_log_level':'info'},
 'soar': {'domain':'s.example.com','udp_port':53,'target':'127.0.0.1:1080'},
 'iodine': {'domain':'i.example.com','udp_port':53,'tunnel_ip':'10.78.0.1'},
 'dns2tcp': {'domain':'c.example.com','udp_port':53,'target':'127.0.0.1:22','resource':'ssh'},
 'xdns': {'domain':'x.example.com','udp_port':53,'xdns_record_type':'txt','xdns_mtu':900},
}
FIELDS = {'domain':{'type':'domain'},'udp_port':{'type':'int','min':1,'max':65535},
 'arq_window':{'type':'int','min':10,'max':8000},'encryption_method':{'type':'int','min':2,'max':5},'log_level':{'type':'enum','choices':['DEBUG','INFO','WARN','ERROR']},
 'target':{'type':'target'},'tunnel_ip':{'type':'ipv4'},'resource':{'type':'resource'},
 'dns_listen_host':{'type':'enum','choices':['0.0.0.0','::','127.0.0.1']},
 'max_connections':{'type':'int','min':1,'max':4096},'idle_timeout_seconds':{'type':'int','min':0,'max':3600},
 'client_port':{'type':'int','min':1024,'max':65535},'client_keep_alive':{'type':'int','min':100,'max':60000},
 'client_cc':{'type':'enum','choices':['auto','bbr','dcubic']},'client_resolvers':{'type':'endpoints'},'client_authoritative':{'type':'endpoints'},
 'vay_idle_timeout':{'type':'int','min':2,'max':180},'vay_keepalive':{'type':'int','min':1,'max':60},
 'vay_kcp_window':{'type':'int','min':0,'max':4096},'vay_queue_overflow':{'type':'enum','choices':['drop','block']},
 'vay_log_level':{'type':'enum','choices':['debug','info','warning','error']},
 'mtu':{'type':'int','min':512,'max':1452}, 'queue_size':{'type':'int','min':16,'max':4096},
 'dnstt_compat':{'type':'bool'},'record_type':{'type':'enum','choices':['txt','a','aaaa','cname']},
 'soar_allow_ports':{'type':'enum','choices':['80,443','443']},
 'xdns_record_type':{'type':'enum','choices':['txt','a','aaaa','cname']},'xdns_mtu':{'type':'int','min':100,'max':1232},
}
SPECS = {engine:list(conf) for engine,conf in DEFAULTS.items()}
UNITS = {x:f'dns-unified@{x}.service' for x in ENGINES}
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
RESOURCE_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{0,20}$')

def validate(field: str, value: Any) -> Any:
    spec = FIELDS[field]; typ = spec['type']
    if typ == 'bool':
        if type(value) is not bool: raise ValueError(f'{field}: boolean required')
        return value
    if typ == 'int':
        if type(value) is not int or not spec['min'] <= value <= spec['max']:
            raise ValueError(f'{field}: integer {spec["min"]}..{spec["max"]} required')
        return value
    if not isinstance(value,str) or len(value) > 253:
        raise ValueError(f'{field}: invalid string')
    if typ == 'domain':
        if any(ord(ch)<32 for ch in value): raise ValueError('control characters not allowed')
        value=value.strip().lower().rstrip('.')
        if not DOMAIN_RE.fullmatch(value): raise ValueError('invalid DNS domain')
    elif typ == 'enum':
        if value not in spec['choices']: raise ValueError('invalid option')
    elif typ == 'ipv4':
        try:
            if not isinstance(ipaddress.ip_address(value),ipaddress.IPv4Address): raise ValueError()
        except ValueError: raise ValueError('invalid IPv4 address')
    elif typ == 'target':
        if value.count(':')!=1: raise ValueError('target must be IPv4-or-hostname:port')
        host,port=value.rsplit(':',1)
        if not host or not re.fullmatch(r'[a-zA-Z0-9.-]+',host) or not port.isdigit() or not 1<=int(port)<=65535:
            raise ValueError('invalid target')
        # Prevent accidental exposure of arbitrary public services from an admin typo.
        if host not in ('127.0.0.1','localhost','::1'): raise ValueError('target must be localhost')
    elif typ=='endpoints':
        # Comma-separated IP:port pairs, no hostnames or shell metacharacters.
        parts=[p.strip() for p in value.split(',') if p.strip()]
        if len(parts)>8: raise ValueError('maximum 8 resolver paths')
        if not parts and value.strip(): raise ValueError('invalid resolver list')
        for endpoint in parts:
            if endpoint.startswith('['):
                match=re.fullmatch(r'\[([^\]]+)\]:(\d{1,5})',endpoint)
            else:
                match=re.fullmatch(r'([0-9.]+):(\d{1,5})',endpoint)
            if not match: raise ValueError('resolver must be IPv4:port or [IPv6]:port')
            try: ipaddress.ip_address(match.group(1))
            except ValueError: raise ValueError('invalid resolver IP')
            if not 1<=int(match.group(2))<=65535: raise ValueError('invalid resolver port')
        if len(set(parts))!=len(parts): raise ValueError('duplicate resolver')
        value=','.join(parts)
    elif typ=='resource':
        if not RESOURCE_RE.fullmatch(value): raise ValueError('invalid resource name')
    return value

def atomic_json(path: pathlib.Path, data: Any):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.tmp')
    with open(tmp,'w',encoding='utf-8') as f:
        json.dump(data,f,indent=2,ensure_ascii=False); f.write('\n');f.flush();os.fsync(f.fileno())
    os.chmod(tmp,0o600); os.replace(tmp,path)

def profiles():
    p=ROOT/'profiles.json'; defaults=copy.deepcopy(DEFAULTS)
    if not p.exists(): return defaults
    loaded=json.loads(p.read_text())
    for e in ENGINES:
        if e in loaded and isinstance(loaded[e],dict):
            for k in SPECS[e]:
                if k in loaded[e]: defaults[e][k]=validate(k,loaded[e][k])
    return defaults

def update_profile(engine, edits):
    if engine not in ENGINES: raise ValueError('unknown engine')
    if not isinstance(edits,dict) or not edits: raise ValueError('empty update')
    if set(edits)-set(SPECS[engine]): raise ValueError('unapproved field')
    data=profiles()
    for k,v in edits.items(): data[engine][k]=validate(k,v)
    # One stable, distinct DNS delegation prefix per engine; a switch never borrows
    # another engine's DNS zone, even if its process is stopped.
    if data[engine]['domain'].split('.',1)[0] != LABELS[engine]:
        raise ValueError(f'{engine}: domain must use its assigned DNS label {LABELS[engine]}.')
    if engine=='slipstream':
        c=data[engine]
        if not c['client_resolvers'] and not c['client_authoritative']:
            raise ValueError('SlipStream Rust requires at least one resolver or authoritative endpoint')
        rec=c['client_resolvers'].split(',') if c['client_resolvers'] else []
        auth=c['client_authoritative'].split(',') if c['client_authoritative'] else []
        if len(set(rec+auth))!=len(rec+auth):raise ValueError('resolver and authoritative addresses must be unique')
    if engine=='vaydns' and data[engine]['vay_keepalive']>=data[engine]['vay_idle_timeout']:
        raise ValueError('VayDNS keepalive must be less than idle timeout')
    atomic_json(ROOT/'profiles.json',data)
    return data[engine]

def run(cmd,timeout=12):
    return subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)

def is_active(engine):
    return run(['systemctl','is-active','--quiet',UNITS[engine]],5).returncode==0

def list_active(): return [e for e in ENGINES if is_active(e)]

def unit_status(engine):
    r=run(['systemctl','show',UNITS[engine],'-p','ActiveState','-p','SubState','-p','MainPID','-p','NRestarts','--no-pager'],6)
    if r.returncode!=0: return {'active':False,'state':'unknown','pid':0,'restarts':0}
    x=dict(z.split('=',1) for z in r.stdout.splitlines() if '=' in z)
    return {'active':x.get('ActiveState')=='active','state':x.get('SubState','unknown'),
      'pid':int(x.get('MainPID','0') or 0),'restarts':int(x.get('NRestarts','0') or 0)}

def check_ready(engine, conf=None):
    conf=conf or profiles()[engine]
    issues=[]
    if conf['domain'].endswith('example.com'): issues.append('Set a real delegated tunnel domain')
    if conf['domain'].split('.',1)[0] != LABELS[engine]: issues.append('Configured domain does not match assigned DNS label for this engine')
    binary=shutil.which(BINARIES[engine])
    if not binary: issues.append(f'Install {BINARIES[engine]} in system PATH')
    if engine=='master':
        if not (ROOT/'engines/master/base.toml').is_file(): issues.append('Copy official server_config.toml.simple to engines/master/base.toml')
        if not (ROOT/'keys/master.key').is_file(): issues.append('Create keys/master.key (shared encryption key)')
    # Shared loopback Dante applies to every audited raw-TCP engine, not just
    # SlipStream. Native-SOCKS engines (Master) do not use Dante.
    if engine in ('slipstream','dnstt','vaydns','dns2tcp','noizdns') and conf.get('target')=='127.0.0.1:1080':
        from . import dante
        if not dante.status()['ready']:
            issues.append('Shared Dante SOCKS5 backend not ready on 127.0.0.1:1080')
    if engine=='slipstream':
        for key_name in ('slipstream-rust.crt','slipstream-rust.key','slipstream-rust.reset-seed'):
            if not (ROOT/'keys'/key_name).is_file():
                issues.append(f'Missing keys/{key_name}; run scripts/prepare-slipstream-rust.sh')
        for private in ('slipstream-rust.key','slipstream-rust.reset-seed'):
            f=ROOT/'keys'/private
            if f.is_file() and (f.stat().st_mode & 0o077):
                issues.append(f'Fix permissions of keys/{private}: chmod 600')
        seed=ROOT/'keys/slipstream-rust.reset-seed'
        if seed.is_file() and not re.fullmatch(r'[0-9a-fA-F]{32}',seed.read_text()):
            issues.append('Invalid reset seed (must be exactly 32 hex characters)')
    for family in ('dnstt','noizdns','vaydns'):
        if engine==family and not (ROOT/'keys'/f'{family}.key').is_file():
            issues.append(f'Generate keys/{family}.key using the corresponding server -gen-key')
    if engine=='soar':
        if conf.get('target')!='127.0.0.1:1080':
            issues.append('Secure Soar accepts only authenticated Dante 127.0.0.1:1080')
        private=ROOT/'keys/soar.key'
        if not private.is_file() or private.stat().st_mode & 0o077:
            issues.append('Soar server installation incomplete: run install.sh / upgrade.sh (private key 0600)')
        from .soar_secure import public_key
        if not public_key(): issues.append('Soar public key unavailable: run install.sh / upgrade.sh')
        from . import dante
        if not dante.status()['ready']:issues.append('Shared authenticated Dante is not ready')
    if engine=='noizdns' and binary:
        from .noiz_provenance import check as provenance_check
        if not provenance_check(binary):
            issues.append('NoizDNS server is not a verified build of anonvector/dnstt; installer must rebuild it')
        try:
            help_result=run([binary,'-help'],4)
            output=(help_result.stdout or '')+(help_result.stderr or '')
            if '-udp' not in output:
                issues.append('NoizDNS binary has not confirmed -udp mode; PT-mode adapter required for this fork')
        except Exception:
            issues.append('NoizDNS CLI compatibility could not be verified')
    if engine=='xdns':
        config=ROOT/'engines/xdns/server.json'
        if not config.is_file(): issues.append('Provide audited Xray xdns server.json; there is no safe universal autogenerated config')
        elif 'xdns' not in config.read_text():issues.append('Xray config does not contain xdns')
        elif binary:
            try:
                test=run([binary,'run','-test','-c',str(config)],10)
                if test.returncode: issues.append('Xray -test rejected xdns config')
            except Exception: issues.append('Xray config test unavailable')
    if engine=='iodine' and not (ROOT/'keys/iodine.pass').is_file(): issues.append('Write a password to keys/iodine.pass')
    if engine=='dns2tcp' and not (ROOT/'keys/dns2tcp.key').is_file(): issues.append('Write a shared key to keys/dns2tcp.key')
    return {'ready':not issues,'issues':issues,'binary':binary or ''}

def port_53_busy(port):
    # Test via ss after stopping our units. Conservative: any listener on target port blocks us.
    r=run(['ss','-H','-lntu'],5)
    if r.returncode: return ['Could not inspect DNS sockets (ss is required)']
    conflicts=[]
    for line in r.stdout.splitlines():
        cols=line.split()
        if len(cols)>=5:
            local=cols[3]
            if local.rsplit(':',1)[-1]==str(port): conflicts.append(local)
    return conflicts

@contextmanager
def switch_lock():
    STATE.mkdir(parents=True,exist_ok=True)
    with open(STATE/'switch.lock','a+') as f:
        fcntl.flock(f.fileno(),fcntl.LOCK_EX)
        try: yield
        finally: fcntl.flock(f.fileno(),fcntl.LOCK_UN)

def await_active(engine, seconds=6):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if is_active(engine):
            # A transient active state immediately followed by failure is not healthy.
            stable_until=time.monotonic()+1.5
            while time.monotonic()<stable_until:
                time.sleep(.25)
                if not is_active(engine): return False
            return True
        time.sleep(.25)
    return False

def switch(engine, restart=False):
    if engine not in ENGINES and engine!='none': raise ValueError('unknown engine')
    with switch_lock():
        # DUC_MULTI_ADDON_0101: protect against legacy switch while Multi is active.
        try:
            from ducmulti.controller import current as _duc_multi_current
            if _duc_multi_current()['mode']!='exclusive':
                return {'ok':False,'stage':'multi-mode','error':'Use Multi-Engine panel/Agent to switch mode'}
        except ImportError:
            pass
        old=list_active()
        if engine!='none':
            ready=check_ready(engine)
            if not ready['ready']: return {'ok':False,'stage':'preflight','issues':ready['issues'],'before':old}
        if old==[engine] and not restart: return {'ok':True,'stage':'unchanged','active':old}
        # Never start/stop engines while bulk install may be replacing their binaries.
        provision_lock = STATE / 'provision.lock'
        if provision_lock.exists():
            with provision_lock.open('r') as guard:
                try:
                    fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return {'ok':False,'stage':'provisioning',
                            'error':'An engine installation is running; retry switching after it finishes',
                            'before':old}
                finally:
                    # LOCK_UN on a handle not holding the lock is harmless.
                    try: fcntl.flock(guard.fileno(), fcntl.LOCK_UN)
                    except OSError: pass
        for e in old:
            r=run(['systemctl','stop',UNITS[e]],25)
            if r.returncode: return {'ok':False,'stage':'stop','error':r.stderr[-700:],'before':old}
        if engine=='none':
            audit('stop',old,[],'ok')
            return {'ok':True,'stage':'stopped','active':[]}
        conflict=port_53_busy(profiles()[engine]['udp_port'])
        failure=''
        if conflict: failure=f'DNS port is occupied: {", ".join(conflict)}'
        else:
            r=run(['systemctl','start',UNITS[engine]],25)
            if r.returncode: failure='Start failed: '+r.stderr[-700:]
            elif not await_active(engine): failure='Service did not stay active after starting'
        if failure:
            run(['systemctl','stop',UNITS[engine]],15)
            restored=[]
            for e in old:
                rr=run(['systemctl','start',UNITS[e]],25)
                if rr.returncode==0 and await_active(e): restored.append(e)
            audit('switch',old,[engine],failure)
            return {'ok':False,'stage':'rollback','error':failure,'restored':restored,
                'warning':'Check SSH/console if rollback is incomplete; no end-to-end connectivity test was performed'}
        audit('switch',old,[engine],'ok')
        return {'ok':True,'stage':'started','active':[engine], 'warning':'Systemd health only; DNS tunnel connectivity requires a client-side test'}

def audit(action,old,new,result):
    STATE.mkdir(parents=True,exist_ok=True)
    with open(STATE/'audit.jsonl','a') as f:
        f.write(json.dumps({'time':int(time.time()),'action':action,'from':old,'to':new,'result':result})+'\n')

def audit_tail(n=25):
    p=STATE/'audit.jsonl'
    if not p.exists():return []
    return [json.loads(l) for l in p.read_text().splitlines()[-n:]][::-1]

def redact(s):
    # Still treat all process logs as potentially sensitive, and do not send raw secrets intentionally.
    s=re.sub(r'(?im)(ENCRYPTION_KEY|SOCKS5_PASS|private.key|password|token)\s*[:=]\s*\S+',r'\1=[REDACTED]',s)
    return s[:16000]

def journal(engine):
    if engine not in ENGINES: raise ValueError('unknown engine')
    r=run(['journalctl','-u',UNITS[engine],'-n','60','--no-pager','-o','short-iso'],8)
    return redact(r.stdout[-15000:] if r.returncode==0 else r.stderr[-1000:])

def system_metrics():
    import psutil
    cpu=psutil.cpu_percent(interval=.05)
    mem=psutil.virtual_memory()
    rootdisk=psutil.disk_usage('/')
    io=psutil.net_io_counters()
    active=list_active()
    processes=[]
    for eng in active:
        details=unit_status(eng)
        if details['pid']>0:
            try:
                process=psutil.Process(details['pid'])
                processes.append({'engine':eng,'pid':details['pid'],
                                  'rss':process.memory_info().rss,'cpu_percent':process.cpu_percent(interval=.05)})
            except (psutil.NoSuchProcess,psutil.AccessDenied):pass
    return {'cpu':cpu,'ram_percent':mem.percent,'ram_used':mem.used,'ram_total':mem.total,
            'disk_percent':rootdisk.percent,'net_sent':io.bytes_sent,'net_recv':io.bytes_recv,'processes':processes,
            'time':int(time.time()),'active':active,
            'port53':port_53_busy(53)}
