"""Privilege-gated switch controller with explicit preflight and rollback.

Does not mutate DNS, keys, Caddy, Xray, HAProxy, or Dante.
"""
from __future__ import annotations
import copy, fcntl, ipaddress, json, os, pathlib, re, socket, subprocess, time
from contextlib import contextmanager
from . import ENGINE_PORTS,ENGINE_ORDER
from .router import load_config

MODE_FILE='multi-mode.json';ROUTER_FILE='multi-router.json';STAGING_FILE='multi-staging.json'
ROUTER_UNIT='dns-unified-multi-router.service'

def deps():
    from duc import core
    return core

def current():
    core=deps();p=core.STATE/MODE_FILE
    if not p.exists():return {'schema':'duc.multi.mode.v1','mode':'exclusive','engines':[]}
    try:
        data=json.loads(p.read_text())
        if data.get('schema')=='duc.multi.mode.v1' and data.get('mode') in ('multi','exclusive') and isinstance(data.get('engines'),list):
            return data
    except (ValueError,OSError,TypeError):pass
    # Never reinterpret damaged state as Exclusive: that could start a conflicting :53 unit.
    return {'schema':'duc.multi.mode.v1','mode':'unknown','engines':[],
            'error':'Invalid lifecycle mode file; manual recovery required'}

def run(cmd,timeout=30):
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)
    return r.returncode,r.stdout[-500:],r.stderr[-600:]

def full_run(cmd,timeout=10):
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)
    return r.returncode,r.stdout,r.stderr

def active(unit):return run(['systemctl','is-active','--quiet',unit],5)[0]==0

def host_ipv4():
    try:
        code,out,_=run(['ip','-j','-4','route','get','1.1.1.1'],5)
        if code==0:
            data=json.loads(out)
            ip=ipaddress.IPv4Address(data[0]['prefsrc'] if 'prefsrc' in data[0] else data[0]['src'])
            if not (ip.is_loopback or ip.is_multicast or ip.is_unspecified):return str(ip)
    except (ValueError,KeyError,IndexError,TypeError,OSError):pass
    return None

def interface_addresses():
    code,out,_=run(['ip','-j','-4','addr','show'],6)
    if code:return []
    try:return [addr['local'] for dev in json.loads(out) for addr in dev.get('addr_info',[]) if addr.get('family')=='inet']
    except (ValueError,KeyError,TypeError):return []

def tcp_or_udp_listen(ip,port):
    # Both TCP and UDP are required for an authoritative DNS endpoint.
    r=full_run(['ss','-H','-lntu'],5)
    if r[0]:return ['socket inspection failed']
    targets={ip+':'+str(port),'0.0.0.0:'+str(port),'*:'+str(port),'[::]:'+str(port),':::'+str(port)}
    return [line.strip()[:190] for line in r[1].splitlines() if len(line.split())>=5 and line.split()[3] in targets]

def external_cotten():
    core=deps();f=core.ROOT/'cotten-adapter.json'
    try:
        obj=json.loads(f.read_text())
        if set(obj)!={'schema','zone','port','unit'} or obj['schema']!='duc.cotten.adapter.v1':raise ValueError('invalid adapter schema')
        if not isinstance(obj['zone'],str) or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+){2,}',obj['zone'].lower()):raise ValueError('bad zone')
        if type(obj['port'])!=int or obj['port']!=ENGINE_PORTS['cotten']:raise ValueError('Cotten port must be 5303')
        if type(obj['unit'])!=str or not obj['unit'].startswith('cotten') or not obj['unit'].endswith('.service') or '/' in obj['unit']:raise ValueError('unsupported Cotten unit')
        return obj,[]
    except (ValueError,KeyError,TypeError,OSError) as exc:
        return None,['CottenDNS requires a reviewed existing loopback service and /etc/dns-unified/cotten-adapter.json ('+type(exc).__name__+')']

def plan(mode,engines=None,listen_ip=None):
    core=deps()
    if mode not in ('exclusive','multi'):raise ValueError('mode must be exclusive or multi')
    engines=list(engines or [])
    if not engines or len(set(engines))!=len(engines):raise ValueError('engines must be a nonempty unique list')
    if any(e not in ENGINE_ORDER for e in engines):raise ValueError('unsupported engine')
    if mode=='exclusive' and len(engines)!=1:raise ValueError('Exclusive requires exactly one engine')
    listen_ip=listen_ip or host_ipv4()
    issues=[];warnings=[];routes=[]
    if not listen_ip:issues.append('Cannot discover the primary local IPv4; specify listen_ip')
    else:
        try:
            ip=ipaddress.IPv4Address(listen_ip)
            if ip.is_loopback or ip.is_unspecified or ip.is_multicast:issues.append('Router IP must be an actual non-loopback interface address')
            elif str(ip) not in interface_addresses():issues.append('Router IP not assigned to a local interface (use AWS private ens5 IP, not public NAT IP)')
        except ValueError:issues.append('Invalid IPv4')
    profiles=core.profiles()
    for e in engines:
        if e=='cotten':
            cfg,problems=external_cotten()
            issues.extend(problems)
            if cfg:
                code,unit_state,_=full_run(['systemctl','show',cfg['unit'],'-p','LoadState','--value'],5)
                if code or unit_state.strip()!='loaded':issues.append('Cotten unit must exist and be loaded')
                if active(cfg['unit']):
                    code,out,_=full_run(['ss','-H','-lntu'],5)
                    listeners=[l for l in out.splitlines() if len(l.split())>=5 and l.split()[3]=='127.0.0.1:'+str(cfg['port'])]
                    if code or len(listeners)<2:issues.append('Cotten must expose TCP AND UDP 127.0.0.1:5303')
                routes.append({'engine':e,'zone':cfg['zone'].strip().lower().rstrip('.'),'port':cfg['port'],'tcp':True})
        else:
            ready=core.check_ready(e)
            issues.extend(f'{e}: {reason}' for reason in ready['issues'])
            if mode=='multi' and e=='slipstream' and not ready['ready']:
                warnings.append('SlipStream Rust requires its own loopback listener and certificate')
            routes.append({'engine':e,'zone':profiles[e]['domain'],'port':ENGINE_PORTS[e],'tcp':False})
    if mode=='multi':
        # A pre-existing listener on a proposed backend port is not overwritten.
        code,live,_=full_run(['ss','-H','-lntu'],5)
        if code:issues.append('Cannot inspect proposed backend ports')
        else:
            for e in engines:
                if e=='cotten':continue  # Controlled external Cotten adapter is verified separately.
                port=ENGINE_PORTS[e]
                matches=[ln for ln in live.splitlines() if len(ln.split())>=5 and ln.split()[3].rsplit(':',1)[-1]==str(port)]
                if matches and not active(f'dns-unified-multi@{e}.service'):
                    issues.append(f'{e}: backend port {port} is already occupied')
        try:
            from .router import Resolver,Route
            Resolver([Route(r['engine'],r['zone'],r['port'],r['tcp']) for r in routes])
        except ValueError as exc:issues.append('Invalid or overlapping route domains: '+str(exc))
    prior=current();classic=core.list_active()
    if prior['mode']=='unknown':issues.append('Mode state file is corrupt or unknown; refuse all switching')
    if prior['mode']=='multi' and 'cotten' in prior.get('engines',[]):
        prev_cotten,prev_errors=external_cotten()
        if not prev_cotten:issues.extend('Current Cotten backend cannot be managed: '+x for x in prev_errors)
    active_multi=[e for e in ENGINE_ORDER if e!='cotten' and active(f'dns-unified-multi@{e}.service')]
    if prior['mode']=='multi' and 'cotten' in prior.get('engines',[]):
        c,_=external_cotten()
        if c and active(c['unit']):active_multi.append('cotten')
    if len(classic)>1:issues.append('Multiple legacy Exclusive engines are active; manual recovery required')
    if classic and active_multi:issues.append('Legacy and Multi engine units are both active; manual recovery required')
    if prior['mode']=='exclusive' and active_multi:issues.append('Multi units unexpectedly active in Exclusive state')
    if prior['mode']=='multi' and classic:issues.append('Exclusive unit unexpectedly active in Multi state')
    if mode=='exclusive' and engines[0]=='cotten':issues.append('Cotten Exclusive adapter has not been verified')
    if mode=='multi' and listen_ip:
        busy=tcp_or_udp_listen(listen_ip,53)
        if busy and prior['mode']=='multi' and active(ROUTER_UNIT):warnings.append('Router currently owns port 53; will be replaced with rollback protection')
        elif busy and classic:
            warnings.append('Exclusive listener currently occupies port 53; will be stopped only after explicit approval')
        elif busy:issues.append('Public DNS port 53 occupied: '+str(busy))
    warnings.extend(['Only local systemd/socket health is verified; client end-to-end traffic remains untested',
      'Switching the active DNS path can disconnect currently connected clients; keep SSH console and rollback access',
      'No Cloudflare, NS delegation, HTTPS, Xray or Dante changes are performed'])
    return {'schema':'duc.multi.plan.v1','mode':mode,'selected':engines,'listen_ip':listen_ip,
       'prior_mode':prior['mode'],'existing_exclusive':classic,'existing_multi':active_multi,
       'routes':routes,'ready':not issues,'issues':issues,'warnings':warnings}

def check(code_tuple,description):
    if code_tuple[0]!=0:raise RuntimeError(description+': '+code_tuple[2][:250])

def await_unit(unit,seconds=7):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if active(unit):
            time.sleep(.7)
            return active(unit)
        time.sleep(.2)
    return False

def unit_enabled(unit):
    return run(['systemctl','is-enabled','--quiet',unit],5)[0]==0


def has_listener(ip,port,proto='udp'):
    code,lines,_=full_run(['ss','-H','-lntu'],5)
    if code:return False
    for ln in lines.splitlines():
        p=ln.split()
        if len(p)>=5 and p[0].lower().startswith(proto) and p[3]==f'{ip}:{port}':return True
    return False


def await_listener(ip,port,proto='udp',seconds=12):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if has_listener(ip,port,proto):return True
        time.sleep(.25)
    return False

def status():
    core=deps();c=current()
    cu,_=external_cotten() if 'cotten' in c.get('engines',[]) else (None,[])
    units=[e for e in ENGINE_ORDER if e!='cotten' and active(f'dns-unified-multi@{e}.service')]
    if cu and c['mode']=='multi' and active(cu['unit']):units.append('cotten')
    return {'mode':c['mode'],'selected':c['engines'], 'exclusive_active':core.list_active(),
       'multi_units':units,
       'router_active':active(ROUTER_UNIT),'public_port_listen':c.get('listen_ip'),
       'field_test':'NOT_VERIFIED_BY_ROUTER','available_engines':list(ENGINE_ORDER)}

@contextmanager
def provision_guard():
    core=deps();path=core.STATE/'provision.lock'
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a+') as f:
        try:
            fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Engine provisioning is running; switching is blocked') from exc
        try:yield
        finally:fcntl.flock(f.fileno(),fcntl.LOCK_UN)

def apply(mode,engines,listen_ip=None,confirm=None):
    if confirm!='yes':raise ValueError('Explicit yes required')
    if os.geteuid()!=0:raise PermissionError('Privileged agent / root required')
    core=deps()
    with core.switch_lock(), provision_guard():
        p=plan(mode,engines,listen_ip)
        if not p['ready']:return {'ok':False,'stage':'preflight','issues':p['issues'],'warnings':p['warnings']}
        old=current(); old_classic=core.list_active();old_multi=[e for e in ENGINE_ORDER if active(f'dns-unified-multi@{e}.service')]
        old_cotten_cfg,_=external_cotten()
        old_cotten_active=bool(old_cotten_cfg and old['mode']=='multi' and 'cotten' in old.get('engines',[]) and active(old_cotten_cfg['unit']))
        if old_cotten_active and 'cotten' not in old_multi and old['mode']=='multi':old_multi.append('cotten')
        old_router=active(ROUTER_UNIT)
        managed_units=[ROUTER_UNIT]+list(core.UNITS.values())+[f'dns-unified-multi@{e}.service' for e in ENGINE_ORDER if e!='cotten']
        if old_cotten_cfg and ('cotten' in old.get('engines',[]) or 'cotten' in engines):managed_units.append(old_cotten_cfg['unit'])
        before_enabled={u:unit_enabled(u) for u in managed_units}
        if old['mode']==mode and (mode=='multi' and set(old['engines'])==set(engines) and old_router or
                                  mode=='exclusive' and old_classic==engines):
            return {'ok':True,'stage':'unchanged','status':status()}
        old_mode_file=core.STATE/MODE_FILE
        old_mode_bytes=old_mode_file.read_bytes() if old_mode_file.exists() else None
        old_files={}
        files=[core.ROOT/ROUTER_FILE,core.ROOT/STAGING_FILE]
        for f in files:old_files[str(f)]=f.read_bytes() if f.exists() else None
        new_unit_names=[f'dns-unified-multi@{e}.service' for e in engines if e!='cotten']
        try:
            if mode=='multi':
                config={'schema':'duc.multi.router.v1','listen':p['listen_ip'],'routes':p['routes']}
                core.atomic_json(core.ROOT/ROUTER_FILE,config)
                core.atomic_json(core.ROOT/STAGING_FILE,{'schema':'duc.multi.staging.v1','engines':engines})
                load_config(core.ROOT/ROUTER_FILE)
            if old_router:check(run(['systemctl','stop',ROUTER_UNIT],25),'stop router')
            for e in old_multi:
                if e=='cotten' and old_cotten_cfg:check(run(['systemctl','stop',old_cotten_cfg['unit']],25),'stop CottenDNS')
                elif e!='cotten':check(run(['systemctl','stop',f'dns-unified-multi@{e}.service'],25),'stop '+e)
            for e in old_classic:check(run(['systemctl','stop',core.UNITS[e]],25),'stop exclusive '+e)
            if mode=='multi':
                conflict=tcp_or_udp_listen(p['listen_ip'],53)
                if conflict:raise RuntimeError('Public port 53 remains occupied: '+str(conflict))
                if 'cotten' in engines:
                    new_cotten,_=external_cotten()
                    if not new_cotten:raise RuntimeError('Cotten adapter missing during apply')
                    check(run(['systemctl','start',new_cotten['unit']],25),'start CottenDNS')
                    if not await_unit(new_cotten['unit']):raise RuntimeError('Cotten backend not active')
                    if not (await_listener('127.0.0.1',new_cotten['port'],'udp') and
                            await_listener('127.0.0.1',new_cotten['port'],'tcp')):
                        raise RuntimeError('Cotten backend TCP+UDP loopback listeners not verified')
                for unit in new_unit_names:
                    check(run(['systemctl','start',unit],25),'start '+unit)
                    if not await_unit(unit):raise RuntimeError('Unstable backend '+unit)
                for e in engines:
                    if e=='cotten':continue
                    port=ENGINE_PORTS[e]
                    if not await_listener('127.0.0.1',port):
                        raise RuntimeError(f'{e} is not listening on loopback port {port}')
                    code,live,_=full_run(['ss','-H','-lntu'],6)
                    if code or any(len(ln.split())>=5 and ln.split()[3] in (
                        '0.0.0.0:'+str(port),'*:'+str(port),'[::]:'+str(port))
                        for ln in live.splitlines()):
                        raise RuntimeError(f'{e} backend port {port} is exposed or cannot be inspected')
                check(run(['systemctl','start',ROUTER_UNIT],25),'start DNS Router')
                if not await_unit(ROUTER_UNIT):raise RuntimeError('Router failed to stay active')
                if not (await_listener(p['listen_ip'],53,'udp') and await_listener(p['listen_ip'],53,'tcp')):
                    raise RuntimeError('Router UDP+TCP port 53 listeners not verified')
            else:
                unit=core.UNITS[engines[0]]
                check(run(['systemctl','start',unit],25),'start Exclusive '+unit)
                if not await_unit(unit):raise RuntimeError('Exclusive engine failed health check')
            # Boot persistence: exactly the currently approved public mode survives reboot.
            for unit in managed_units:
                wanted=(mode=='multi' and unit in ([ROUTER_UNIT]+new_unit_names)) or (mode=='exclusive' and unit==core.UNITS[engines[0]])
                if old_cotten_cfg and unit==old_cotten_cfg['unit']:
                    wanted=(mode=='multi' and 'cotten' in engines)
                check(run(['systemctl','enable' if wanted else 'disable',unit],15),
                      ('enable ' if wanted else 'disable ')+unit)
            # Persist only once services and boot configuration passed health gates.
            new_state={'schema':'duc.multi.mode.v1','mode':mode,'engines':list(engines),
                       'listen_ip':p['listen_ip'] if mode=='multi' else None,'updated':int(time.time())}
            core.atomic_json(core.STATE/MODE_FILE,new_state)
            core.audit('multi-mode',old.get('engines',old_classic),list(engines),'local-health-ok')
            return {'ok':True,'stage':'local-health-ok','status':status(),'warning':'End-to-end client tunnel not verified; no DNS records changed'}
        except Exception as exc:
            # Bounded rollback to *previous* engine services; identity/keys unchanged.
            run(['systemctl','stop',ROUTER_UNIT],20)
            for e in ENGINE_ORDER:
                if e!='cotten':run(['systemctl','stop',f'dns-unified-multi@{e}.service'],20)
            if 'cotten' in engines:
                cfg,_=external_cotten()
                if cfg:run(['systemctl','stop',cfg['unit']],20)
            for e in engines:
                if e in core.UNITS:run(['systemctl','stop',core.UNITS[e]],20)
            for f in files:
                data=old_files[str(f)]
                if data is None:f.unlink(missing_ok=True)
                else:
                    f.parent.mkdir(parents=True,exist_ok=True)
                    f.write_bytes(data);f.chmod(0o600)
            if old_mode_bytes is None:old_mode_file.unlink(missing_ok=True)
            else:
                old_mode_file.parent.mkdir(parents=True,exist_ok=True)
                old_mode_file.write_bytes(old_mode_bytes);old_mode_file.chmod(0o600)
            for unit,enabled in before_enabled.items():
                run(['systemctl','enable' if enabled else 'disable',unit],15)
            for e in old_classic:run(['systemctl','start',core.UNITS[e]],25)
            for e in old_multi:
                if e=='cotten' and old_cotten_cfg:run(['systemctl','start',old_cotten_cfg['unit']],25)
                elif e!='cotten':run(['systemctl','start',f'dns-unified-multi@{e}.service'],25)
            if old_router:run(['systemctl','start',ROUTER_UNIT],25)
            core.audit('multi-mode',old.get('engines',old_classic),list(engines),'rollback:'+type(exc).__name__)
            return {'ok':False,'stage':'rollback','error':str(exc)[:350],
                    'restored_exclusive':[e for e in old_classic if core.is_active(e)],
                    'restored_multi':[e for e in old_multi if e=='cotten' or active(f'dns-unified-multi@{e}.service')],
                    'router_restored':not old_router or active(ROUTER_UNIT),
                    'warning':'Verify service health and public DNS through provider console; rollback is best-effort'}
