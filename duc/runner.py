"""systemd launch wrapper. argv is constructed from audited fixed templates only."""
import json, os, pathlib, re, shutil, sys
from .core import ROOT, ENGINES, BINARIES, profiles, validate

def replace_keys(text, changes):
    # Preserve unmodified upstream TOML options and comments. Exactly one occurrence per key.
    for key,value in changes.items():
        line=re.compile(r'(?m)^'+re.escape(key)+r'\s*=.*$')
        if not line.search(text): raise ValueError(f'Upstream config missing {key}')
        if len(line.findall(text))!=1: raise ValueError(f'Upstream config has duplicate {key}')
        text=line.sub(lambda m:key+' = '+json.dumps(value),text)
    return text

def write_secure(path, body):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.tmp')
    with open(tmp,'w') as f: f.write(body);f.flush();os.fsync(f.fileno())
    os.chmod(tmp,0o600);os.replace(tmp,path)

def cmd_for(engine, conf=None):
    if engine not in ENGINES: raise ValueError('invalid engine')
    conf=conf or profiles()[engine]
    for k,v in conf.items(): validate(k,v)
    binary=shutil.which(BINARIES[engine])
    if not binary: raise ValueError('binary not found: '+BINARIES[engine])
    domain=conf['domain'];port=str(conf['udp_port'])
    if engine=='master':
        p=ROOT/'engines/master/base.toml'
        template=p.read_text()
        rendered=replace_keys(template,{'DOMAIN':[domain],'UDP_PORT':int(port),'UDP_HOST':'',
                'ARQ_WINDOW_SIZE':conf['arq_window'],'LOG_LEVEL':conf['log_level'],
                'DATA_ENCRYPTION_METHOD':conf['encryption_method'],
                'ENCRYPTION_KEY_FILE':str(ROOT/'keys/master.key')})
        out=ROOT/'engines/master/server_config.toml';write_secure(out,rendered)
        return [binary,'-config',str(out)]
    if engine=='slipstream':
        # Mygod/slipstream-rust server CLI, not the older C implementation.
        return [binary,
            '--domain',domain,'--dns-listen-host',conf['dns_listen_host'],
            '--dns-listen-port',port,'--target-address',conf['target'],
            '--cert',str(ROOT/'keys/slipstream-rust.crt'),
            '--key',str(ROOT/'keys/slipstream-rust.key'),
            '--reset-seed',str(ROOT/'keys/slipstream-rust.reset-seed'),
            '--max-connections',str(conf['max_connections']),
            '--idle-timeout-seconds',str(conf['idle_timeout_seconds'])]
    if engine=='dnstt':
        return [binary,'-udp',':'+port,'-privkey-file',str(ROOT/'keys/dnstt.key'),domain,conf['target']]
    if engine=='noizdns':
        # NoizDNS fork CLI differs across distributions: the binary must accept
        # DNSTT-compatible -udp command. If not, use an audited wrapper or replace.
        return [binary,'-udp',':'+port,'-privkey-file',str(ROOT/'keys/noizdns.key'),domain,conf['target']]
    if engine=='vaydns':
        args=[binary,'-udp',':'+port,'-privkey-file',str(ROOT/'keys/vaydns.key'),
              '-domain',domain,'-upstream',conf['target'],'-mtu',str(conf['mtu']),
              '-queue-size',str(conf['queue_size']),'-record-type',conf['record_type']]
        if conf['dnstt_compat']:
            # Let upstream apply its *different* compatibility defaults (2m/10s)
            # unless the admin explicitly customized these fields.
            args.append('-dnstt-compat')
        defaults={'vay_idle_timeout':10,'vay_keepalive':2,'vay_kcp_window':0,
                  'vay_queue_overflow':'drop','vay_log_level':'info'}
        params={'vay_idle_timeout':('-idle-timeout',lambda x:str(x)+'s'),
                'vay_keepalive':('-keepalive',lambda x:str(x)+'s'),
                'vay_kcp_window':('-kcp-window-size',str),
                'vay_queue_overflow':('-queue-overflow',str),
                'vay_log_level':('-log-level',str)}
        for key,(flag,formatter) in params.items():
            if conf[key]!=defaults[key]:args.extend([flag,formatter(conf[key])])
        return args
    if engine=='soar':
        if conf.get('target')!='127.0.0.1:1080':
            raise ValueError('Restricted Soar only supports shared Dante 127.0.0.1:1080')
        return [binary,'-zone',domain,'-key-file',str(ROOT/'keys/soar.key'),
                '-listen',':'+port,'-backend','127.0.0.1:1080']
    if engine=='xdns':
        return [binary,'run','-c',str(ROOT/'engines/xdns/server.json')]
    if engine=='iodine':
        # Password is read from root-owned file; iodined requires -P in noninteractive mode.
        # Its password may be visible in process args to privileged local users.
        password=(ROOT/'keys/iodine.pass').read_text().strip()
        if not password or len(password)>32: raise ValueError('iodine password must be 1..32 chars')
        return [binary,'-f','-c','-p',port,'-P',password,conf['tunnel_ip'],domain]
    if engine=='dns2tcp':
        key=(ROOT/'keys/dns2tcp.key').read_text().strip()
        if not key or any(ch in key for ch in '\n\r'): raise ValueError('bad dns2tcp key')
        host,pt=conf['target'].rsplit(':',1)
        cfg=f'listen = 0.0.0.0\nport = {port}\nuser = nobody\nkey = {key}\ndomain = {domain}\nresources = {conf["resource"]}:{host}:{pt}\n'
        out=ROOT/'engines/dns2tcp/server.conf';write_secure(out,cfg)
        return [binary,'-F','-f',str(out)]
    raise ValueError('unsupported engine')

def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ENGINES:
        print('Usage: python -m duc.runner {engine-id}',file=sys.stderr);sys.exit(2)
    engine=sys.argv[1]
    try: cmd=cmd_for(engine)
    except Exception as exc: print('Startup preflight:',exc,file=sys.stderr);sys.exit(1)
    # Replace process, preserving systemd PID tracking; never invoke shell.
    os.execv(cmd[0],cmd)
if __name__=='__main__':main()
