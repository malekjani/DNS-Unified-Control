"""Read-only field audit. Does NOT switch, install, benchmark or restart engines."""
from __future__ import annotations
import json, os, shutil, subprocess, time
from . import core, dante, telemetry


def binary_help(name, *flags):
    path=shutil.which(name)
    if not path:return {'present':False,'cli_observed':False}
    try:
        result=subprocess.run([path,*flags],capture_output=True,text=True,timeout=4,check=False)
        return {'present':True,'cli_observed':bool(result.stdout or result.stderr),
                'exit_code':result.returncode,
                'sample':(result.stdout+'\n'+result.stderr).strip()[:400]}
    except (OSError, subprocess.TimeoutExpired):return {'present':True,'cli_observed':False}


def run_check():
    active=core.list_active()
    t=telemetry.snapshot()['latest']
    checks={}
    for e in core.ENGINES:
        p=core.profiles()[e]
        ready=core.check_ready(e,p)
        tools={
            'dnstt':('dnstt-server','-h'),
            'vaydns':('vaydns-server','-h'),
            'dns2tcp':('dns2tcpd','-h'),
            'soar':('duc-soar-server','-help'),
            'noizdns':('noizdns-server','-help'),
            'xdns':('xray','version'),
        }
        helper=binary_help(*tools[e]) if e in tools else {'present':bool(ready['binary'])}
        record=t.get(e)
        checks[e]={
            'systemd_active':e in active,
            'preflight_ready':ready['ready'],
            'preflight_issues':ready['issues'],
            'binary':ready['binary'],
            'binary_inspection':helper,
            'backend_target':p.get('target'),
            'real_client_probe':('passed' if record and record.get('successful',0)>0 else
                                 'failed' if record else 'not-recorded'),
            'real_probe_timestamp':record.get('timestamp') if record else None,
            'notes':{'dnstt':'When selecting Dante, rebuild/launch the actual client on local port 2080 and run SOCKS probe.',
                     'vaydns':'Client/server record types and keepalive must match.',
                     'dns2tcp':'Do not forward raw Dante: the DNS traffic is unencrypted. Verify through SSH only.',
                     'soar':'Restricted Soar-only binary; public destinations denied; default is shared authenticated Dante.',
                     'noizdns':'Native SlipNet NoizDNS Stealth client packaging is available; server installed at upgrade, real SOCKS5+Dante field test pending.',
                     'xdns':'Requires Xray FinalMask xdns/mKCP config and xray run -test, not just a few form fields.',
                     'iodine':'Tune from client with independent ICMP/IP-level diagnostics, not SOCKS.',
                     }.get(e,'')}
    return {'version':'0.9.8','time':time.time(), 'active':active,
            'exclusive_healthy':len(active)<=1,'dante':dante.status(),
            'engines':checks,'changes_performed':False}


def main():
    print(json.dumps(run_check(),ensure_ascii=False,indent=2))

if __name__=='__main__':main()
