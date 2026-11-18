"""Privileged, fixed-action jobs. No arbitrary commands, paths, URLs or shell input."""
from __future__ import annotations
import json, os, pathlib, re, subprocess, time, uuid
from . import core
from .catalog import ENGINES

# Soar is bootstrapped by install.sh/upgrade.sh. Keep server install actions
# for other engines, but do not duplicate Soar provisioning in the client UI.
INSTALLABLE = ('dnstt','iodine','dns2tcp','master','vaydns','slipstream')
BUILDABLE = ('dnstt','master','vaydns','slipstream','soar','noizdns')
ACTIONS = {'install-server': INSTALLABLE, 'build-client': BUILDABLE,
           'build-alternate': ('dnstt','noizdns','vaydns'),
           'install-dante': ('slipstream',),
           'setup-dante': ('dante',)}


def job_dir():
    d=core.STATE/'workflow-jobs';d.mkdir(parents=True,exist_ok=True)
    return d


def job_file(action,engine):
    if action not in ACTIONS or engine not in ACTIONS[action]: raise ValueError('unknown action or engine')
    return job_dir()/f'{action}-{engine}.json'


CLIENT_PACKAGE_SCHEMAS={'noizdns':'0.9.7'}
ALTERNATE_PACKAGE_SCHEMAS={e:'0.9.7' for e in ACTIONS['build-alternate']}

def info(action,engine):
    p=job_file(action,engine)
    if not p.exists():return {'state':'not-started','engine':engine,'action':action}
    try:
        data=json.loads(p.read_text())
        # Never return raw logs; journal may have upstream secrets.
        result={k:data[k] for k in ('action','engine','state','message','updated','job_id','unit','source_commit','artifact','sha256','package_schema','resolver','port') if k in data}
        if (result.get('state')=='succeeded' and
                (action=='build-client' and engine in CLIENT_PACKAGE_SCHEMAS and
                 result.get('package_schema')!=CLIENT_PACKAGE_SCHEMAS[engine] or
                 action=='build-alternate' and engine in ALTERNATE_PACKAGE_SCHEMAS and
                 result.get('package_schema')!=ALTERNATE_PACKAGE_SCHEMAS[engine])):
            result['state']='stale'
            result['message']='Client launcher is from an older release. Rebuild to enforce recursive DNS and port settings.'
        return result
    except (OSError,ValueError,TypeError):
        return {'state':'unknown','engine':engine,'action':action}


def artifact_path(engine):
    if engine not in BUILDABLE: raise ValueError('unsupported client')
    return core.STATE/'client-artifacts'/f'{engine}-linux-amd64.zip'


def alternate_artifact_path(engine):
    if engine not in ACTIONS['build-alternate']: raise ValueError('alternate client unavailable')
    return core.STATE/'client-artifacts'/f'{engine}-alternate-linux-amd64.zip'


def initiate(action,engine,settings=None):
    if action not in ACTIONS or engine not in ACTIONS[action]:
        raise ValueError('Operation not supported for this engine. Review manual installation guide.')
    if action in ('build-client','build-alternate'):
        from .client_catalog import build_settings
        params=build_settings(**(settings or {}))
    elif settings:
        raise ValueError('Build options are not valid for this action')
    else:
        params={}
    if action=='install-server' and core.is_active(engine):
        raise ValueError('Stop this engine using Exclusive Mode before replacing its binary.')
    with core.switch_lock():
        for a,values in ACTIONS.items():
            for e in values:
                old=info(a,e)
                if old.get('state') in ('queued','running'):
                    # If an interrupted transient unit has vanished, allow a new job.
                    unit=old.get('unit','')
                    check=core.run(['systemctl','show',unit,'--property=ActiveState','--value'],5) if unit else None
                    active=bool(check and getattr(check,'stdout','').strip() in ('active','activating','reloading'))
                    if active or old.get('updated',0)>time.time()-40:
                        raise ValueError(f'Another installation/build is running: {a}/{e}')
        jobid=uuid.uuid4().hex[:12]
        unit=f'duc-job-{jobid}'
        p=job_file(action,engine)
        core.atomic_json(p,{'action':action,'engine':engine,'state':'queued',
                            'job_id':jobid,'unit':unit,'message':'Queued with systemd', 'updated':time.time(),**params})
        # systemd-run creates an independent root transient service; unlike the agent,
        # it is permitted to install packages or binaries. Fixed argv only.
        command=['systemd-run','--quiet','--collect','--unit='+unit,
          '--property=CPUQuota=100%',
          '--property=MemoryAccounting=yes',
          '--setenv=PYTHONPATH=/opt/dns-unified-control',
          '/opt/dns-unified-control/.venv/bin/python','-m','duc.worker',action,engine,jobid]
        try:r=subprocess.run(command,text=True,capture_output=True,timeout=15,check=False)
        except (OSError,subprocess.TimeoutExpired) as ex:
            r=None;err=type(ex).__name__
        else:err=r.stderr.strip()[:250] if r.returncode else ''
        if r is None or r.returncode:
            core.atomic_json(p,{'action':action,'engine':engine,'state':'failed',
                                'job_id':jobid,'message':'Could not start transient systemd job: '+err,
                                'updated':time.time()})
            raise RuntimeError('systemd-run could not start the job: '+err)
        return info(action,engine)
