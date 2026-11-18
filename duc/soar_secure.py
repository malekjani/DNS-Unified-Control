"""Restricted Soar mode: single authenticated Dante target, no public destination dial."""
from __future__ import annotations
import base64
import os
import pathlib
import re
import subprocess
from . import core

TARGET='127.0.0.1:1080'
BINARY='duc-soar-server'


def public_key():
    path=core.ROOT/'keys/soar.pub'
    if not path.is_file(): return None
    try:
        value=path.read_text('ascii').strip()
        if len(base64.b64decode(value,validate=True))!=32: return None
        return value
    except (OSError,ValueError,UnicodeError): return None


def ensure_keys():
    directory=core.ROOT/'keys';directory.mkdir(parents=True,exist_ok=True)
    private=directory/'soar.key';public=directory/'soar.pub'
    if private.exists():
        seed=private.read_text('ascii').strip()
        if len(base64.b64decode(seed,validate=True))!=32:
            raise RuntimeError('Existing Soar key is invalid; refusing to overwrite it')
        if private.stat().st_mode & 0o077: private.chmod(0o600)
    else:
        if public.exists(): raise RuntimeError('Public key exists but private key is missing; refusing to replace identity')
        result=subprocess.run(['/usr/local/bin/'+BINARY,'keygen'],capture_output=True,text=True,timeout=15,check=True)
        match=re.search(r'^private ([A-Za-z0-9+/]{43}=)\s*$',result.stdout,re.M)
        if not match:raise RuntimeError('Unexpected output from Soar key generator')
        seed=match.group(1)
        if len(base64.b64decode(seed,validate=True))!=32:raise RuntimeError('Invalid generated Soar seed')
        fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:f.write(seed+'\n');f.flush();os.fsync(f.fileno())
    # Derive the public key from the actual private key, never trust a stale pub file.
    result=subprocess.run(['/usr/local/bin/'+BINARY,'pubkey',str(private)],capture_output=True,text=True,timeout=15,check=True)
    derived=result.stdout.strip()
    if len(base64.b64decode(derived,validate=True))!=32:raise RuntimeError('Invalid Soar public key')
    if public.exists() and public.read_text('ascii').strip()!=derived:
        raise RuntimeError('Existing public key mismatches private key; manual review required')
    if not public.exists():
        fd=os.open(public,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'w') as f:f.write(derived+'\n');f.flush();os.fsync(f.fileno())
    return {'public_key_ready':True,'private_key_preserved':True}


def status():
    from . import dante
    c=core.profiles()['soar']
    private=core.ROOT/'keys/soar.key'
    target=c.get('target',TARGET)
    return {'mode':'restricted-dante-only','domain':c['domain'],'target':target,
        'public_key':public_key(),'private_key_present':private.is_file(),
        'dante_ready':dante.status()['ready'],'preflight':core.check_ready('soar',c),
        'active_dns':core.list_active(), 'client_gateway_required':False,
        'security':'Refuses every destination except 127.0.0.1:1080; Dante authenticates user.'}
