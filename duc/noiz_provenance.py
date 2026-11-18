"""Track the exact reviewed upstream source commit and ELF hash of NoizDNS.

This deliberately does not trust a random noizdns-server found on PATH.
An unknown/mismatched server must be rebuilt, with the running-engine guard.
"""
from __future__ import annotations
import hashlib
import json
import pathlib
import re
from . import core

REPOSITORY='anonvector/dnstt'


def marker_path():
    return core.STATE/'noizdns-server-build.json'


def digest(binary):
    h=hashlib.sha256()
    with pathlib.Path(binary).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):
            h.update(block)
    return h.hexdigest()


def save(binary, commit):
    if not isinstance(commit,str) or not re.fullmatch(r'[0-9a-f]{40}',commit):
        raise RuntimeError('Invalid NoizDNS source commit identifier')
    core.atomic_json(marker_path(),{'repository':REPOSITORY,
                                    'commit':commit,'sha256':digest(binary),
                                    'binary':str(binary)})


def check(binary):
    try:
        p=marker_path()
        if not p.is_file() or p.is_symlink():return False
        data=json.loads(p.read_text())
        return (data.get('repository')==REPOSITORY and
                re.fullmatch(r'[0-9a-f]{40}',data.get('commit','')) is not None and
                data.get('sha256')==digest(binary) and
                data.get('binary')==str(binary))
    except (OSError,ValueError,TypeError,AttributeError):return False
