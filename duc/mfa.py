"""RFC 6238 TOTP and single-use recovery codes for the administrative web app.

Secrets are stored with filesystem permissions, NOT encrypted at rest. Protect
server backups and /var/lib/dns-unified/mfa. No third-party OTP service is used.
"""
import base64
import fcntl
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import tempfile
import time
from contextlib import contextmanager
from urllib.parse import quote, urlencode

DEFAULT_PATH = pathlib.Path('/var/lib/dns-unified/mfa/web-mfa.json')
STEP_SECONDS = 30


def new_secret():
    # RFC 6238, 160 bits for HMAC-SHA1
    return base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')


def provisioning_uri(secret, account='admin'):
    issuer = 'DNS Unified Control'
    label = quote(issuer + ':' + account, safe='')
    return ('otpauth://totp/' + label + '?' + urlencode({
        'secret': secret, 'issuer': issuer, 'algorithm': 'SHA1',
        'digits': '6', 'period': str(STEP_SECONDS),
    }))


def otp(secret, counter):
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, int(counter).to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = mac[-1] & 0x0f
    number = (int.from_bytes(mac[offset:offset+4], 'big') & 0x7fffffff) % 1000000
    return f'{number:06d}'


def matched_step(secret, code, now=None, after=-1):
    if not isinstance(code, str) or re.fullmatch(r'[0-9]{6}', code) is None:
        return None
    tick = int((time.time() if now is None else now) // STEP_SECONDS)
    # +/- 1 allows modest clock skew. Reuse of an accepted step is rejected.
    for step in (tick, tick-1, tick+1):
        if step < 0 or step <= after:
            continue
        if hmac.compare_digest(otp(secret, step), code):
            return step
    return None


def generate_recovery_codes(count=10):
    return ['-'.join([s[i:i+4] for i in range(0, 20, 4)])
            for s in (secrets.token_hex(10).upper() for _ in range(count))]


def normalize_recovery(code):
    if not isinstance(code, str):
        return ''
    result = code.replace('-', '').replace(' ', '').upper()
    return result if re.fullmatch(r'[0-9A-F]{20}', result) else ''


def digest_recovery(code, salt):
    normalized = normalize_recovery(code)
    if not normalized:
        return None
    return hashlib.sha256(bytes.fromhex(salt) + normalized.encode('ascii')).hexdigest()


def make_config(secret, first_step, codes):
    salt = secrets.token_hex(16)
    return {'version': 1, 'generation': secrets.token_hex(16), 'secret': secret, 'last_step': int(first_step),
            'recovery_salt': salt, 'recovery_hashes': [digest_recovery(c, salt) for c in codes]}


def _save(path, data):
    path = pathlib.Path(path)
    # A temp file in the same directory makes replacement atomic.
    fd, tmp = tempfile.mkstemp(prefix='.mfa-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            json.dump(data, file, separators=(',', ':'))
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextmanager
def locked(path):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lockfile = path.parent / '.mfa.lock'
    fd = os.open(str(lockfile), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(fd, 'r+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
    finally:
        pass


def configured(path):
    return pathlib.Path(path).exists()


def activate(path, secret, first_step, codes):
    """Create once, never overwrite an existing MFA config from web enrollment."""
    with locked(path):
        if configured(path):
            raise ValueError('MFA already enabled')
        _save(path, make_config(secret, first_step, codes))


def generation(path):
    return json.loads(pathlib.Path(path).read_text(encoding='utf-8'))['generation']


def use_code(path, code):
    """Consume a TOTP step or recovery code exactly once, across processes."""
    with locked(path):
        data = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
        step = matched_step(data['secret'], code, after=data.get('last_step', -1))
        if step is not None:
            data['last_step'] = step
            _save(path, data)
            return 'totp'
        digest = digest_recovery(code, data['recovery_salt'])
        if digest:
            for i, item in enumerate(data['recovery_hashes']):
                if hmac.compare_digest(item, digest):
                    del data['recovery_hashes'][i]
                    _save(path, data)
                    return 'recovery'
        return None


def rotate_recovery(path, totp_code):
    with locked(path):
        data = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
        step = matched_step(data['secret'], totp_code, after=data.get('last_step', -1))
        if step is None:
            return None
        codes = generate_recovery_codes()
        data['last_step'] = step
        data['generation'] = secrets.token_hex(16)
        data['recovery_salt'] = secrets.token_hex(16)
        data['recovery_hashes'] = [digest_recovery(c, data['recovery_salt']) for c in codes]
        _save(path, data)
        return codes


def recovery_count(path):
    data = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
    return len(data.get('recovery_hashes', []))
