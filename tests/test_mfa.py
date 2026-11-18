import json
import os
import time

from fastapi.testclient import TestClient
from duc import mfa, web


def test_rfc6238_sha1_first_vector_and_clock_skew():
    secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    assert mfa.otp(secret, 1) == '287082'  # RFC 6238 at Unix time 59s, 6 digits
    assert mfa.matched_step(secret, '287082', now=59) == 1
    assert mfa.matched_step(secret, '287082', now=60) == 1
    assert mfa.matched_step(secret, '287082', now=59, after=1) is None
    assert mfa.matched_step(secret, 'abc123', now=59) is None
    assert mfa.matched_step(secret, '00000000', now=59) is None


def test_persistence_and_single_use_recovery(tmp_path):
    path = tmp_path / 'mfa.json'
    secret = mfa.new_secret()
    now = int(time.time())
    step = now // 30
    codes = mfa.generate_recovery_codes()
    mfa.activate(path, secret, step-3, codes)
    assert oct(path.stat().st_mode & 0o777) == '0o600'
    assert codes[0] not in path.read_text()
    assert mfa.use_code(path, mfa.otp(secret, step)) == 'totp'
    assert mfa.use_code(path, mfa.otp(secret, step)) is None
    assert mfa.use_code(path, codes[0]) == 'recovery'
    assert mfa.use_code(path, codes[0]) is None
    assert mfa.recovery_count(path) == 9
    assert mfa.use_code(path, codes[1].replace('-', '')) == 'recovery'
    assert mfa.recovery_count(path) == 8
    assert mfa.rotate_recovery(path, mfa.otp(secret, step)) is None
    try:
        mfa.activate(path, secret, step, codes)
        assert False, 'Overwriting MFA should fail'
    except ValueError:
        pass


def test_web_mfa_end_to_end(tmp_path, monkeypatch):
    pw = 'this-is-a-long-test-password'
    salt = os.urandom(16)
    auth_file = tmp_path / 'web-auth.json'
    auth_file.write_text(json.dumps({
        'salt': salt.hex(),
        'hash': __import__('hashlib').pbkdf2_hmac('sha256', pw.encode(), salt, 600000).hex(),
    }))
    mfa_file = tmp_path / 'mfa.json'
    monkeypatch.setattr(web, 'AUTH_PATH', auth_file)
    monkeypatch.setattr(web, 'MFA_PATH', mfa_file)
    web.SESSIONS.clear()
    web.ATTEMPTS.clear()

    async def mock_agent(method, path, data=None):
        return {'ok': True, 'path': path, 'data': data}
    monkeypatch.setattr(web, 'agent_request', mock_agent)

    with TestClient(web.app) as client:
        assert client.get('/api/status').status_code == 401
        assert client.get('/api/mfa/qr').status_code == 401
        assert client.post('/api/mfa/setup').status_code == 401
        bad = client.post('/api/login', json={'password': 'wrong'})
        assert bad.status_code == 401
        r = client.post('/api/login', json={'password': pw})
        assert r.status_code == 200 and r.json()['stage'] == 'enroll'
        csrf = r.json()['csrf']
        assert client.get('/api/status').status_code == 401
        assert client.get('/api/session').json()['logged_in'] is False
        assert client.post('/api/mfa/setup').status_code == 403
        header = {'X-CSRF-Token': csrf}
        setup = client.post('/api/mfa/setup', headers=header).json()
        assert setup['secret'] in setup['otpauth_uri']
        assert client.get('/api/mfa/qr').headers['content-type'].startswith('image/svg+xml')
        code = mfa.otp(setup['secret'], int(time.time()) // 30)
        assert client.post('/api/mfa/activate', headers=header, json={'code': 'nonsense'}).status_code == 401
        ok = client.post('/api/mfa/activate', headers=header, json={'code': code})
        assert ok.status_code == 200 and ok.json()['logged_in']
        assert len(ok.json()['recovery_codes']) == 10
        codes = ok.json()['recovery_codes']
        assert client.post('/api/mfa/setup', headers=header).status_code == 401
        assert client.get('/api/status').status_code == 200
        assert client.get('/api/mfa/status').json()['recovery_codes_remaining'] == 10
        assert client.post('/api/switch', headers=header, json={'engine': 'master'}).status_code == 403
        fresh_csrf = ok.json()['csrf']
        assert client.post('/api/switch', headers={'X-CSRF-Token': fresh_csrf}, json={'engine': 'master'}).status_code == 200
        assert client.post('/api/logout', headers={'X-CSRF-Token': fresh_csrf}).status_code == 200
        assert client.get('/api/status').status_code == 401

        r = client.post('/api/login', json={'password': pw})
        assert r.json()['stage'] == 'challenge'
        assert client.get('/api/status').status_code == 401
        header2 = {'X-CSRF-Token': r.json()['csrf']}
        # Replay of enrollment TOTP must fail even after new password login.
        assert client.post('/api/mfa/verify', headers=header2, json={'code': code}).status_code == 401
        r2 = client.post('/api/mfa/verify', headers=header2, json={'code': codes[0]})
        assert r2.status_code == 200 and r2.json()['used_recovery']
        assert client.get('/api/mfa/status').json()['recovery_codes_remaining'] == 9
        c3 = r2.json()['csrf']
        assert client.post('/api/logout', headers={'X-CSRF-Token': c3}).status_code == 200
        r3 = client.post('/api/login', json={'password': pw})
        assert client.post('/api/mfa/verify', headers={'X-CSRF-Token': r3.json()['csrf']}, json={'code': codes[0]}).status_code == 401
        # An independent, unused recovery code works.
        r4 = client.post('/api/mfa/verify', headers={'X-CSRF-Token': r3.json()['csrf']}, json={'code': codes[1]})
        assert r4.status_code == 200


def test_web_expired_session_denied(tmp_path, monkeypatch):
    p = tmp_path / 'mfa.json'
    mfa.activate(p, mfa.new_secret(), -1, mfa.generate_recovery_codes())
    monkeypatch.setattr(web, 'MFA_PATH', p)
    web.SESSIONS.clear()
    with TestClient(web.app) as client:
        data = web._create_session(type('R', (), {'set_cookie': lambda *args, **kwargs: None})(), 'full', True)
        sid = next(iter(web.SESSIONS))
        client.cookies.set('duc_session', sid)
        web.SESSIONS[sid]['last'] = time.time() - web.IDLE_MAX - 1
        assert client.get('/api/status').status_code == 401


def test_recovery_rotation_revokes_old_codes(tmp_path, monkeypatch):
    path = tmp_path / 'mfa.json'
    secret = mfa.new_secret()
    step = 1234567
    previous = mfa.generate_recovery_codes()
    mfa.activate(path, secret, step-1, previous)
    # Freeze time two steps after the enrollment TOTP to demand a fresh OTP.
    monkeypatch.setattr(mfa.time, 'time', lambda: (step+2)*30+5)
    old_gen = mfa.generation(path)
    replacement = mfa.rotate_recovery(path, mfa.otp(secret, step+2))
    assert mfa.generation(path) != old_gen
    assert len(replacement) == 10
    assert mfa.use_code(path, previous[0]) is None
    assert mfa.use_code(path, replacement[0]) == 'recovery'
    assert mfa.recovery_count(path) == 9


def test_account_level_rate_limits_and_mfa_only_route_access(tmp_path, monkeypatch):
    path = tmp_path / 'mfa.json'
    mfa.activate(path, mfa.new_secret(), -1, mfa.generate_recovery_codes())
    monkeypatch.setattr(web, 'MFA_PATH', path)
    web.SESSIONS.clear()
    web.ATTEMPTS.clear()
    with TestClient(web.app) as client:
        # Even a synthetically created, pre-MFA full session must not pass the guard.
        sid = 'unverified-full-session'
        web.SESSIONS[sid] = {'csrf': 'csrf', 'exp': time.time()+3600,
                             'last': time.time(), 'stage': 'full', 'mfa_checked': False}
        client.cookies.set('duc_session', sid)
        assert client.get('/api/status').status_code == 401
        assert client.get('/api/metrics').status_code == 401
        assert client.get('/api/dns/plan').status_code == 401
        assert client.post('/api/switch', headers={'X-CSRF-Token':'csrf'},
                           json={'engine':'master'}).status_code == 401
        web.ATTEMPTS['mfa:account'] = [time.time()] * 12
        try:
            web._rate('mfa:account', max_attempts=12)
            assert False
        except __import__('fastapi').HTTPException as e:
            assert e.status_code == 429
