"""Passive DNS delegation diagnostics. Does not create records or start tunnels.

Checks recursive visibility, *not* client reachability or authenticated tunneling.
"""
from __future__ import annotations
import concurrent.futures
import ipaddress
import shutil
import subprocess
from .catalog import ENGINES, LABELS

RESOLVERS = ('1.1.1.1', '8.8.8.8')


def expected_ns(engine: str, hostname: str) -> str:
    """Return ns.<zone> only if engine owns its configured subdomain label."""
    host = hostname.strip().rstrip('.').lower()
    parts = host.split('.')
    if engine not in LABELS or len(parts) < 3 or parts[0] != LABELS[engine]:
        raise ValueError('Configured hostname does not match the engine label')
    return 'ns.' + '.'.join(parts[1:])


def dig(rtype: str, host: str, resolver: str, *, runner=subprocess.run) -> list[str]:
    if rtype not in ('NS', 'A') or resolver not in RESOLVERS:
        raise ValueError('Unsupported DNS diagnostic')
    try:
        result = runner(['dig', '@'+resolver, '+time=2', '+tries=1', '+short', rtype, host],
                        text=True, capture_output=True, timeout=3.5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode:
        return []
    return [r.strip().rstrip('.').lower() for r in result.stdout.splitlines() if r.strip()]


def parent_delegation(hostname: str, target: str, nameserver: str, *, runner=subprocess.run) -> bool:
    """Read delegation from the authoritative *parent* zone.

    Recursive NS lookups for a child whose own server is offline may SERVFAIL,
    which is expected in Exclusive Mode and is NOT proof that the NS is missing.
    """
    try:
        result = runner(['dig', '@'+nameserver, '+norecurse', '+time=2',
                         '+tries=1', '+noall', '+authority', 'NS', hostname],
                        text=True, capture_output=True, timeout=3.5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode:
        return False
    for line in result.stdout.splitlines():
        parts = line.lower().split()
        if (len(parts) >= 5 and parts[0].rstrip('.') == hostname.lower().rstrip('.')
                and parts[-2].upper() == 'NS' and parts[-1].rstrip('.') == target.lower()):
            return True
    return False


def check_one(engine: str, domain: str) -> dict:
    result = {'engine': engine, 'domain': domain, 'delegated': False,
              'resolvers': {}, 'target': '', 'note': ''}
    try:
        target = expected_ns(engine, domain)
        result['target'] = target
    except ValueError as exc:
        result['note'] = str(exc)
        return result
    if not shutil.which('dig'):
        result['note'] = 'dig not installed; install bind9-dnsutils'
        return result
    zone = domain.split('.',1)[1]
    for resolver in RESOLVERS:
        parent_ns = dig('NS', zone, resolver)
        # The parent delegation is visible even when the child server is OFF.
        delegation = any(parent_delegation(domain, target, server)
                         for server in parent_ns[:2])
        addresses = dig('A', target, resolver)
        public = []
        for address in addresses:
            try:
                if ipaddress.IPv4Address(address).is_global:
                    public.append(address)
            except ipaddress.AddressValueError:
                pass
        result['resolvers'][resolver] = {'parent_ns': parent_ns,
                'a': addresses, 'matches': delegation and bool(public)}
    result['delegated'] = all(v['matches'] for v in result['resolvers'].values())
    if not result['delegated']:
        result['note'] = 'Check authoritative parent delegation, A DNS-only, propagation and resolver filtering'
    return result

def check_all(profiles: dict) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
        jobs = {engine: pool.submit(check_one, engine, profiles[engine]['domain']) for engine in ENGINES}
        results = [jobs[e].result() for e in ENGINES]
    return {'checks': results, 'verified': sum(bool(i['delegated']) for i in results),
            'total': len(results), 'scope': 'recursive DNS visibility only; NOT client-to-VPS connectivity'}
