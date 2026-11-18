"""Read-only operational summary consumed by the privileged Agent and all UIs.

Readiness != end-to-end connectivity. No private keys, passwords or raw journal
lines are returned. Avoid mutation, engine activation and network probes here.
"""
from __future__ import annotations
from . import core, dante, jobs, client_catalog


def assemble(*, active: list[str], dante_state: dict, checks: dict, job_states: dict) -> dict:
    """Pure serializer, allowing read-only tests without systemctl or root."""
    entries = {}
    for engine in core.ENGINES:
        ready = checks[engine]
        builds = job_states.get(engine, {})
        entries[engine] = {
            'active': engine in active,
            'server_ready': bool(ready.get('ready', False)),
            'preflight_issues': list(ready.get('issues', [])),
            'clients': [
                {'id': c['id'], 'kind': c['kind'], 'field_tested': bool(c['tested']),
                 'build_state': builds.get('build-client' if c['kind'] == 'native'
                                           else 'build-alternate', 'not-supported')}
                for c in client_catalog.options(engine)['choices']
            ],
        }
    return {
        'schema': 1,
        'exclusive_healthy': len(active) <= 1,
        'active': list(active),
        'dante': {
            'ready': bool(dante_state.get('ready')),
            'running': bool(dante_state.get('running')),
            'auth_verified': bool(dante_state.get('auth_verified')),
            'bind': dante_state.get('bind', '127.0.0.1:1080'),
        },
        'engines': entries,
        'evidence_policy': {
            'server_ready': 'Local installation/configuration preflight only',
            'field_tested': 'Historical manual field test for the specified client variant; not a live check',
            'build_state': 'Artifact job state only; not an end-to-end tunnel test',
            'active': 'systemd state only; not an end-to-end tunnel test',
        },
    }


def snapshot() -> dict:
    active = core.list_active()
    ds = dante.status()
    profiles = core.profiles()
    checks = {engine: core.check_ready(engine, profiles[engine]) for engine in core.ENGINES}
    states = {}
    for engine in core.ENGINES:
        states[engine] = {}
        for action in ('build-client', 'build-alternate'):
            if engine in jobs.ACTIONS.get(action, ()):
                states[engine][action] = jobs.info(action, engine)['state']
    data = assemble(active=active, dante_state=ds, checks=checks, job_states=states)
    from . import instance
    try:
        configured = instance.load()
        data['instance'] = {key: configured[key] for key in
                            ('instance_id', 'domain', 'public_ipv4', 'panel_fqdn', 'nameserver_fqdn')}
    except instance.InstanceError:
        data['instance'] = None  # Existing pre-0.10.0 deployment; not a fresh instance.
    return data
