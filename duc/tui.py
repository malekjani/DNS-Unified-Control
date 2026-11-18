"""DNS Unified Control local TUI / CLI.

The TUI uses the exact privileged Agent HTTP contract over its LOCAL Unix
socket. No extra daemon, public port, embedded secrets or shell execution.
Root or explicitly authorized dns-unified group membership is required.
"""
from __future__ import annotations
import argparse
import http.client
import json
import os
import socket
import sys
from typing import Any
from .confirm import ask_yes_no

DEFAULT_SOCKET = '/run/dns-unified-agent.sock'
MAX_RESPONSE = 1_000_000


class AgentFailure(RuntimeError):
    pass


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, uds_path: str, timeout: float = 20):
        super().__init__('localhost', timeout=timeout)
        self.uds_path = uds_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.uds_path)
        except BaseException:
            s.close()
            raise
        self.sock = s


class Agent:
    def __init__(self, uds_path: str = DEFAULT_SOCKET):
        self.uds_path = uds_path

    def call(self, method: str, path: str, payload: dict | None = None) -> dict:
        if method not in ('GET', 'POST') or not path.startswith('/') or '://' in path:
            raise ValueError('Only local fixed Agent HTTP routes are supported')
        conn = UnixHTTPConnection(self.uds_path)
        raw = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
        try:
            conn.request(method, path, body=raw,
                         headers={'Accept': 'application/json',
                                  'Content-Type': 'application/json'} if raw is not None else
                                 {'Accept': 'application/json'})
            response = conn.getresponse()
            content = response.read(MAX_RESPONSE + 1)
            if len(content) > MAX_RESPONSE:
                raise AgentFailure('Agent response exceeded safety limit')
            try:
                data = json.loads(content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise AgentFailure('Agent returned invalid JSON')
            if response.status >= 400:
                # No raw server journal/credentials; short error only.
                detail = data.get('detail', data) if isinstance(data, dict) else 'Error'
                raise AgentFailure(f'Agent HTTP {response.status}: {str(detail)[:350]}')
            if not isinstance(data, dict):
                raise AgentFailure('Unexpected Agent response format')
            return data
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            raise AgentFailure('Cannot access local Agent socket. Check systemctl status '
                               'dns-unified-agent.socket and run as root / authorized group. '
                               f'({type(exc).__name__})') from None
        finally:
            conn.close()

    def get(self, path: str):
        return self.call('GET', path)

    def post(self, path: str, data: dict):
        return self.call('POST', path, data)


def _print_readiness(data: dict):
    active = ', '.join(data.get('active', [])) or 'none'
    inst=data.get('instance') or {}
    if inst:
        print(f"Instance: {inst.get('domain')} | Public IPv4: {inst.get('public_ipv4')} | ID: {inst.get('instance_id')}")
    else:
        print('Instance: legacy/unregistered installation')
    print(f"Exclusive: {'HEALTHY' if data.get('exclusive_healthy') else 'CONFLICT'} | Active DNS: {active}")
    d = data.get('dante', {})
    print(f"Dante: {'READY' if d.get('ready') else 'NOT READY'} | Auth: "
          f"{'verified' if d.get('auth_verified') else 'not verified'} | {d.get('bind', 'unknown')}")
    print('Engine          Server       Running      Client variants (package state)')
    print('-' * 81)
    for engine, item in data.get('engines', {}).items():
        variants = ', '.join(f"{c['id']}:{c['build_state']}" for c in item.get('clients', []))
        print(f"{engine:<15} {'READY' if item['server_ready'] else 'REVIEW':<12} "
              f"{'ACTIVE' if item['active'] else 'stopped':<12} {variants}")
    print('NOTE: These are local states, not live end-to-end connectivity results.')


def _print_client_options(data: dict):
    print(f"Engine: {data.get('engine')} | Default: {data.get('default')}")
    for choice in data.get('choices', []):
        print(f"  {choice['id']:<12} {choice['kind']:<10} "
              f"{'field-tested' if choice.get('tested') else 'NOT field-tested'}")
        print('    ' + choice.get('note', ''))
    print('Selecting a client does NOT switch/start the server DNS engine.')


def _confirm(action: str, input_fn=input, output=print):
    if input_fn is input and not sys.stdin.isatty():
        output('Interactive TTY is required for write operations. Cancelled.')
        return False
    if action.startswith('BUILD '):
        output('Build starts a package Job only; it does not start or switch any DNS engine.')
    else:
        output('WARNING: A running DNS tunnel may drop existing client connections and SSH sessions.')
        output('Use a separate SSH/console connection. No automatic client migration occurs.')
    output(f'Action requested: {action}')
    return ask_yes_no('Proceed with this action?', input_fn=input_fn, output=output)


def _switch(api: Agent, engine: str, restart: bool = False, confirm_fn=_confirm):
    preview = api.get('/workflow/readiness')
    if engine != 'none' and engine not in preview.get('engines', {}):
        raise ValueError('Unknown DNS engine')
    if not preview.get('exclusive_healthy') and engine != 'none':
        raise AgentFailure('Exclusive Mode conflict exists; only STOP DNS is allowed until it is repaired')
    if engine != 'none' and not preview['engines'][engine]['server_ready']:
        issues = '; '.join(preview['engines'][engine]['preflight_issues'])
        raise AgentFailure('Target preflight not ready: ' + issues[:350])
    phrase = ('STOP DNS' if engine == 'none' else
              ('RESTART ' if restart else 'SWITCH ') + engine)
    if not confirm_fn(phrase):
        print('Cancelled. No changes.')
        return {'ok': False, 'stage': 'cancelled'}
    return api.post('/switch', {'engine': engine, 'restart': restart})


def _build(api: Agent, engine: str, client_id: str, resolver: str, port: int,
           confirm_fn=_confirm):
    options = api.get('/workflow/client/options/' + engine)
    variants = {c['id']: c for c in options['choices']}
    if client_id not in variants:
        raise ValueError('Client variant not available for this engine')
    kind = variants[client_id]['kind']
    action = 'build-client' if kind == 'native' else 'build-alternate'
    if not confirm_fn('BUILD ' + engine + ' ' + client_id):
        print('Cancelled. No changes.')
        return {'state': 'cancelled'}
    # Agent does canonical resolver / port validation, same as Web.
    return api.post(f'/workflow/jobs/{action}/{engine}',
                    {'confirm': f'{action}:{engine}', 'resolver': resolver, 'port': port})


def _job_status(api: Agent, engine: str):
    options = api.get('/workflow/client/options/' + engine)
    for c in options['choices']:
        action = 'build-client' if c['kind'] == 'native' else 'build-alternate'
        try:
            result = api.get(f'/workflow/jobs/{action}/{engine}')
            print(f"{c['id']}: {result.get('state', 'unknown')} | "
                  f"resolver={result.get('resolver', 'not set')} | "
                  f"port={result.get('port', 'not set')} | "
                  f"artifact={result.get('artifact', 'not built')}")
        except AgentFailure as exc:
            print(f"{c['id']}: {exc}")
    print('Artifacts are available through authenticated Web Panel downloads.')


def interactive(api: Agent) -> int:
    print('DNS UNIFIED CONTROL | local TUI v' + __import__('pathlib').Path(__file__).resolve().parent.parent.joinpath('VERSION').read_text().strip())
    print('Agent Unix socket only. No web password/TOTP is read or stored.')
    while True:
        print('\n1 Status  2 Engines  3 Dante  4 Clients  5 Jobs')
        print('6 Switch DNS engine  7 Build client  8 Metrics  9 Exclusive/Multi  0 Exit')
        try: choice = input('Choice: ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nExit')
            return 0
        try:
            if choice == '0':return 0
            elif choice in ('1', '2'):
                _print_readiness(api.get('/workflow/readiness'))
            elif choice == '3':
                d = api.get('/workflow/dante/status')
                print('Dante:', 'READY' if d.get('ready') else 'NOT READY',
                      '| loopback:', d.get('bind', '?'), '| auth:', bool(d.get('auth_verified')))
            elif choice == '4':
                engine = input('Engine id: ').strip()
                _print_client_options(api.get('/workflow/client/options/' + engine))
            elif choice == '5':
                _job_status(api, input('Engine id: ').strip())
            elif choice == '6':
                engine = input('Switch to engine id (or none): ').strip()
                print(json.dumps(_switch(api, engine), indent=2))
            elif choice == '7':
                engine = input('Engine id: ').strip()
                choices = api.get('/workflow/client/options/' + engine)
                _print_client_options(choices)
                client = input('Client id: ').strip()
                resolver = input('Resolver IPv4:port [1.1.1.1:53]: ').strip() or '1.1.1.1:53'
                port = int(input('Local TCP port [2080]: ').strip() or '2080')
                print(json.dumps(_build(api, engine, client, resolver, port), indent=2))
            elif choice == '8':
                m = api.get('/metrics')
                print(f"CPU={m.get('cpu')}% RAM={m.get('ram_percent')}% "
                      f"DISK={m.get('disk_percent')}%")
            # DUC_MULTI_ADDON_0101
            elif choice == '9':
                from ducmulti import ENGINE_ORDER
                r=api.get('/multi/status')
                print(json.dumps(r,ensure_ascii=False,indent=2))
                mode=input('Mode [exclusive/multi] (blank: cancel): ').strip()
                if mode not in ('exclusive','multi'):print('Cancelled.');continue
                choices=input('Engine ids comma-separated: ').strip().split(',')
                choices=[e.strip() for e in choices if e.strip()]
                import json as _json
                request={'mode':mode,'engines':choices}
                proposed=api.post('/multi/plan',request)
                print(_json.dumps(proposed,ensure_ascii=False,indent=2))
                if not proposed.get('ready'):print('BLOCKED by preflight; no changes.');continue
                try:answer=input('Apply change? [yes/no] (default: no): ').strip().lower()
                except (EOFError,KeyboardInterrupt):answer='no'
                if answer=='yes':print(_json.dumps(api.post('/multi/apply',{**request,'confirm':'yes'}),ensure_ascii=False,indent=2))
                else:print('Cancelled.')
            else:print('Unknown choice')
        except (AgentFailure, ValueError, KeyError) as exc:
            print('Error:', exc)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Local Unix-socket-only DUC TUI (root or authorized group)')
    parser.add_argument('--socket', default=os.environ.get('DUC_AGENT_SOCKET', DEFAULT_SOCKET))
    parser.add_argument('--json', action='store_true', help='machine-readable response (read-only commands)')
    sub = parser.add_subparsers(dest='command')
    for command in ('menu', 'status', 'engines', 'dante', 'metrics'):
        sub.add_parser(command)
    clients = sub.add_parser('clients');clients.add_argument('engine')
    jobs = sub.add_parser('jobs'); jobs.add_argument('engine')
    switch = sub.add_parser('switch');switch.add_argument('engine')
    switch.add_argument('--restart', action='store_true')
    build = sub.add_parser('build');build.add_argument('engine');build.add_argument('client')
    build.add_argument('--resolver', default='1.1.1.1:53')
    build.add_argument('--port', default=2080, type=int)
    args = parser.parse_args(argv)
    if args.json and args.command not in ('status', 'engines', 'dante', 'metrics', 'clients'):
        parser.error('--json is available only for read-only status commands')
    api = Agent(args.socket)
    try:
        if args.command in (None, 'menu'): return interactive(api)
        if args.command in ('status', 'engines'):
            data=api.get('/workflow/readiness')
            if args.json:print(json.dumps(data, ensure_ascii=False, indent=2))
            else:_print_readiness(data)
        elif args.command=='dante':
            data=api.get('/workflow/dante/status')
            if args.json:print(json.dumps(data, ensure_ascii=False, indent=2))
            else:print('Dante:', 'READY' if data.get('ready') else 'NOT READY',
                       'bind:', data.get('bind'), 'auth:', bool(data.get('auth_verified')))
        elif args.command=='metrics':
            data=api.get('/metrics')
            if args.json:print(json.dumps(data, ensure_ascii=False, indent=2))
            else:print(f"CPU={data.get('cpu')}% RAM={data.get('ram_percent')}% "
                       f"DISK={data.get('disk_percent')}%")
        elif args.command=='clients':
            data=api.get('/workflow/client/options/' + args.engine)
            if args.json:print(json.dumps(data, ensure_ascii=False, indent=2))
            else:_print_client_options(data)
        elif args.command=='jobs':_job_status(api,args.engine)
        elif args.command=='switch':print(json.dumps(_switch(api,args.engine,args.restart),indent=2))
        elif args.command=='build':print(json.dumps(_build(api,args.engine,args.client,args.resolver,args.port),indent=2))
    except (AgentFailure,ValueError,KeyError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
