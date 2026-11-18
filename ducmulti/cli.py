"""Read-only plan/status by default; write only after typed yes."""
from __future__ import annotations
import argparse,json,sys
from . import ENGINE_ORDER,controller

def main(argv=None):
    p=argparse.ArgumentParser(description='DNS Unified Multi-mode add-on')
    sub=p.add_subparsers(dest='action',required=True)
    sub.add_parser('status')
    for name in ('plan','apply'):
        x=sub.add_parser(name)
        x.add_argument('--mode',choices=('multi','exclusive'),required=True)
        x.add_argument('--engines',default=','.join(ENGINE_ORDER))
        x.add_argument('--listen-ip',default=None)
    a=p.parse_args(argv)
    if a.action=='status':print(json.dumps(controller.status(),indent=2));return 0
    engines=[e.strip() for e in a.engines.split(',') if e.strip()]
    result=controller.plan(a.mode,engines,a.listen_ip)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    if a.action=='plan':return 0 if result['ready'] else 2
    if not result['ready']:
        print('BLOCKED: No changes performed.',file=sys.stderr);return 2
    if not sys.stdin.isatty():
        print('Interactive TTY required for apply.',file=sys.stderr);return 3
    try:
        answer=input('Apply this DNS mode switch? [yes/no] (default: no): ').strip().lower()
    except (EOFError,KeyboardInterrupt):answer='no'
    if answer!='yes':print('Cancelled.');return 0
    applied=controller.apply(a.mode,engines,a.listen_ip,confirm='yes')
    print(json.dumps(applied,ensure_ascii=False,indent=2))
    return 0 if applied.get('ok') else 1
if __name__=='__main__':raise SystemExit(main())
