"""Create PBKDF2 auth file; run as root during install."""
import getpass, hashlib, json, os, pathlib, sys
from .core import ROOT, atomic_json

def main():
    p=os.environ.get('DUC_INITIAL_PASSWORD')
    if not p:
        if not sys.stdin.isatty(): raise SystemExit('Set DUC_INITIAL_PASSWORD or run interactively')
        p=getpass.getpass('New dashboard password (min 16 chars): ')
    if len(p)<16:raise SystemExit('Password must be at least 16 characters')
    salt=os.urandom(16)
    digest=hashlib.pbkdf2_hmac('sha256',p.encode(),salt,600000)
    path=ROOT/'web-auth.json';atomic_json(path,{'salt':salt.hex(),'hash':digest.hex()})
    # Web service runs as dns-unified; not world readable.
    import grp
    try:os.chown(path,0,grp.getgrnam('dns-unified').gr_gid)
    except KeyError:pass
    os.chmod(path,0o640)
    print('Admin password set. Auth file:',path)
if __name__=='__main__':main()
