"""Break-glass admin reset. Must be run locally with sudo after identity checks."""
import os
import pathlib
import sys
from .mfa import DEFAULT_PATH
from .confirm import ask_yes_no


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the VPS console, not in the web panel')
    path = pathlib.Path(os.getenv('DUC_MFA_PATH', str(DEFAULT_PATH)))
    if not path.exists():
        print('MFA not configured')
        return
    if not sys.stdin.isatty():
        raise SystemExit('Interactive terminal required')
    print('WARNING: This deletes the current TOTP enrollment and requires re-enrollment at next login.')
    if not ask_yes_no('Reset admin MFA on this VPS?'):
        raise SystemExit('Cancelled')
    path.unlink()
    print('MFA configuration reset. Sign in with password and enroll again from an SSH tunnel.')
    print('For immediate session revocation, restart dns-unified-web.service.')


if __name__ == '__main__':
    main()
