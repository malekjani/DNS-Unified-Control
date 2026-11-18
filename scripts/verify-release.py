#!/usr/bin/env python3
"""Verify bundled file digests after extraction (integrity, NOT authenticity)."""
from pathlib import Path
import hashlib
import json
import sys


def verify(root: Path):
    manifest = json.loads((root / 'release-manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema') != 'duc.release.v1':
        raise ValueError('Unknown release manifest schema')
    files = manifest.get('files', {})
    if not isinstance(files, dict) or not files:
        raise ValueError('Empty release manifest')
    for name, digest in files.items():
        target = root / name
        if target.is_symlink() or target.resolve() == root.resolve() or not target.resolve().is_relative_to(root.resolve()):
            raise ValueError('Unsafe manifest path: ' + name)
        if not target.is_file():
            raise ValueError('Missing release file: ' + name)
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            raise ValueError('Checksum mismatch: ' + name)
    return len(files)


def main():
    try:
        root = Path(__file__).resolve().parents[1]
        n = verify(root)
        print(f'Release files verified: {n}. Note: SHA-256 manifest is not a digital signature.')
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'Release integrity check failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
