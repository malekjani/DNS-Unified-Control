"""Static offline regression tests: provenance, no conflicts, no secret export."""
import hashlib
import io
import json
import os
import pathlib
import struct
import zipfile
import pytest
from duc import core, provision, slipstream_ali, workflow


def test_pinned_release_is_immutable_in_code():
    assert slipstream_ali.TAG=='42e3e75'
    assert slipstream_ali.REPO=='AliRezaBeigy/slipstream-rust-deploy'
    for kind,info in slipstream_ali.BINARIES.items():
        assert len(info['sha256'])==64
        assert int(info['sha256'],16)
        assert info['asset'].endswith('-linux-amd64')
        assert info['target'].name=='slipstream-rust-'+kind
    assert provision.STRATEGIES['slipstream'].kind=='consent'


def test_hash_and_elf_64_x86_64_validation(tmp_path,monkeypatch):
    data=bytearray(b'\x7fELF\x02\x01'+b'\x00'*200000)
    struct.pack_into('<H',data,18,62)
    binary=tmp_path/'server';binary.write_bytes(data)
    assert slipstream_ali.is_x86_64_elf(binary)
    monkeypatch.setitem(slipstream_ali.BINARIES,'server',{
        **slipstream_ali.BINARIES['server'],
        'sha256':hashlib.sha256(data).hexdigest()})
    slipstream_ali.check_binary(binary,'server',cli=False)
    with binary.open('r+b') as out:
        out.seek(200);out.write(b'BAD')
    with pytest.raises(RuntimeError,match='SHA-256'):
        slipstream_ali.check_binary(binary,'server',cli=False)
    binary.unlink();binary.symlink_to(tmp_path/'another')
    with pytest.raises(RuntimeError,match='regular file'):
        slipstream_ali.check_binary(binary,'server',cli=False)


def test_slipstream_profile_uses_multiresolver_cert_keepalive_bilingual(monkeypatch):
    settings=core.profiles()
    conf=settings['slipstream']
    conf.update(domain='r.m2m.diy',client_resolvers='1.1.1.1:53,8.8.8.8:53',
                client_authoritative='188.132.174.249:53',client_cc='bbr',client_keep_alive=700)
    monkeypatch.setattr(core,'profiles',lambda:settings)
    guide=workflow.build_client_guide('slipstream','1.1.1.1:53',2222)
    cmd=guide['example_command']
    assert cmd.count('--resolver')==2
    assert '--authoritative 188.132.174.249:53' in cmd
    assert '--congestion-control bbr' in cmd
    assert '--keep-alive-interval 700' in cmd
    assert '--cert ./slipstream-rust.crt' in cmd
    assert 'FA:' in ' '.join(guide['steps'])
    assert 'EN:' in ' '.join(guide['steps'])
    assert 'github.com/AliRezaBeigy' in guide['docs']
    assert '--gso' not in cmd
    conf.update(client_cc='auto',client_authoritative='')
    assert '--congestion-control' not in workflow.build_client_guide('slipstream')['example_command']


def test_no_independent_scripts_nor_firewall_mutations():
    folder=pathlib.Path(__file__).resolve().parents[1]
    script=(folder/'scripts/install-slipstream-ali.sh').read_text()
    loader=(folder/'duc/slipstream_ali.py').read_text()
    assert 'Type exactly yes' not in script
    assert 'IFS= read -r confirmation' not in script
    assert 'duc.slipstream_ali --install' in script
    assert 'fcntl.flock' in loader and 'core.switch_lock()' in loader
    assert 'os.link(stage,target)' in loader  # never overwrite an existing binary
    assert 'iptables -t nat -A' not in script + loader
    assert 'slipstream-rust-deploy.sh' not in script + loader
    assert 'systemctl start' not in script + loader


def test_public_bundle_no_private_tls_key(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path)
    (tmp_path/'keys').mkdir()
    (tmp_path/'keys/slipstream-rust.crt').write_text('PUBLIC-CERTIFICATE')
    (tmp_path/'keys/slipstream-rust.key').write_text('PRIVATE-SUPER-SECRET')
    b=workflow.create_public_guide_bundle('slipstream')
    with zipfile.ZipFile(io.BytesIO(b)) as z:
        assert z.read('slipstream-rust.crt')==b'PUBLIC-CERTIFICATE'
        assert b'PRIVATE-SUPER-SECRET' not in b
        assert not any(n.endswith('.key') for n in z.namelist())
