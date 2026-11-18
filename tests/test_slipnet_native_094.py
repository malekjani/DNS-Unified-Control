"""v0.9.5 pinned Linux CLI release download tests. No network in CI."""
import hashlib, zipfile
import pytest
from duc import core,jobs,worker,slipnet_native as native


def test_fixed_release_and_hash():
    assert native.TAG=='v2.5.3'
    assert native.BINARY=='slipnet-linux-amd64'
    assert native.PINNED_SHA256=='1eb6a66df7a9d15e2260dd28d28655a3d5cebced8504509062ab614097f27534'
    assert native.DOWNLOAD_URL.startswith('https://github.com/anonvector/SlipNet/releases/download/v2.5.3/')
    assert native.MIRROR_URL.startswith('https://downloads.sourceforge.net/project/slipnet.mirror/v2.5.3/')


def test_bad_binary_refuses(monkeypatch):
    class R:
        def __enter__(self):return self
        def __exit__(self,*a):return None
        def geturl(self):return native.DOWNLOAD_URL
        def read(self,max_bytes):return b'\x7fELF'+b'0'*120000
    monkeypatch.setattr(native.urllib.request,'urlopen',lambda *a,**kw:R())
    with pytest.raises(RuntimeError,match='SHA-256 mismatch'): native.get_release_binary()


def test_release_fallback_does_not_bypass_checksum(monkeypatch):
    urls=[]
    def fail(req,timeout):
        urls.append(req.full_url)
        raise OSError('network inaccessible')
    monkeypatch.setattr(native.urllib.request,'urlopen',fail)
    with pytest.raises(RuntimeError,match='Could not fetch pinned SlipNet'):native.get_release_binary()
    assert urls==[native.DOWNLOAD_URL,native.MIRROR_URL]


def test_valid_fixed_hash_return(monkeypatch):
    payload=b'\x7fELF'+b'0'*150000
    actual=hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(native,'PINNED_SHA256',actual)
    class R:
        def __enter__(self):return self
        def __exit__(self,*a):return None
        def geturl(self):return native.DOWNLOAD_URL
        def read(self,n):return payload[:n]
    monkeypatch.setattr(native.urllib.request,'urlopen',lambda *a,**kw:R())
    assert native.get_release_binary()==(payload,native.TAG,actual)


def test_native_client_zip_no_secret(monkeypatch,tmp_path):
    monkeypatch.setattr(core,'ROOT',tmp_path/'etc')
    monkeypatch.setattr(core,'STATE',tmp_path/'state')
    (core.ROOT/'keys').mkdir(parents=True)
    (core.ROOT/'keys/noizdns.pub').write_text('e'*64)
    (core.ROOT/'keys/noizdns.key').write_text('PRIVATEKEY_NOT_FOR_ZIP')
    monkeypatch.setattr(native,'get_release_binary',lambda:(b'\x7fELF'+b'0'*120000,native.TAG,'f'*64))
    result=worker.build_client('noizdns')
    with zipfile.ZipFile(jobs.artifact_path('noizdns')) as z:
        assert {'slipnet-linux-amd64','slipnet-profile.txt','run-noizdns.sh','UPSTREAM.txt','README.txt'} <= set(z.namelist())
        assert z.read('slipnet-profile.txt').decode().split('|')[38]=='1'
        assert b'PRIVATEKEY_NOT_FOR_ZIP' not in jobs.artifact_path('noizdns').read_bytes()
    assert result['source_commit']==native.TAG
