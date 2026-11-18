#!/usr/bin/env python3
"""Authenticated SOCKS5 end-to-end and HTTPS measurement, no extra proxy.

Fields: RTT is SOCKS5 CONNECT + authentication; failure rate is *request*
failure, not raw DNS packet loss. Throughput is received HTTP body bytes/sec.
"""
import argparse, datetime, getpass, json, os, socket, ssl, statistics, struct, time
from urllib.parse import urlparse


def recv_exact(s,n):
    out=bytearray()
    while len(out)<n:
        b=s.recv(n-len(out))
        if not b: raise OSError('Truncated proxy reply')
        out.extend(b)
    return bytes(out)


def connect_socks(host,port,username,password,target,target_port,timeout):
    user=username.encode('utf-8'); pwd=password.encode('utf-8'); domain=target.encode('idna')
    if not all(0<len(x)<=255 for x in (user,pwd,domain)):raise ValueError('Credentials and destination must fit SOCKS5')
    start=time.monotonic()
    s=socket.create_connection((host,port),timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b'\x05\x01\x02')
        if recv_exact(s,2)!=b'\x05\x02':raise OSError('SOCKS username/password auth unavailable')
        s.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(pwd)])+pwd)
        if recv_exact(s,2)!=b'\x01\x00':raise PermissionError('SOCKS username/password rejected')
        s.sendall(b'\x05\x01\x00\x03'+bytes([len(domain)])+domain+struct.pack('!H',target_port))
        reply=recv_exact(s,4)
        if reply[:3]!=b'\x05\x00\x00':raise OSError('SOCKS CONNECT refused: '+reply.hex())
        atyp=reply[3]
        if atyp==1:recv_exact(s,4)
        elif atyp==4:recv_exact(s,16)
        elif atyp==3:recv_exact(s,recv_exact(s,1)[0])
        else:raise OSError('Bad SOCKS address type')
        recv_exact(s,2)
        return s,(time.monotonic()-start)*1000
    except Exception:
        s.close();raise


def measure(url,proxy_port,user,password,timeout=25):
    parsed=urlparse(url)
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None,443):
        raise ValueError('Only HTTPS URLs on port 443 with no URL credentials are supported')
    path=(parsed.path or '/')+('?' + parsed.query if parsed.query else '')
    raw,rtt=connect_socks('127.0.0.1',proxy_port,user,password,parsed.hostname,443,timeout)
    try:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=parsed.hostname) as sock:
            # HTTP/1.1 explicit to avoid ALPN framing confusion.
            sock.sendall(f'GET {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\nUser-Agent: DUC-probe/0.9\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n'.encode())
            start=time.monotonic(); buf=bytearray(); first=None
            while True:
                b=sock.recv(65536)
                if not b:break
                if first is None:first=(time.monotonic()-start)*1000
                buf.extend(b)
                if len(buf)>2_000_000:raise OSError('Probe body unexpectedly large')
            elapsed=time.monotonic()-start
        header,sep,body=bytes(buf).partition(b'\r\n\r\n')
        if not sep:raise OSError('No HTTP headers')
        code=int(header.split(b' ',2)[1])
        if code!=200:raise OSError('HTTP '+str(code))
        # Data is measured at HTTPS layer (not on-the-wire DNS payload)
        return {'ok':True,'socks_connect_rtt_ms':round(rtt,2),
                'http_ttfb_ms':round(first or 0,2),'http_body_bytes':len(body),
                'http_body_bps':round(len(body)/max(elapsed,0.001),1) if len(body)>=65536 else None,
                'exit_ip':body.decode('ascii','ignore').strip() if parsed.hostname=='api.ipify.org' else None}
    finally:raw.close()


def summary(engine,results):
    successes=[x for x in results if x['ok']]
    n=len(results)
    return {'schema':1,'engine':engine,
            'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'samples':n,'successful':len(successes),'failed':n-len(successes),
            'request_failure_pct':round((n-len(successes))*100/n,2),
            'socks_connect_rtt_ms':round(statistics.median(x['socks_connect_rtt_ms'] for x in successes),2) if successes else None,
            'http_ttfb_ms':round(statistics.median(x['http_ttfb_ms'] for x in successes),2) if successes else None,
            'http_throughput_bps':round(statistics.median(x['http_body_bps'] for x in successes if x.get('http_body_bps') is not None),1) if any(x.get('http_body_bps') is not None for x in successes) else None,
            'exit_ip':next((x['exit_ip'] for x in successes if x.get('exit_ip')),None),
            'measurement':'real-client-socks5-https',
            'raw_dns_packet_loss_pct':None,
            'raw_dns_packet_loss_note':'Not measurable from a reliable TCP application probe',
            'results':[{'ok':r['ok'],'error_type':r.get('error_type')} for r in results]}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--engine',required=True,choices=['slipstream','dnstt','vaydns','master','noizdns','dns2tcp','soar'])
    p.add_argument('--port',type=int,default=2080)
    p.add_argument('--username',default=os.environ.get('DUC_SOCKS_USER','duc-socks'))
    p.add_argument('--repeat',type=int,default=4)
    p.add_argument('--url',default='https://api.ipify.org/')
    p.add_argument('--out',default='duc-socks-report.json')
    p.add_argument('--timeout',type=int,default=35)
    a=p.parse_args()
    if a.port<1024 or a.port>65535 or not 1<=a.repeat<=25 or not 5<=a.timeout<=90:p.error('invalid range')
    password=getpass.getpass('Dante SOCKS password (hidden): ')
    results=[]
    for i in range(a.repeat):
        try:
            r=measure(a.url,a.port,a.username,password,a.timeout)
            print(f'{i+1}/{a.repeat} HTTP OK  SOCKS RTT={r["socks_connect_rtt_ms"]}ms')
        except Exception as exc:
            r={'ok':False,'error_type':type(exc).__name__}
            print(f'{i+1}/{a.repeat} FAILED: {type(exc).__name__}')
        results.append(r)
    report=summary(a.engine,results)
    target=os.path.abspath(a.out)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},indent=2))
    print('Report (no password):',target)
    raise SystemExit(0 if report['successful']>0 else 1)

if __name__=='__main__':main()
