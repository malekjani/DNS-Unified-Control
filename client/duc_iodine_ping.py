#!/usr/bin/env python3
"""IP-level iodine loss benchmark; requires an already running iodine client."""
import argparse, datetime, json, os, re, subprocess

def parse_ping(output):
    m=re.search(r'(\d+) packets transmitted, (\d+)(?: packets)? received,\s*([\d.]+)% packet loss',output)
    if not m:raise ValueError('Cannot parse ping packet summary')
    sent,received,loss=int(m[1]),int(m[2]),float(m[3])
    if sent<1 or received>sent:raise ValueError('Malformed ping result')
    r=re.search(r'(?:round-trip|rtt) min/avg/max/(?:stddev|mdev) = ([\d.]+)/([\d.]+)/',output)
    return sent,received,loss,float(r[2]) if r else None

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--peer',default='10.78.0.1',help='TUN peer address. Only private IPs accepted')
    p.add_argument('--count',type=int,default=12)
    p.add_argument('--out',default='duc-iodine-ping.json')
    a=p.parse_args()
    import ipaddress
    try:
        ip=ipaddress.ip_address(a.peer)
        if ip.version!=4 or not ip.is_private:raise ValueError()
    except ValueError:p.error('--peer must be a private IPv4 tunnel address')
    if not 3<=a.count<=40:p.error('--count must be 3..40')
    command=['ping','-n','-c',str(a.count),'-W','3','-i','0.3',a.peer]
    output=subprocess.run(command,capture_output=True,text=True,timeout=a.count*5+10)
    sent,received,loss,rtt=parse_ping(output.stdout+'\n'+output.stderr)
    report={'schema':1,'engine':'iodine','timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'measurement':'client-iodine-icmp','samples':sent,'successful':received,'failed':sent-received,
            'request_failure_pct':round((sent-received)*100/sent,2),
            'icmp_packet_loss_pct':loss,'raw_dns_packet_loss_pct':None,
            'socks_connect_rtt_ms':None,'http_ttfb_ms':rtt,
            'http_throughput_bps':None,'exit_ip':None}
    fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
