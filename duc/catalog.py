"""Single source of truth: mutually exclusive DNS engines, classifications and DNS labels."""
ENGINES=('master','slipstream','dnstt','noizdns','vaydns','soar','iodine','dns2tcp','xdns')
NAMES={'master':'MasterDnsVPN','slipstream':'SlipStream Rust','dnstt':'DNSTT','noizdns':'NoizDNS','vaydns':'VayDNS','soar':'Soar','iodine':'iodine','dns2tcp':'dns2tcp','xdns':'XDNS (Xray FinalMask)'}
LABELS={'master':'m','slipstream':'r','dnstt':'d','noizdns':'n','vaydns':'v','soar':'s','iodine':'i','dns2tcp':'c','xdns':'x'}
FAMILIES={'master':'ARQ / Multi resolver','slipstream':'QUIC over DNS','dnstt':'Noise / KCP','noizdns':'DPI-resistant DNSTT','vaydns':'KCP / SMUX','soar':'Multi-path / signed handshake','iodine':'IP over DNS','dns2tcp':'TCP over DNS','xdns':'Xray / FinalMask / mKCP'}
METHODS={'master':['UDP DNS','ARQ','multi-resolver'], 'slipstream':['UDP DNS','QUIC','Rust'],
 'dnstt':['UDP DNS','Noise','KCP'], 'noizdns':['UDP DNS','Noise','alternate query encoding'],
 'vaydns':['UDP DNS','DoH client','DoT client','TXT','A','AAAA','CNAME','KCP'],
 'soar':['UDP DNS','multipath','TXT','AAAA'], 'iodine':['UDP DNS','IP over DNS'],
 'dns2tcp':['UDP DNS','TCP forwarding'], 'xdns':['FinalMask','TXT','A','AAAA','CNAME','mKCP']}
BINARIES={'master':'masterdnsvpn-server','slipstream':'slipstream-rust-server','dnstt':'dnstt-server',
 'noizdns':'noizdns-server','vaydns':'vaydns-server','soar':'duc-soar-server','iodine':'iodined','dns2tcp':'dns2tcpd','xdns':'xray'}
META={e:{'id':e,'name':NAMES[e],'label':LABELS[e],'family':FAMILIES[e],'methods':METHODS[e],
 'binary':BINARIES[e]} for e in ENGINES}
