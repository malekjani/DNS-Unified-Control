"""Honest, version-scoped advanced option registry and safety classification.

Exposes only options that the currently installed runner actually uses. An
upstream fork's unverified flags are not offered as 'enabled'.
"""
from . import core
from .unified import MODES

SCOPE = {
 'slipstream': {'server':['dns_listen_host','udp_port','max_connections','idle_timeout_seconds','target'],
                'client':['client_resolvers','client_authoritative','client_keep_alive','client_cc','client_port']},
 'dnstt': {'server':['domain','udp_port','target'], 'client':['resolver','public_key','listen_port']},
 'vaydns': {'server':['domain','udp_port','target','mtu','queue_size','dnstt_compat','record_type','vay_idle_timeout','vay_keepalive','vay_kcp_window','vay_queue_overflow','vay_log_level'],
            'client':['resolver','record_type','public_key','listen_port']},
 'master': {'server':['arq_window','log_level','encryption_method'], 'client':['client_port','resolver','native_socks']},
 'iodine': {'server':['tunnel_ip','udp_port'], 'client':['iodine_frag','iodine_max_down','iodine_type','iodine_encoding','iodine_upstream']},
 'dns2tcp': {'server':['domain','udp_port','target','resource'], 'client':['resolver','resource','local_port','query_type']},
 'soar': {'server':['domain','udp_port','target'], 'client':['resolver','forward','listen']},
 'noizdns': {'server':['domain','udp_port','target'], 'client':['native-slipnet-cli','sayedns','stealth']},
 'xdns': {'server':[], 'client':[]},
}

REFERENCES = {
 'slipstream':'https://github.com/AliRezaBeigy/slipstream-rust-deploy',
 'dnstt':'https://www.bamsoftware.com/software/dnstt/',
 'vaydns':'https://github.com/net2share/vaydns',
 'master':'https://github.com/masterking32/MasterDnsVPN',
 'iodine':'https://github.com/yarrick/iodine',
 'dns2tcp':'https://manpages.debian.org/unstable/dns2tcp/dns2tcpd.1.en.html',
 'soar':'https://github.com/getlantern/soar',
 'noizdns':'https://github.com/anonvector/SlipNet',
 'xdns':'https://xtls.github.io/en/config/transports/finalmask.html',
}

NOTES = {
 'iodine':'IP/TUN requires an explicit routed client; unencrypted; loss via ping only if tunnel is up.',
 'dns2tcp':'No encryption: keep SSH target; never pass Dante username/password directly.',
 'noizdns':'Server: standalone anonvector/dnstt and dedicated keypair. Client: official SlipNet Go CLI (sayedns + stealth), SHA256-verified release; native in-process SOCKS5. Working SOCKS credentials and HTTPS over recursive DNS field-tested 2026-11-07; server Dante logs not independently correlated.',
 'xdns':'Xray FinalMask xdns requires mKCP + matching configs; never auto-build guessed configs.',
 'soar':'Restricted Soar fixed-dial build: only 127.0.0.1:1080; matches authenticated shared Dante. Native Go client, no Gateway.',
 'master':'Native SOCKS5 listener. Local port is configurable when the client package is rebuilt.',
}


def registry():
    profiles=core.profiles()
    return {e:{'engine':e,'server_operational':SCOPE[e]['server'],
               'client_operational_or_documented':SCOPE[e]['client'],
               'backend_modes':list(MODES[e]),
               'current':{k:v for k,v in profiles[e].items() if k in SCOPE[e]['server'] or k in SCOPE[e]['client']},
               'upstream':REFERENCES[e], 'note':NOTES.get(e,'')}
            for e in core.ENGINES}
