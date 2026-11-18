"""Immutable client compatibility registry shared by web, agent and future TUI.

Engine != client implementation != backend. Only demonstrated or upstream-
documented combinations are buildable. No secrets are returned in catalog.
"""
from __future__ import annotations
from .catalog import ENGINES

CHOICES = {
    'dnstt': [
        {'id':'native','label':'DNSTT اختصاصی (Raw TCP)','kind':'native','tested':True,
         'note':'کلاینت رسمی DNSTT؛ SOCKS5 احرازشده Dante از داخل تونل TCP عبور می‌کند.'},
        {'id':'slipnet','label':'SlipNet CLI (DNSTT)','kind':'alternate','tested':False,
         'note':'پشتیبانی DNSTT در SlipNet مستند است؛ سازگاری دقیق با سرور فعلی هنوز نیازمند آزمایش است.'}
    ],
    'noizdns': [
        {'id':'slipnet','label':'SlipNet CLI · NoizDNS Stealth','kind':'native','tested':True,
         'note':'حالت sayedns + stealth؛ اتصال recursive DNS و کنترل اعتبارنامه SOCKS5 در Debian تأیید شده است.'},
        {'id':'dnstt','label':'DNSTT استاندارد · بدون Stealth','kind':'alternate','tested':True,
         'note':'سرور fork با کلاینت استاندارد DNSTT سازگار است؛ این حالت مزایای Stealth اختصاصی را ندارد.'}
    ],
    'vaydns': [
        {'id':'native','label':'VayDNS اختصاصی','kind':'native','tested':True,
         'note':'کلاینت native، با پرچم‌های نسخه متناظر سرور و تنظیمات پروفایل.'},
        {'id':'slipnet','label':'SlipNet CLI (VayDNS)','kind':'alternate','tested':False,
         'note':'پشتیبانی VayDNS در SlipNet مستند است؛ record type و ClientID باید با سرور یکسان باشند.'}
    ],
}

SINGLE = {
    'master': ('native', 'MasterDnsVPN اختصاصی؛ SOCKS5 داخلی مستقل از Dante'),
    'slipstream': ('native', 'SlipStream Rust اختصاصی؛ SlipNet CLI v2.5.3 این نوع را اجرا نمی‌کند'),
    'soar': ('native', 'Soar اختصاصی محدودشده به Dante؛ SlipNet CLI در این بسته تأیید نشده'),
    'iodine': ('native', 'iodine سیستم؛ IP-over-DNS و بدون SOCKS5 داخلی'),
    'dns2tcp': ('native', 'dns2tcp سیستم؛ TCP-over-DNS بدون رمزنگاری'),
    'xdns': ('native', 'Xray FinalMask؛ نیازمند پیکربندی سازگار Xray')
}

def options(engine):
    if engine not in ENGINES: raise ValueError('unknown engine')
    if engine in CHOICES: choices=[dict(x) for x in CHOICES[engine]]
    else:
        _,note=SINGLE[engine]
        choices=[{'id':'native','label':'کلاینت اختصاصی / مستندات موتور',
                  'kind':'native','tested':False,'note':note}]
    return {'engine':engine,'choices':choices,'default':choices[0]['id'],
            'exclusive_dns':True, 'shared_backend':'127.0.0.1:1080',
            'client_listener':'127.0.0.1:2080',
            'warning':'انتخاب کلاینت موتور DNS سرور را تغییر یا Start نمی‌کند.'}


# Build configuration is an engine-independent value object. Web, Agent,
# worker, and a future TUI must all use this same strict validation.
def build_settings(resolver='1.1.1.1:53', port=2080):
    import ipaddress
    if not isinstance(resolver,str) or resolver.count(':')!=1:
        raise ValueError('resolver must be IPv4:port')
    address, dns_port = resolver.split(':')
    try:
        if str(ipaddress.IPv4Address(address)) != address:
            raise ValueError('resolver IP must be canonical')
    except ipaddress.AddressValueError:
        raise ValueError('invalid resolver IP')
    if not dns_port.isascii() or not dns_port.isdecimal() or not 1 <= int(dns_port) <= 65535:
        raise ValueError('resolver port must be 1..65535')
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('client local port must be 1024..65535')
    return {'resolver':f'{address}:{int(dns_port)}','port':port}
