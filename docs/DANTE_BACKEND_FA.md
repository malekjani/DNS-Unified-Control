# Dante SOCKS5 backend — DNS Unified Control v0.7.0

سرویس Dante **موتور DNS نیست**. روی `127.0.0.1:1080/TCP` در VPS و با نام کاربری و گذرواژه مستقل اجرا می‌شود؛ نام سرویس `dns-unified-dante.service` است. این سرویس روی UDP/53 گوش نمی‌دهد، NAT/IPTables یا Caddy را تغییر نمی‌دهد و هیچ سیستم مستقلی برای مدیریت SlipStream نمی‌سازد.

## نصب از پنل

در `راه‌اندازی و کلاینت‌ها` موتور SlipStream را انتخاب کن. در کارت Dante ابتدا `نصب/تعمیر Dante` را بزن. نتیجهٔ Job و صحت احراز هویت را بررسی کن. سپس `فعال‌سازی SOCKS5 برای SlipStream` را انتخاب کن. تنها وقتی SlipStream فعال است، از مسیر Exclusive Mode Restart می‌شود؛ سایر موتورهای فعال دست‌نخورده‌اند.

## نصب و سوئیچ از SSH (بدون yes)

```bash
bash /opt/dns-unified-control/scripts/setup-dante-backend.sh
```

بازگشت به مقصد SSH `127.0.0.1:22`:

```bash
bash /opt/dns-unified-control/scripts/setup-dante-backend.sh --ssh
```

## دریافت لینک مخصوص v2rayN

پس از نصب، **فقط از ترمینال روت VPS**:

```bash
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante credentials
```

این دستور یک `socks://BASE64(user:password)@127.0.0.1:2080#SlipStream-Dante` می‌دهد. آن را **خصوصی** نگه دار و در v2rayN وارد کن. پورت 2080 روی Debian فقط وقتی کار می‌کند که کلاینت SlipStream در حال اجرا باشد. نمونه دستور لینوکس:

```bash
./slipstream-rust-client -r 1.1.1.1:53 -d r.m2m.diy -l 2080 --cert ./slipstream-rust.crt
```

تست با نام کاربری و رمز واقعی دانته روی Debian:

```bash
curl -4 --max-time 60 --socks5-hostname 127.0.0.1:2080 --proxy-user 'USER:PASSWORD' https://api.ipify.org
```

محدودیت: این روش فقط SOCKS5 TCP CONNECT را از طریق SlipStream منتقل می‌کند؛ UDP ASSOCIATE و ترافیک مستقیم UDP از تونل TCP پشتیبانی نمی‌شوند. احراز هویت لایه SOCKS5 برای جلوگیری از سوءاستفاده از DNS tunnel عمومی الزامی است.

## اشکال‌یابی

```bash
systemctl status dns-unified-dante dns-unified@slipstream --no-pager
ss -lntp | grep -E ':1080|:22'
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.dante status
journalctl -u dns-unified-dante -n 50 --no-pager
```

پس از نصب، وضعیت برنامه باید نشان دهد `ready: true`؛ فقط آن زمان Backend را فعال کن. اگر نصب یا Restart با خطا مواجه شد، به گزارش دقیق آن نگاه کن و از نوشتن رمز در چت خودداری کن.
