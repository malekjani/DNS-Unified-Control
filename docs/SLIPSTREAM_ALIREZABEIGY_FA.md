# یکپارچه‌سازی AliRezaBeigy SlipStream Rust با DNS Unified Control v0.7.0

## منبع باینری‌ها
- مخزن مدیریت/ساخت انتشار: https://github.com/AliRezaBeigy/slipstream-rust-deploy
- Release ثابت: `42e3e75` (منتشرشده ۲۰ ژوئن ۲۰۲۶)
- سرور Linux AMD64: `slipstream-server-linux-amd64`، SHA256: `e4363c228c0b5c6ab80a75726f87e40dba55eef6d4a148a839972a9e5fc977a5`
- کلاینت Linux AMD64: `slipstream-client-linux-amd64`، SHA256: `677eb993a8033f1bbec1739b36c7d233b23da98f35b00e1d9181f7c0b994e0b1`

این باینری‌ها از مخزن Deploy دریافت می‌شوند؛ خودِ اسکریپت نصب و مدیریت آن مخزن هرگز اجرا نمی‌شود.

## اجرا روی VPS
1. بسته کامل پروژه را روی `/root` استخراج کنید؛ سپس `cd /root/dns-unified-control && bash upgrade.sh`.
2. **موتور فعال را حفظ کنید** و این را اجرا کنید:
   `bash /opt/dns-unified-control/scripts/install-slipstream-ali.sh`
3. Preflight منابع را می‌بینید؛ فقط اگر پذیرفتید دقیقاً `yes` وارد کنید.
4. نصب‌کننده قبل از نصب هر دو فایل، SHA256، معماری ELF و آرگومان‌ها را بررسی می‌کند.
5. گواهی TLS و Reset Seed در مسیر `/etc/dns-unified/keys/slipstream-rust.*` محفوظ می‌ماند.
6. نتیجه را با `PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.slipstream_ali --verify` کنترل کنید.
7. برای ساخت ZIP کلاینت، در پنل `راه‌اندازی و کلاینت‌ها` → SlipStream → `ساخت بسته کلاینت`.
8. در پایان، فقط از داخل پنل به SlipStream سوئیچ کنید، نه با systemctl مستقل.

## بدون تداخل با Exclusive Mode
- هیچ قانون iptables/nftables، NAT/REDIRECT، Route، DNS Stub یا Caddy تغییر نمی‌کند.
- هیچ سرویس مستقل `slipstream-rust-server.service`، Dante یا Shadowsocks ایجاد نمی‌شود.
- تا قبل از سوئیچ پنل، موتور فعلی روی UDP/53 باقی می‌ماند.
- نصب‌کننده قفل `/var/lib/dns-unified/provision.lock` را می‌گیرد؛ سوئیچ هم‌زمان اجازه ندارد.
- دو باینری پین‌شده روی `/usr/local/bin/slipstream-rust-server` و `/usr/local/bin/slipstream-rust-client` نصب می‌شوند و توسط Runner و Worker پنل مصرف می‌شوند.
- نصب‌کننده هیچ فایل قبلی با هش متفاوت را بازنویسی نمی‌کند. نصب مجدد idempotent است.

## Backendها و امکانات قابل استفاده
- SSH: هدف موجود `127.0.0.1:22`، تست `ssh-keyscan -T 35 -p 2222 127.0.0.1` از داخل تونل.
- SOCKS5: تنها در صورت وجود SOCKS ایمن روی Loopback و تنظیم `target` همان پورت، بدون اجرای خودکار Dante توسط اسکریپت بیرونی.
- Shadowsocks: فقط در صورت آماده‌بودن `ss-server` روی Loopback و تأیید احراز هویت / سازگاری؛ هیچ Backend عمومی بدون رمز ساخته نمی‌شود.
- Resolver چندگانه: از `client_resolvers` در پروفایل پنل، با تکرار `--resolver`.
- Authoritative path اختیاری: `client_authoritative`، با هشدار افزایش بار و قابلیت تشخیص.
- Congestion: `client_cc=auto/bbr/dcubic`؛ `auto` فلگ را حذف می‌کند.
- Keepalive: `client_keep_alive` بر حسب میلی‌ثانیه (پیش‌فرض 400).
- TLS pinning: `--cert ./slipstream-rust.crt`; کلید خصوصی هرگز در ZIP قرار نمی‌گیرد.
- GSO: با وجود فلگ، upstream گزارش کرده در loop Rust هنوز پیاده‌سازی کامل نشده؛ در راهنما فعال نمی‌شود.

## هنوز تأییدنشده
اتصال واقعی این Release به `r.m2m.diy`، پایداری و سرعت، سازگاری نسخه GUI و Android، و عملکرد SOCKS/Shadowsocks باید روی سرور و شبکهٔ کلاینت آزمایش شوند. گواهی داخلی پنل با گواهی SlipStream متفاوت است.
