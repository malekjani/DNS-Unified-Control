# رفع 203/EXEC و مرحله TLS در نسخه 0.10.2

## چرا پنل وب بالا نیامد؟

`umask 077` برای محافظت از هویت نصب تازه صحیح است، اما Python venv را 0700 می‌کند؛ web با UID `dns-unified` به آن دسترسی ندارد. اصلاح نباید شامل `chmod -R 777` یا افشای `/etc/dns-unified/keys` باشد. اسکریپت `ensure-runtime-access.sh` فقط کد و venv زیر `/opt/dns-unified-control` را برای گروه سرویس قابل خواندن/اجرا می‌کند و group-write را حذف می‌کند.

```bash
cd /root/dns-unified-control
sudo bash upgrade.sh
sudo bash scripts/check-local-health.sh
sudo bash scripts/panel-https-status.sh
```

اگر Upgrade در میانه خطای نصب موتور گرفت، ترمیم مستقیم پس از استخراج سورس 0.10.2:

```bash
sudo bash scripts/ensure-runtime-access.sh
sudo systemctl reset-failed dns-unified-web.service
sudo systemctl restart dns-unified-web.service
sudo bash scripts/check-local-health.sh
```

## صدور گواهی در VPS جایگزین

در مهاجرتی که `panel.m2m.diy` به سرور **قدیمی** اشاره می‌کند، نصب نمی‌تواند به شکل امن گواهی HTTP-01 را پیش از تغییر DNS صادر کند. اسکریپت رکورد Cloudflare را خودکار تغییر نمی‌دهد. پیش از صدور باید اطمینان پیدا کرد پنل جدید روی `127.0.0.1:8088` کار می‌کند و از طریق SSH Forwarding با MFA قابل ورود است. سپس **با تأیید کاربر** رکورد `panel` منتقل شود، اگر پورت‌های 80/443 آزاد و در AWS Security Group باز هستند، `scripts/setup-panel-https.sh` اجرا و Caddy/TLS بررسی شود. انتقال `ns` DNS Tunnel فقط بعد از تست موتور/کلاینت صورت گیرد.

اگر لازم است پیش از انتقال DNS گواهی صادر شود، باید از DNS-01 با مجوز `DNS Edit` و ابزار مدیریت امن و بازسازی/تمدید خودکار گواهی استفاده کرد؛ این گزینه در 0.10.2 **پیاده‌سازی نشده است**. توکن موقت مرحله Read-only برای این کار کافی نیست. وضعیت گواهی را جداگانه بررسی کن.
