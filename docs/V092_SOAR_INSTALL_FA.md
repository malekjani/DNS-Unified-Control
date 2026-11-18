# DNS Unified Control v0.9.2 — سرور Soar در مرحلهٔ نصب

## چه چیزی اصلاح شد؟
در 0.9.1 سرور Soar تنها با فشردن دکمه در پنل نصب می‌شد. اکنون با اجرای **install.sh** یا **upgrade.sh**، بدون مرحلهٔ دستی در وب‌پنل:

1. ابزارهای لازم Go/Git در صورت فقدان از apt نصب می‌شوند.
2. منبع بالادستی `getlantern/soar` در cache بررسی و دریافت می‌شود و `soar-src/server.go` به باینری محدودشده `/usr/local/bin/duc-soar-server` کامپایل می‌شود. این باینری تنها اجازهٔ اتصال TCP به `127.0.0.1:1080` را دارد.
3. کلید خصوصی Ed25519 فقط در صورت نبودن در `/etc/dns-unified/keys/soar.key` ساخته می‌شود (مجوز دقیق 0600). اگر فایل موجود معتبر باشد تغییر نمی‌کند. کلید عمومی از همان کلید خصوصی مشتق و در `soar.pub` ذخیره می‌شود؛ ناسازگاری دو فایل خطای نصب است و فایل‌های قبلی بازنویسی نمی‌شوند.
4. مرحلهٔ نصب وجود باینری ELF قابل اجرا، صحت کلیدها و مجوزها را بررسی می‌کند. اگر هر یک شکست بخورد اسکریپت `install.sh`/`upgrade.sh` با exit code غیرصفر خارج می‌شود؛ وضعیت خطا در ترمینال و گزارش Provision ذخیره می‌شود.

**نصب باینری به معنای روشن‌کردن Soar نیست**. سرویس فعلی DNS بدون تغییر می‌ماند؛ Dante مشترک هم Restart نمی‌شود. ساخت و دانلود کلاینت Linux amd64 از بخش «راه‌اندازی و کلاینت‌ها» پنل انجام می‌شود و گذرواژهٔ Dante هرگز داخل ZIP نیست. Soar هنوز برای آزمون عملکردی به DNS delegation و سوئیچ موتور با Exclusive Mode نیاز دارد.

## ارتقا

فایل `DNS-Unified-Control-v0.9.2-Soar-AutoInstall.zip` را به `/root` VPS منتقل کن، سپس:

```bash
cd /root
unzip -tq DNS-Unified-Control-v0.9.2-Soar-AutoInstall.zip
unzip -oq DNS-Unified-Control-v0.9.2-Soar-AutoInstall.zip
cd /root/dns-unified-control
bash upgrade.sh
```

خروج موفق حاوی `=== Soar server assets verified; no DNS engine activated ===` است. برای بازرسی **فقط‌خواندنی** بدون نصب:

```bash
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.install_soar --check
```

اگر شبکه یا کامپایل Go ناموفق باشد، وضعیت خطا معتبر است و نباید با «نصب موفق» اشتباه گرفته شود. روی VPS کم‌حافظه ساخت اولیه زمان‌بر است و ممکن است به Go toolchain جدید از اینترنت نیاز داشته باشد.

## محدودیت‌های باقی‌مانده

- فقط سرور Soar در این اصلاح **در خود installer** نصب می‌شود؛ نصب کامل بقیه موتورهای DNS همچنان تابع روند قبلی است.
- ساخت کلاینت فعلاً **Linux amd64** است، نه Windows. پشتیبانی Windows تا وقتی بیلد واقعی انجام نشود اعلام نمی‌شود.
- سلامت سرویس Dante و واگذاری واقعی NS در مرحلهٔ فعال‌سازی بررسی می‌شوند؛ ساخت کلیدها به‌تنهایی تونل را تأیید نمی‌کند.
- لاگ و گزارش نباید حاوی `soar.key` یا رمز Dante باشد.
