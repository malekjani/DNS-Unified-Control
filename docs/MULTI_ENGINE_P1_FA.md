# DNS Unified Control — Multi-Engine Stage 1 add-on

**نسخهٔ یکپارچهٔ 0.10.6، مرحلهٔ اول Multi-Engine.** این سورس کامل مبتنی بر نسخهٔ رسمی 0.10.5 است و از مسیر نصب و ارتقای اصلی استفاده می‌کند.

## آنچه واقعاً پیاده‌سازی شده

- یک DNS Router واقعی روی یک IPv4 اینترفیس محلی سرور (TCP/53 و UDP/53)، با مسیریابی DNS Query از روی **مرز دقیق دامنه** به آداپتور موتور مربوطه. Query/Response بدون تغییر payload عبور می‌کند. درخواست ناشناخته `REFUSED` می‌شود؛ Recursive DNS عمومی نمی‌سازد.
- آداپتورهای حلقه‌بستهٔ اجرا برای MasterDnsVPN، Soar، SlipStream Rust، NoizDNS، DNSTT و VayDNS: 5301، 5302، 5304، 5305، 5306 و 5307 روی `127.0.0.1`. مشخصات Exclusive موتور، رمزها و کلیدها به صورت مستقیم تغییر نمی‌کنند.
- یک جایگاه External Adapter برای CottenDNS روی `127.0.0.1:5303`، که نیازمند **نصب و صحت‌سنجی جداگانهٔ باینری و کانفیگ سرور** است. این بسته CottenDNS را دانلود، Build، یا راه‌اندازی اولیه نمی‌کند.
- پیش‌بررسی و تأیید `yes/no`، قفل اختصاصی سوییچ، توقف/اجرای مدیریتی، تست Listen، ثبت State، محافظت از سوییچ قدیمی در Multi، تلاش برای برگشت به وضعیت سابق، راه‌اندازی دوباره پس از reboot با Unitهای enableشده.
- APIهای MFA+CSRF محافظت‌شده در پنل Web و endpointهای مستقل privileged Agent؛ یک پنجرهٔ مدیریتی در Web و گزینهٔ 9 در TUI؛ CLI کمکی.
- آزمایش‌ها برای UDP/TCP forwarding، سازگاری نام دامنه، مجزا بودن transaction ID درخواست‌های موازی، تشخیص نصب ناقص و سناریوی Rollback شبیه‌سازی‌شده.

**مواردی که هنوز انجام نشده:** تست روی VPS واقعی فرانسه، تست کلاینت برای هر هفت موتور، نصب مستقل و تولید پروفایل CottenDNS، بهینه‌سازی high-throughput dataplane، تحقیق دربارهٔ DoT/DoH و FEC، تنظیمات جدید در کل Lifecycle 0.10.5، و اثبات امنیت/پایداری در بار سنگین. حالت Multi نباید «Production Ready» اعلام شود تا این آزمون‌ها پاس شوند.

## نصب نسخهٔ یکپارچه بدون فعال‌سازی DNS

ابتدا همین ZIP افزونه را در `/root` استخراج کن. روی سرور فرانسه که DUC 0.10.5 نصب است:

```bash
cd /root
unzip -tq DNS-Unified-Control-v0.10.6-Multi-Engine-P1-Integrated.zip
unzip -oq DNS-Unified-Control-v0.10.6-Multi-Engine-P1-Integrated.zip
cd dns-unified-control
sudo bash install.sh --dry-run
```

دستور `--check` باید `COMPATIBILITY OK` برگرداند. در صورت هرگونه incompatibility به نسخهٔ قدیمی downgrade نکن؛ لاگ را برای اصلاح ادغام سورس ارسال کن.

برای اعمال فقط تغییرات **کد و منوی پنل** (نه پورت 53):

```bash
sudo bash install.sh
```

از تو `Install Multi-Engine add-on? [yes/no]` می‌پرسد. Backup فایل‌های تغییر‌یافته را زیر `/var/backups/dns-unified/duc-multi-*` نگه می‌دارد. `Agent` و `Web` دوباره بارگذاری و تست HTTP/Unix socket می‌شوند، اما DNS، Cloudflare، HTTPS، Xray، HAProxy و Dante دست‌نخورده می‌مانند.

## پیش‌بررسی اجرای هفت موتور (بدون تغییر)

```bash
cd /opt/dns-unified-control
sudo .venv/bin/python -m ducmulti.cli status
sudo .venv/bin/python -m ducmulti.cli plan --mode multi \
  --engines master,soar,cotten,slipstream,noizdns,dnstt,vaydns
```

به احتمال زیاد `ready=false` دیده می‌شود، چون روی فرانسه CottenDNS هنوز نصب/تنظیم نشده و SlipStream Rust نیز طبق گزارش پیشین آماده نبود. **در این حالت هیچ موتور یا پورت 53 تغییر نمی‌کند.** برای شش موتور قدیمی نیز تنها در صورت ready شدن همهٔ پیش‌شرط‌ها امکان آزمایش مرحله‌ای وجود دارد.

برای دیدن UI: Web بعد از ورود MFA در Sidebar دکمهٔ **Exclusive / Multi** دارد. در TUI گزینهٔ **9** در منوی اصلی اضافه می‌شود. همهٔ تغییرات نیاز به نمایش Plan و تأیید `yes` دارند.

## CottenDNS integration adapter (هنوز خودکار نیست)

هنگامی که CottenDNS با یک Unit قابل تأیید روی **UDP/TCP 127.0.0.1:5303** نصب شد، ساختار مورد انتظار در `/etc/dns-unified/cotten-adapter.json` چنین است:

```json
{
  "schema": "duc.cotten.adapter.v1",
  "zone": "t.YOUR_DOMAIN",
  "port": 5303,
  "unit": "cottendns.service"
}
```

این نمونه را بدون نصب/تطبیق واقعی CottenDNS و delegation مناسب اعمال نکن. اجرای installer عمومی CottenDNS با پورت 53 پیش‌فرض می‌تواند موتورهای DUC و DNS سرور را قطع کند. سرور Cotten باید TCP/53 داخلی را هم به جای 53 عمومی از طریق Router دریافت کند. فعال‌سازی کل هفت موتور تنها پس از آزمون مؤثر Adapter مجاز است.

## اتصال و امنیت

- حالت Exclusive پیش‌فرض فعلی حفظ می‌شود. Multi با TCP/UDP53 روی IPv4 اینترفیس واقعی VPS کار می‌کند. در AWS NAT، این همان IPv4 خصوصی `ens5` است، نه IPv4 عمومی EC2.
- روی پورت‌های داخلی فقط `127.0.0.1` مجاز است؛ Router و frontend 53 در preflight جلوی تداخل را می‌گیرند. خود Docker، HAProxy و Xray تغییر نمی‌کنند.
- Router به‌صورت Python asyncio با سقف درخواست‌های هم‌زمان، timeout و socket مجزا برای هر درخواست ساخته شده است. برای ترافیک سنگین باید با Router تخصصی بهینه‌شده جایگزین یا benchmark شود.
- بازگشت به حالت Exclusive یک کار تغییردهنده است و تست/تأیید مجدد می‌خواهد. در صورت قطع برق حین سوییچ، وضعیت را از پنل و `systemctl` بررسی کن؛ Rollback فقط برای شکست‌های کنترل‌شده است، نه تراکنش اتمیک سیستم‌عامل.
- موتورهای دارای SOCKS5 خام از Dante موجود استفاده می‌کنند؛ MasterDnsVPN بک‌اند خودش را دارد. تونل iodine و dns2tcp و XDNS به این فاز Multi افزوده نشده‌اند.
- **این افزونه گواهی HTTPS، Cloudflare یا A/NS دامنه را تغییر نمی‌دهد.** ابتدا نصب Web 0.10.5 را جداگانه به پایان برسان.

## مسیر ارتقای محصول

برای انتشار کامل و رسمی نسخهٔ بعدی، سورس واقعی ZIP نسخهٔ 0.10.5 لازم است تا همین ماژول بدون patch کنار Lifecycle Manager قرار بگیرد و Manifest و آزمون‌های پیشین حفظ شوند. در این بسته سورس کامل نسخهٔ 0.10.6 به‌همراه ماژول ادغام‌شده وجود دارد.
