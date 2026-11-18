# راهنمای NoizDNS و SlipNet — DNS Unified Control v0.9.6

## دو انتخاب مستقل برای NoizDNS

- **اول: SlipNet CLI v2.5.3، حالت `sayedns` و Stealth فعال**. کلاینت رسمی Go که خودش SOCKS5 محلی روی `127.0.0.1:2080` ارائه می‌دهد؛ Gateway یا سرویس اضافی لازم نیست.
- **دوم: DNSTT Native**. از همان سرور `anonvector/dnstt` و کلید عمومی NoizDNS استفاده می‌کند، اما **قابلیت اختصاصی Stealth را ندارد**. برای مقایسه و مواقعی که سازگاری DNSTT استاندارد کافی است.
- هر گزینه Job ساخت و ZIP دانلود خودش را دارد و ساخت هیچ‌کدام باعث Start، Stop یا تعویض موتور DNS سرور نمی‌شود. پیش از اجرای کلاینت جدید، کلاینت قبلی را از پورت 2080 خارج کن.

## ساخت بسته

در **کلاینت‌ها → NoizDNS** گزینه SlipNet یا DNSTT Native را انتخاب، Build و سپس ZIP مستقل آن را دانلود کن. باینری SlipNet از Release `v2.5.3 - CLI` با هش SHA-256 ثابت در کد تأیید می‌شود؛ GitHub مسیر اصلی و SourceForge فقط Mirror با **همان هش** است. هش منتشرشده توسط Mirror امضای دیجیتال upstream محسوب نمی‌شود. سرور و کلیدهای NoizDNS با نصب خودکار کنترل شده و کلید خصوصی وارد ZIP نمی‌شود.

## اجرای Native SlipNet با Resolver عمومی (بدون Direct Mode)

فایل `run-noizdns.sh` نسخه 0.9.6 اکنون Resolver را **صریحاً** با `--dns` به برنامه انتقال می‌دهد؛ به علت تشخیص نامناسب رکورد NS توسط upstream، در آزمایش نسخهٔ قبلی بدون `--dns` به اتصال مستقیم `188.132.174.249:53` برگشت. برای اجرای حالت Recursive:

```bash
cd ~/Downloads/noizdns-linux-amd64
chmod +x slipnet-linux-amd64 run-noizdns.sh
DUC_DNS_RESOLVER=1.1.1.1:53 DUC_CLIENT_PORT=2080 ./run-noizdns.sh
```

یا مستقیم با خود CLI:

```bash
URI="slipnet://$(base64 -w0 < slipnet-profile.txt)"
./slipnet-linux-amd64 --dns 1.1.1.1:53 --port 2080 "$URI"
```

پروفایل فقط اطلاعات عمومی (`domain`, `public key`, پارامترهای عمومی) دارد. نام کاربری/رمز Dante را در v2rayN، FoxyProxy یا ابزار SOCKS وارد کن؛ در اجرای آزموده‌شده نیازی به تزریق رمز در URI نبوده است. اسکریپت اختیاری `run-noizdns-inject-auth.sh` **صرفاً برای عیب‌یابی ویژه** است، چون اطلاعات ورودِ کدگذاری‌شدهٔ base64 می‌تواند در آرگومان پردازش قابل مشاهده باشد؛ آن را بدون ضرورت اجرا نکن.

## آزمون عملی و حدود نتیجه

در تاریخ 2026-11-07 روی Debian با SlipNet CLI `v2.5.3`:

1. دستور `ss` مالک `127.0.0.1:2080` را پردازش SlipNet نشان داد.
2. `tcpdump` درخواست‌های DNS TXT زیر دامنه `n.m2m.diy` به `1.1.1.1:53` را ثبت کرد، نه Direct Mode به IP VPS در فیلتر مشاهده‌شده.
3. `curl` از SOCKS5 پاسخ `HTTP/2 200` و IP خروجی `188.132.174.249` دریافت کرد.
4. اعتبارنامه اشتباه خطای `User was rejected by the SOCKS5 server` داد؛ درخواست بدون اعتبارنامه خطای `No authentication method was acceptable` داد.

در نتیجه اتصال Recursive DNS، HTTPS و کنترل ورود SOCKS5 در مسیر کار می‌کند. برای ادعای تأیید مستقلِ **Dante** لازم است لاگ سرویس Dante در VPS با زمان تست تطبیق داده شود. همچنین این آزمون تضمین مقاومت در برابر DPI نیست.

## وضعیت DNS و ایمنی

تفویض `n.m2m.diy NS ns.m2m.diy` در Cloudflare موجود است؛ درخواست NS عادی به DNS server تونل می‌تواند NXDOMAIN برگرداند و باعث خطای تشخیص خودکار SlipNet شود، هرچند پرس‌وجوهای مخصوص تونل کار کنند. رکورد Cloudflare را بدون دلیل عوض نکن؛ `--dns` صریح برای اجرای Recursive ضروری است.

Dante روی VPS فقط در `127.0.0.1:1080` می‌ماند و احراز هویت بر اساس تنظیمات فعلی ادامه دارد. فقط یک موتور در UDP/53 و فقط یک کلاینت روی پورت 2080 اجرا شود. کلید خصوصی NoizDNS، رمز Dante و توکن Cloudflare نباید در ZIP یا API عمومی قرار بگیرند. ساخت Windows در این نسخه انجام نمی‌شود.

منابع: https://github.com/anonvector/SlipNet و https://github.com/anonvector/dnstt؛ [معماری Web/TUI](UI_TUI_ARCHITECTURE_V096_FA.md).
