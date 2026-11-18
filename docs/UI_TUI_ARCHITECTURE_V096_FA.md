# معماری رابط Web و TUI آینده — DNS Unified Control v0.9.6

## اصول ثابت

1. **Engine**: برنامهٔ سروری روی VPS که روی UDP/53 به DNS پاسخ می‌دهد. در هر لحظه فقط یک Engine فعال (Exclusive Mode). Start/Stop/Restart فقط در `duc.core` و مسیر کنترل موتور انجام می‌شود.
2. **Client implementation**: برنامهٔ سمت Debian/Windows که به همان Engine وصل می‌شود. انتخاب Client به معنی تغییر Engine یا نصب Backend نیست. کلاینت‌های Native و SlipNet با یک سرور در برخی موتورها جایگزین یکدیگر هستند؛ **هم‌زمان روی یک پورت محلی اجرا نمی‌شوند**.
3. **Backend**: Dante مشترک احرازهویت‌دار در `127.0.0.1:1080` روی VPS. این یک سرویس مستقل systemd است، نه موتور DNS. کنترل آن و اتصال Backend موتورهای TCP در صفحه جدا انجام می‌شود. هیچ Gateway سمت کلاینت وجود ندارد.
4. **DNS delegation**: Cloudflare و `ns.<domain>` زیرساخت مستقل از Engine/Client است؛ موفقیت NS به معنی موفقیت تونل نیست.
5. **Job/Artifact**: ساخت باینری یا نصب موتور عملیات جداگانه، قابل نظارت و بدون Start خودکار موتور است. Job موفق یعنی فایل ساخته شده؛ نه اینکه شبکهٔ بیرون آزمایش شده باشد.
6. **Test evidence**: `ready` (آمادگی سرور)، `built` (وجود بسته)، `tested` (نتیجه مستند) و `active` (وضعیت systemd) چهار مفهوم مجزا هستند و نباید در UI با هم یکی شوند.

## ساختار منو

| دسته | صفحه | مسئولیت مشخص |
|---|---|---|
| نمای کلی | داشبورد | وضعیت سیستم و موتور فعال |
| تونل و کلاینت | کنترل موتورها | Exclusive Mode / انتخاب و توقف موتور |
| تونل و کلاینت | پروفایل موتور | پارامترهای سروری و کلاینت متناظر |
| تونل و کلاینت | کلاینت‌ها | انتخاب Native یا SlipNet، ساخت، دریافت و تست |
| تونل و کلاینت | پروتکل‌ها | قابلیت‌ها و محدودیت‌های موتور |
| زیرساخت | Dante · SOCKS5 | سلامت، نصب/بررسی، اتصال موتورهای TCP و backend loopback سفارشی |
| زیرساخت | DNS و دامنه‌ها | رکوردها/NS و آزمون DNS |
| زیرساخت | نصب و سلامت | Provision و پیش‌نیازهای VPS |
| نظارت | مانیتورینگ/گزارش‌ها | داده واقعی و لاگ |
| امنیت | TOTP | امنیت ورود به پنل |

## ماتریس کلاینت‌ها در این نسخه

| سرور DNS | کلاینت اول | کلاینت دوم | نتیجهٔ آزمایش |
|---|---|---|---|
| DNSTT | Native DNSTT | SlipNet DNSTT | Native آزموده شده؛ SlipNet با این VPS هنوز تأیید نشده |
| NoizDNS | SlipNet `sayedns` + Stealth | DNSTT استاندارد، بدون Stealth | هر دو در آزمایش کاربر؛ اجرای SlipNet با Resolver عمومی و SOCKS5 تأیید شد |
| VayDNS | Native VayDNS | SlipNet VayDNS | Native آزموده شده؛ SlipNet نیازمند تست متناسب با wire-format/ClientID |
| SlipStream Rust | Native Rust | — | SlipNet CLI نسخه 2.5.3 از `slipstream` پشتیبانی عملیاتی ندارد |
| Soar | Native Soar | — | سرور محدودشده به Dante؛ SlipNet جایگزین بدون بررسی جداگانه ارائه نمی‌شود |
| MasterDnsVPN | Native Master | — | SOCKS داخلی مستقل؛ کلید اشتراکی محرمانه در بسته Master |
| iodine | iodine | — | IP-over-DNS؛ SOCKS5 عمومی تلقی نمی‌شود |
| dns2tcp | dns2tcp | — | رمزنگاری ندارد؛ اعتبارنامه Dante را بی‌حفاظ داخل آن منتقل نکن |
| XDNS | Xray | — | تنظیمات باید با نسخه واقعی Xray تطبیق داده شوند |

**مهم:** SlipNet/NoizDNS 2026-11-07 با Resolver `1.1.1.1:53`، IP خروجی VPS، HTTPS 200 و پذیرش/رد اعتبارنامه SOCKS5 از سمت کلاینت آزموده شد. **ثبت مستقل لاگ احراز هویت Dante روی VPS انجام نشده**. قابلیت Stealth به معنای مصونیت اثبات‌شده در برابر DPI نیست.

## یک منبع حقیقت برای Web و TUI

```
                    core (engine state/config/switch)
                         |
  client_catalog (engine -> client choices / capabilities)
                         |
     jobs + worker (install/build/ZIP by engine & variant)
                         |
     unified + dante (one authenticated SOCKS backend)
                         |
              agent (Unix socket + fixed API)
                         |
              +---------------------+
              |                     |
          Web facade            Future TUI
         (MFA + CSRF)       (authorized local UI)
```

- `duc/catalog.py`: موتورهای موجود، دامنه‌های تفویضی و مشخصات ثابت سرور.
- `duc/client_catalog.py`: **registry مشترک** برای گزینه‌های کلاینت. هیچ تصمیم سازگاری کلاینت نباید فقط در HTML تعریف شود.
- `duc/core.py`: وضعیت، پروفایل، قفل و سوئیچ Exclusive Mode.
- `duc/jobs.py`: Job ثابت و محافظت‌شده، صف و مسیر Artifact. `build-client` و `build-alternate` مستقل‌اند.
- `duc/worker.py`: Build اجرایی و بسته‌بندی؛ از انتخاب Client تا استارت موتور نباید وابستگی پنهان وجود داشته باشد.
- `duc/unified.py`, `duc/dante.py`: Backend مستقل و ارتباط موتورهای سازگار.
- `duc/workflow.py`: راهنمای مبتنی بر مشخصات عمومی، بدون کلید خصوصی و توکن.
- `duc/agent.py`: کنترل مرکزی با Unix socket؛ وب و TUI باید یک منطق اعتبارسنجی را صدا بزنند.
- `duc/web.py`: فقط احراز هویت/MFA، CSRF و proxy ایمن به Agent؛ منطق ساخت باینری در Web ممنوع.
- `web/app.js`: صرفاً نمایش/انتخاب؛ نباید به‌شکل مستقل تشخیص بدهد کدام کلاینت با کدام سرور سازگار است.

## قراردادهای UI برای TUI آینده

برای گزینه‌ها: `GET /workflow/client/options/{engine}` در Agent یا `GET /api/workflow/client/options/{engine}` پس از ورود به Web. برمی‌گرداند: `engine`, `default`, `choices[]` شامل `id`, `kind`, `tested`, `note`، و `exclusive_dns`.

برای Jobها:

- Client اصلی: `build-client / ENGINE`
- Client دوم: `build-alternate / ENGINE` (فعلاً فقط `dnstt`, `noizdns`, `vaydns`)
- نصب سرور: `install-server / ENGINE` برای موتورهای نصب‌پذیر
- نصب Dante (مسیر استاندارد): `setup-dante / dante`. مسیر قدیمی `install-dante / slipstream` فقط برای سازگاری با کلاینت‌های قدیمی باقی مانده و در Web جدید استفاده نمی‌شود.

این‌ها از `jobs.ACTIONS` و `jobs.info()` تغذیه می‌شوند و stateهای مستقل دارند: `not-started`, `queued`, `running`, `succeeded`, `failed`.

مسیر Artifactها متفاوت است:

- `client-artifacts/ENGINE-linux-amd64.zip`
- `client-artifacts/ENGINE-alternate-linux-amd64.zip`

هر دو از طریق مسیرهای دانلود احرازهویت‌شده و با اعتبارسنجی Job تحویل می‌شوند؛ ZIP راهنما باینری نیست. بسته NoizDNS ساخته‌شده در نسخه‌های قدیمی به عنوان `stale` علامت می‌خورد؛ برای اجرای launcher جدید لازم است دوباره ساخته شود.

TUI آینده باید `client_catalog`, `core`, `unified`, `jobs` و همان Agent routeها را مصرف کند. نیازی به خواندن CSS، استخراج گزینه‌ها از JavaScript یا بازنویسی Ruleهای Compatibility ندارد. TUI با دسترسی‌های محدود به Agent و برای کارهای Privileged از Job ثابت استفاده خواهد کرد، نه Shell دلخواه.

## رفتار هنگام ارتقا

`bash upgrade.sh` از سورس پنل فعلی پشتیبان می‌گیرد و دوباره نصب می‌کند. سرویس وب و Agent برای بارگذاری کد جدید راه‌اندازی مجدد می‌شوند، **اما موتور فعال DNS را تغییر نمی‌دهد**. سورس و کلیدهای موجود NoizDNS/Soar حفظ و اعتبارسنجی می‌شوند. نصب کل همه موتورها همچنان opt-in است.

## محدودیت‌های دانسته

- ساخت خودکار ZIP در این نسخه فقط **Linux amd64** است. ماتریس سازگاری منطق کلاینت با حمایت رسمی SlipNet از Windows یکی نیست و Windows هنوز در پنل Build نشده است.
- NoizDNS/SlipNet پروفایل عمومی را از کلاینت CLI جدا می‌کند. `run-noizdns.sh` اکنون `--dns` را صریح ارسال می‌کند؛ متغیرهای `DUC_DNS_RESOLVER` و `DUC_CLIENT_PORT` اختیاری‌اند.
- تعویض رمز Dante، کنترل کاربران و مدیریت کامل Dante از داخل پنل هنوز به گردش امن جداگانه نیاز دارند؛ رمز نه داخل Web API بازگردانده و نه در ZIP جاسازی می‌شود.
- کاربر باید پس از تغییر کلاینت، خود پردازش قبلی روی `2080` را ببندد. Exclusive Mode فقط سمت VPS است.


## اصلاح بازبینی در نسخهٔ 0.9.7

پارامترهای Resolver/Port هنگام درخواست ساخت کلاینت از Web/Agent اعتبارسنجی می‌شوند، در Job ذخیره می‌شوند و به بستهٔ خروجی منتقل می‌گردند؛ TUI آینده از همان قرارداد `resolver` و `port` استفاده می‌کند. بسته‌های قدیمی NoizDNS/کلاینت جایگزین در وضعیت `stale` قرار می‌گیرند تا با تنظیمات نامشخص تحویل داده نشوند.
