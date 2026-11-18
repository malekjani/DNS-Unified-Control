# DUC Multi Client + Relay — P0 اثبات ایده (v0.11.0-dev)

> **Experimental, not production-ready.** این کد بخشی از شاخهٔ اصلی GitHub نیست و هیچ تنظیمی را روی سرور شما تغییر نمی‌دهد.

## چرا ساخته شد؟

DUC 0.10.6 در Multi فقط DNS را بر اساس Zone به موتورهای فعال هدایت می‌کند. این P0 نخستین نمونهٔ مستقل **Bonding واقعی یک جریان TCP** روی چند تونل TCP است، نه صرفاً Load Balancing اتصال‌ها.

معماری:

```
App/FoxyProxy -> 127.0.0.1:2080 [DUC client Go]
                  |        |
             path TCP #0  path TCP #1 ...  (local DNS-engine clients)
                  |        |
             DNS router on VPS UDP/TCP :53 + dedicated engine loops
                  |        |
                TCP forward to 127.0.0.1:2090 [DUC relay Go]
                                  |
                      authenticated Dante 127.0.0.1:1080
                                  |
                               Internet
```

برنامه **کلاینت بومی موتورهای DNS را هنوز نصب یا اجرا نمی‌کند**؛ آنها باید جداگانه در پورت‌های محلی مستقل فعال باشند. هر مسیر باید **TCP خام به 2090 سرور** بدهد، نه SOCKS5 کلاینتی. برنامه فقط Loopback گوش می‌دهد و از STD library زبان Go استفاده می‌کند.

**سازگاری سرور فعلی:** در DUC 0.10.6 معمولاً `target` موتورهایی مثل DNSTT برابر Dante (`127.0.0.1:1080`) است. بنابراین برای استفاده از این Relay باید در آینده، فقط در حالت Bonding، مقصد سمت سرور موتورهای دارای TCP خام را به `127.0.0.1:2090` تنظیم کنیم. این کار **هنوز در P0 انجام نشده است** و نباید دستی روی VPS عملیاتی انجام شود. MasterDnsVPN/Soar/CottenDNS نیازمند آداپتور یا تأیید سازگاری جداگانه‌اند.

## چیزی که امروز واقعاً تست شده

- یک SOCKS5 CONNECT محلی (بدون احراز هویت، فقط روی 127.0.0.1).
- جداسازی یک اتصال به frameهای DATA با offset سراسری؛ رفت و برگشت هم‌زمان از چند TCP path.
- بافر محدود ۴ MiB برای out-of-order و بازسازی صحیح ترتیب TCP.
- HMAC-SHA256 در پیام JOIN برای اتصال کلاینت به Relay؛ کلید مشترک در فایل خصوصی.
- Relay با egress احرازشده Dante؛ حالت direct فقط برای آزمایش محلی.
- تست End-to-End با **دو forwarder ساختگی TCP** و echo server و آزمون race؛ دو مسیر مستقل در هر دو طرف از پروتکل عبور می‌کنند.

## وضعیت محدودیت‌ها

- **هنوز ACK سراسری و retransmit روی مسیر جایگزین وجود ندارد.** قطع یک مسیر وسط انتقال باعث قطع‌کردن ایمن کل session می‌شود؛ failover واقعی در فاز بعدی.
- scheduler فعلاً Round Robin است؛ RTT/Packet Loss، سهمیه ظرفیت، adaptive congestion control و FEC ندارد.
- رمزنگاری application-level ندارد؛ امنیت محرمانگی داده به موتورهای DNS زیرین و TLS کاربردی وابسته است. به همین دلیل اجرای عمومی یا tunnelهای بدون رمزنگاری توصیه نمی‌شود.
- quota و محدودیت تعداد session، کنترل backpressure تفکیکی، تشخیص حمله replay پس از پایان session و تست فشار تولیدی ندارد.
- SOCKS5 فقط TCP CONNECT را اجرا می‌کند. UDP ASSOCIATE/BIND و TUN پشتیبانی نمی‌شوند.
- هیچ systemd، پنل، Cloudflare، NS delegation یا سوییچ موتور در این بسته تغییر نمی‌کند.

## ساخت و تست بدون نیاز به سرور

به Go نسخه ۱.۲۳ یا جدیدتر نیاز داریم.

```bash
go test ./...
go test -race ./...
go build -trimpath -o duc-multi ./cmd/duc-multi
```

تست `TestTwoPathsOneSOCKSStream` دو مسیر TCP محلی مستقل ایجاد می‌کند، از طریق SOCKS5 به یک echo server وصل می‌شود و صحت بازسازی داده را بررسی می‌کند.

## نحوه اجرای P0 در محیط آزمایشی ایزوله (نه سرور عملیاتی)

ابتدا یک secret طولانی و تصادفی روی هر دو سمت با مجوز 0600 آماده کنید (همان مقدار در هر دو سمت و خارج از Git). نمونه روی Linux:

```bash
umask 077
openssl rand -hex 32 > /tmp/duc-p0-secret
```

روی Relay آزمایشی با Dante فعال و معتبر:

```bash
./duc-multi --mode server --listen 127.0.0.1:2090 \
  --secret-file /tmp/duc-p0-secret \
  --egress-socks 127.0.0.1:1080 \
  --egress-user YOUR_DANTE_USER \
  --egress-pass-file /path/to/private/dante-password.txt
```

روی کلاینت که **دو کلاینت موتور بومی با forward خام به Relay** از قبل آماده‌اند:

```bash
./duc-multi --mode client --listen 127.0.0.1:2080 \
  --paths 127.0.0.1:21001,127.0.0.1:21002 \
  --secret-file /tmp/duc-p0-secret
```

> توجه: این دستورات «یک نمونهٔ آزمایشگاهی قابل اجرا» هستند، **نه راهنمای آماده وصل‌کردن موتورهای DUC 0.10.6**. سازوکار تغییر مقصد موتور در Multi و تولید پکیج کلاینت در نسخه‌های بعدی باید اضافه شوند.

## قدم بعدی در پروژه اصلی

1. رابط `MultiTransportAdapter` برای هر موتور، ثبت دقیق نوع native raw TCP / native SOCKS5 / IP tunnel و آمادگی واقعی هر مسیر.
2. اتصال امن Relay به کنترل‌کننده `ducmulti` به‌صورت **opt-in bonding** با snapshot/rollback مستقل؛ نباید Exclusive و Multi P1 را تخریب کند.
3. پروتکل پایدار با DATA ACK، send window، deduplication، retransmit و نگهداری session در هنگام شکست یک مسیر.
4. scheduler تطبیقی براساس RTT، نرخ تحویل، نرخ خطا و هزینه DNS و انتخاب ظرفیت مناسب هر موتور؛ ارسال و دریافت schedulerهای جدا دارند.
5. ایجاد یک کلاینت بسته‌بندی‌شده Go/Rust که برنامه‌های engine را خودش از manifest تأییدشده start/stop و healthcheck کند؛ همچنان فقط یک listener عمومی در 2080.
6. تست واقعی روی دو موتور سازگار، سپس سه موتور، و در آخر بررسی تک‌به‌تک هفت موتور. پارامترهای عملی باید از upstream همان binary خوانده و validate شوند.

## مفاهیم اصلی

`Join` = احراز هویت هر مسیر متعلق به یک نشست، `DATA(offset)` = قطعه جریان در موقعیت سراسری، `FIN(offset)` = پایان نیمهٔ جریان. هر دو جهت، با شمارنده و بازساز مستقل کار می‌کنند. صورتِ این طراحی از ایدهٔ شماره‌گذاری داده‌های سراسری در Multipath TCP الهام می‌گیرد اما **پیاده‌سازی MPTCP نیست**.
