# نسخه 0.9.0 — Native SOCKS + Dante مشترک — راهنمای عملیاتی

## فلسفه

روی VPS یک Dante احرازهویت‌دار در `127.0.0.1:1080`، و فقط یک موتور DNS روی
`UDP/53` از طریق Exclusive Mode فعال است. موتورهای **raw TCP forwarding** که
نسخه مشخص و سازگاری‌شان اثبات شده، می‌توانند مقصد `127.0.0.1:1080` داشته باشند.

روی Debian **هیچ Gateway جداگانه‌ای** اجرا نمی‌شود. فقط کلاینت موتور فعال را روی
`127.0.0.1:2080` اجرا می‌کنیم؛ v2rayN / FoxyProxy با یوزرنیم/رمز **Dante سمت VPS**
به همان پورت وصل می‌شوند. نام کاربری/رمز در SOCKS URL صرفاً base64 است و نباید
افشا شود. UDP ASSOCIATE برای این مسیر raw TCP پشتیبانی نشده است.

اگر موتور انتخابی native SOCKS خودش دارد (Master)، امکان تغییر پورت کلاینت هست،
اما خودکار به Dante تزریق نمی‌شود مگر بالادستی سرور واقعاً dialer سازگار ارائه کند.
Soar مقصد را به‌صورت مستقیم انتخاب می‌کند و از نظر امنیتی اجازهٔ اتصال به Loopback
ندارد. iodine هم تونل IP است و اصولاً خروجی SOCKS بومی ندارد.

## ارتقای بی‌خطر

1. قبل از ارتقا با `systemctl list-units 'dns-unified@*.service' --state=running`
و `ss -lunp | grep ':53'` وضعیت را بگیر.
2. `bash upgrade.sh` از پوشهٔ استخراج‌شده؛ قبل از آن ZIP را آزمایش کن. این کار
بکاپ از کد می‌گیرد و سرویس وب/Agent را تازه می‌کند اما موتور فعال را Restart نمی‌کند.
3. با `PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.fieldcheck`
پیش‌نیازها و نتیجه تست‌های ثبت‌شده را بررسی کن.
4. **بدون تأیید دسترسی از مسیر جایگزین، موتور فعال SlipStream را بی‌دلیل تغییر نده.**

## اتصال DNSTT / VayDNS به همان Dante

در وب‌پنل: «راه‌اندازی و کلاینت‌ها» → Shared Dante → فقط DNSTT و VayDNS را انتخاب
کن → «اتصال به Dante». قبل از فعال‌سازی هر موتور، `check_ready` و اعتبار کلید
آن را بررسی کن. صرف ذخیره `target` به معنای تست موفق نیست. هنگام سوییچ، اتصال
کلاینت SlipStream قطع می‌شود؛ برای بازیابی دوباره انتخابش کن.

### DNSTT کلاینت

پس از ساخت بستهٔ دقیق DNSTT و استخراج روی Debian، دستور نمونه (کلید عمومی خودت
در راهنمای پنل است؛ اینجا تعمداً ساختگی است):

```
./dnstt-client -udp 1.1.1.1:53 -pubkey YOUR_SERVER_PUBLIC_KEY d.m2m.diy 127.0.0.1:2080
python3 duc_socks_probe.py --engine dnstt --port 2080 --repeat 5 --out dnstt-report.json
```

### VayDNS کلاینت

```
./vaydns-client -udp 1.1.1.1:53 -pubkey-file ./server.pub -domain v.m2m.diy -listen 127.0.0.1:2080
python3 duc_socks_probe.py --engine vaydns --port 2080 --repeat 5 --out vaydns-report.json
```

فقط یک کلاینت در هر زمان به `2080` متصل شود. Probe رمز Dante را بدون echo
می‌گیرد، TLS/HTTPS را واقعاً تست می‌کند، نتیجه را بدون رمز در فایل می‌نویسد.
روی VPS برای واردکردن آمار:

```
# First transfer the client report securely to /root/ on VPS.
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.telemetry import /root/dnstt-report.json
```

یا JSON را در بخش مانیتورینگ پنل بچسبان و «ثبت نتیجه واقعی» بزن. فقط از گزارش
دستگاه خودت استفاده کن؛ این گزارش به تنهایی قابل گواهی مستقل نیست.

## پورت دلخواه / Backend دلخواه

برای موتورهای دارای TCP Backend سه حالت وجود دارد:
* `dante`: اولویت اول، مقصد ثابت `127.0.0.1:1080`.
* `custom`: فقط یک موتور و فقط یک مقصد loopback، مثلا `127.0.0.1:1090`.
* `restore`: برگشت به مقصد قبلاً ذخیره‌شده؛ اگر بکاپ وجود نداشته باشد، fail closed.

Dante **نمونه جدید روی پورت سفارشی نصب نمی‌کند**؛ آن سرویس باید از قبل مستقل
ایجاد و امن شده باشد. حفظ پورت 2080 سمت کلاینت از ویژگی forwarding است، نه
Gateway؛ یک موتور انتخابی را Stop و موتور بعدی را Run کن.

## dns2tcp — معیار تست کامل

سرور: تنها برای تست از backend SSH استفاده کن؛ DNS2TCP فاقد رمزنگاری حمل است و
فرستادن رمز Dante به آن ناامن است. `dns2tcpd -h`، `/etc/dns-unified/engines/dns2tcp/server.conf`
و کلید خصوصی را چک کن. تونل را در Exclusive Mode فعال، روی کلاینت `dns2tcpc`
را با resource صحیح به SSH متصل کن و با یک فرمان `ssh` واقعی (نه فقط ssh-keyscan)
مذاکره KEX را تأیید کن. روی VPS دستور `python -m duc.fieldcheck` فقط audit می‌کند؛
سرور را سوئیچ نمی‌کند و نتیجه واقعی جعل نمی‌کند.

## Soar — محدودیت معماری

Soar در حالت استاندارد به مقصدهای عمومی با پورت‌های مجاز مستقیم وصل می‌شود؛
Dante خصوصی به عنوان raw TCP target جزو این معماری نیست. بخش امنیت پیش از تست:
کلید Ed25519، پورت‌های مجاز، zone delegation، و `soar-server` CLI را بررسی کن.
در تست، TCP به یک مقصد عمومی مجاز و تأیید TLS کلاینت را بررسی کن. به دلیل
امکان استفاده غیرمجاز از public key، default proxy عمومی را بی‌محابا فعال نکن.

## NoizDNS / XDNS

NoizDNS: توزیع‌های مختلف ممکن است از `dnstt-server` برای حالت NoizDNS استفاده
کنند، درحالی‌که پنل انتظار `noizdns-server` دارد. ابتدا upstream binary و wire
format را دقیق انتخاب و pin کن؛ نه ادعای ready بودن، نه Start خودکار از نام باینری.

XDNS: Xray FinalMask نوع `xdns` با mKCP استفاده می‌شود. بنابر مستندات Xray،
برای TXT مقدار server MTU نزدیک 900 و client حدود 130 پیشنهاد شده است، اما این
مقادیر universal نیست. ساخت server/client JSON و آزمون `xray run -test` برای هر دو
لازم است. فعلاً پشتیبانی بدون کانفیگ آزموده‌شده «ناقص» باقی می‌ماند.

## iodine — بهینه‌سازی و مقایسه

`client/iodine_benchmark.py` ده ترکیب DNS Resolver، نوع رکورد، Frag و Ping را
**یکی‌یکی** آزمایش می‌کند، با حداقل تداخل؛ رمز را بدون echo گرفته و وارد argv
نمی‌کند. اجرای آن روی Debian نیازمند root و یک سرویس iodine آماده در VPS است.

```
sudo python3 iodine_benchmark.py
```

گزارش، نرخ از دست رفتن ICMP/RTT روی IP تونل را نشان می‌دهد نه raw DNS query loss.
برای ثبت یک تست IP-سطح در پنل بعد از اتصال inode:

```
python3 duc_iodine_ping.py --peer 10.78.0.1 --count 12 --out iodine-icmp.json
```

پیش از اعلام «بهترین موتور»، برای همه موتورها از شرایط DNS یکسان، اندازه انتقال
یکسان و چند نوبت تست استفاده کن. `api.ipify.org` فقط اتصال/RTT را مشخص می‌کند و برای پاسخ کمتر از ۶۴ کیلوبایت Throughput در پنل خالی می‌ماند؛
برای مقایسه throughput واقعی باید یک HTTPS payload بزرگ‌تر با URL یکسان و
`duc_socks_probe.py --url` اندازه‌گیری شود.

## آمار پنل: تعریف دقیق

* `CPU/RAM`: نمونهٔ واقعی VPS؛ `RX/TX`: جمع کل اینترفیس‌ها، نه مختص DNS engine.
* `SOCKS RTT`: روی دستگاه کلاینت شامل TCP + احراز هویت + SOCKS CONNECT.
* `HTTP Throughput`: بایت‌های بدنه پاسخ HTTPS بر ثانیه، نه بیت‌های DNS روی wire.
* `request_failure_pct`: درصد درخواست‌های ناموفق HTTPS/SOCKS؛ **نه Packet Loss**.
* `icmp_packet_loss_pct`: فقط برای تونل IP (iodine)، روی پینگ tunnel-peer.
* `raw_dns_packet_loss_pct`: بدون exporter پایین‌سطح موتور، نامشخص می‌ماند.

وضعیت واقعی v0.9.0 در VPS تو بعد از ارتقا باید دوباره تأیید شود. تست‌های محلی
پایتون جایگزین تست انتها-به-انتها در شبکه نیستند.
