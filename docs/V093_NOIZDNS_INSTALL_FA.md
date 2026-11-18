# DNS Unified Control v0.9.3 — NoizDNS server bootstrap

## مهم: نصب سرور در installer، نه در UI کلاینت

`install.sh` و `upgrade.sh` بعد از Soar، `python -m duc.install_noizdns` را **اجباری** اجرا می‌کنند. در صورت شکست باینری/کلید، نصب با exit 1 پایان می‌یابد و موتور فعال DNS قطع/تعویض نمی‌شود.

سرور از `https://github.com/anonvector/dnstt` ساخته می‌شود، نه از مخزن قدیمی `net2share/dnstt` و نه از اسکریپت نصب جایگزین که خودش سرویس/فایروال/Dante ایجاد کند. خروجی تحت `/usr/local/bin/noizdns-server` است؛ `dnstt-server` موجود سر جای خود می‌ماند.

نسخه/commit منبع در گزارش نصب و `/var/lib/dns-unified/noizdns-server-build.json` ثبت شده است؛ SHA256 باینری و منبع بازبینی می‌شود. کلید خصوصی `noizdns.key` (X25519، مجوز `0600`) و کلید عمومی متناظر `noizdns.pub` زیر `/etc/dns-unified/keys/` تولید و حفظ می‌شوند. کلید خصوصی و رمز Dante وارد وب‌پنل یا بسته کلاینت نمی‌شوند. اگر کلید عمومی موجود با کلید خصوصی نخواند، نصب خطا می‌دهد، کلید خصوصی را عوض نمی‌کند.

مقصد جدید پیش‌فرض `127.0.0.1:1080` همان Dante مشترک با username/password است. اگر پروفایل قدیمی هنوز دقیقاً `127.0.0.1:22` باشد، فقط همین مقدار NoizDNS به `1080` منتقل و مقصد قبلی برای Restore ذخیره می‌شود. مقادیر سفارشیِ Loopback حفظ می‌شوند. هیچ Gateway پایتونی در سمت کاربر وجود ندارد.

## روی VPS بعد از ارتقا

```bash
PYTHONPATH=/opt/dns-unified-control \
/opt/dns-unified-control/.venv/bin/python -m duc.install_noizdns --check

PYTHONPATH=/opt/dns-unified-control \
/opt/dns-unified-control/.venv/bin/python -m duc.unified status
```

بعد از تأیید سرور و DNS delegation `n.m2m.diy`، NoizDNS را فقط از پنل در Exclusive Mode فعال کن.

## وضعیت کلاینت

NoizDNS در مسیر فعلی نسخه `anonvector` به‌صورت تغییر encoding/stealth در کلاینت است. `dnstt-client` معمولی یا نسخهٔ `dnstt-client` داخل این مخزن **اثبات نمی‌کند** که حالت NoizDNS فعال است. پیاده‌سازی NoizDNS در SlipNet وجود دارد، اما رابط بومی Linux بدون Gateway و انتقال احراز هویت Dante به‌صورت مستقیم هنوز در این پروژه تست واقعی نشده و دانلود خودکار کلاینت NoizDNS در پنل عمداً غیرفعال است. تا نسخه کلاینت آزمایش نشود، وضعیت E2E آن را PASS نزن.

**محدودیت تست:** در محیط بسته‌سازی ما اینترنت به GitHub در دسترس نبود.  تست‌های خودکار کد شامل صحت مسیر نصب، سازگاری CLI runner، مقداردهی باینری، هویت X25519، مجوزها، migration و حفظ موتور فعال است؛ کامپایل واقعی باید روی VPS انجام شود.

Upstream: https://github.com/anonvector/dnstt  |  https://github.com/anonvector/slipgate
