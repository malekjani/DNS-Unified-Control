# اصلاح مدیریت SlipStream از پنل — v0.7.0 Webfix

این اصلاح بر پایه `DNS-Unified-Control-v0.7.0-AliRezaBeigy-SlipStream.zip` ساخته شده است.
نسخه نمایشی `0.7.0` حفظ شده و دیگر نیازی به تایپ `yes` در نصب‌کنندهٔ Shell نیست.

## ارتقا با ZIP

```bash
cd /root
unzip -tq DNS-Unified-Control-v0.7.0-SlipStream-Webfix.zip
unzip -oq DNS-Unified-Control-v0.7.0-SlipStream-Webfix.zip
cd /root/dns-unified-control
bash upgrade.sh
```

اسکریپت ارتقا از کد قبلی نسخهٔ پشتیبان می‌سازد، وب و Agent را برای بارگذاری کد جدید restart می‌کند، اما **موتور فعال DNS را متوقف یا تعویض نمی‌کند**. تنظیمات، کلیدها، گواهی‌ها، MFA و DNS دست‌نخورده می‌مانند.

## نصب و مدیریت از پنل

1. در `https://panel.m2m.diy` ورود کامل رمز و TOTP را انجام دهید.
2. بخش `راه‌اندازی و کلاینت‌ها` را باز کنید؛ SlipStream را انتخاب کنید.
3. Preflight منابع RAM، CPU، Swap، دیسک، نسخهٔ ثابت AliRezaBeigy، وضعیت تأیید باینری‌ها و موتور فعال را ببینید.
4. در صورت نیاز، `نصب SlipStream از پنل` را بزنید و تأیید مرورگر را انجام دهید. عملیات در یک Job با آرگومان ثابت اجرا می‌شود و پیشرفت آن در پنل قابل مشاهده است.
5. اگر هر دو باینری قبلاً نصب و تأیید شده‌اند، پنل `بازبینی صحت بسته SlipStream` را نشان می‌دهد و نصب مجدد لازم نیست.
6. `ساخت بسته کلاینت` یک عملیات جداست؛ روشن‌کردن سرور هم فقط با Start/Switch موتور در کنترل سرور انجام می‌شود.

## مسیر Shell

```bash
# فقط بررسی سخت‌افزار / نصب — بدون تغییر سرویس فعال
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.slipstream_ali --preflight

# فقط در صورت نیاز به نصب یا تأیید دوبارهٔ باینری‌های نسخه‌ثابت
bash /opt/dns-unified-control/scripts/install-slipstream-ali.sh

# اعتبارسنجی دو باینری نصب‌شده
PYTHONPATH=/opt/dns-unified-control /opt/dns-unified-control/.venv/bin/python -m duc.slipstream_ali --verify
```

هیچ دستور `yes` لازم نیست؛ اجرای صریح نصب‌کننده در CLI به معنای درخواست نصب است.

## اصول عدم تداخل

- باینری‌ها فقط از Release پین‌شده AliRezaBeigy گرفته می‌شوند و SHA-256 بررسی می‌شود.
- نصب‌کننده، اسکریپت Deploy بالادستی را اجرا نمی‌کند و مستقل از پنل systemd، NAT، iptables، Caddy، DNS 53 یا فایل‌های تنظیمات شبکه را تغییر نمی‌دهد.
- کلید خصوصی TLS به فایل کلاینت راه نمی‌یابد.
- وضعیت سخت‌افزار و وجود باینری‌ها، جدا از آخرین وضعیت Job نصب نمایش داده می‌شوند.
- اگر باینری موجود از نظر هش با Release پین‌شده ناسازگار باشد، نصب با خطا متوقف می‌شود و فایل موجود بازنویسی نمی‌شود.
- نصب موتور به معنی تست اتصال واقعی DNS از کلاینت نیست. برای تست شبکه باید موتور را جداگانه در Exclusive Mode فعال کنید.

## کنترل بعد از ارتقا

```bash
systemctl is-active dns-unified-web.service dns-unified-agent.socket caddy
systemctl list-units --type=service --state=running 'dns-unified@*.service' --no-pager
curl -4sS -o /dev/null -w 'HTTP %{http_code} | SSL %{ssl_verify_result}\n' https://panel.m2m.diy/
```
