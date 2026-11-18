# DNS Unified Control — قواعد محصول و نصب مستقل (v0.10.0)

## نصب مستقل و چندسروری

هر VPS یک Instance جداگانه دارد: `/etc/dns-unified/instance.json` حاوی UUID، دامنه، IPv4 عمومی و FQDNهای پنل و NS (بدون راز). رمز ادمین، TOTP، کلیدهای هر موتور و حساب‌های Dante مستقل از این فایل و مختص همان سرور هستند.

```bash
unzip -tq DNS-Unified-Control-v0.10.0-Portable-Foundation.zip
unzip -oq DNS-Unified-Control-v0.10.0-Portable-Foundation.zip
cd dns-unified-control
bash scripts/fresh-install.sh --audit --domain EXAMPLE.COM --ip PUBLIC_IPV4
sudo bash scripts/fresh-install.sh --install --domain EXAMPLE.COM --ip PUBLIC_IPV4
```

دستور `--audit` فقط بررسی است. نصب باید در ترمینال مدیریتی اجرا شود، پس از Confirm هویت سرور ایجاد می‌شود. Resume فقط روی **همان** دامنه و IP قبلی اجازه دارد. اگر IP سرور بعداً تغییر کرد، به‌جای دستکاری `instance.json` باید فرآیند Migration اختصاصی ساخته شود؛ Resume ابزار جابه‌جایی IP نیست.

## مرز نصب

- نصب فعلی از `apt` و `systemd` و مسیرهای استاندارد ثابت `/opt/dns-unified-control`, `/etc/dns-unified`, `/var/lib/dns-unified` استفاده می‌کند. Ubuntu 24.04 / Debian 12/13 هدف اولیه هستند؛ نسخه‌های دیگر تا آزمون مستقل تضمین ندارند.
- تکمیل نصب هر ۹ موتور تضمین نیست: SlipStream سنگین و XDNS نیازمند آماده‌سازی/بررسی جداگانه‌اند. نصب پایه شامل سرویس پنل، Agent و provisioning موتورهای Soar/NoizDNS است. هیچ موتور UDP/53 خودکار فعال نمی‌شود.
- `install.sh` برای نصب پایه است؛ برای نصب جدید از wrapper ارزیابی‌شدهٔ `scripts/fresh-install.sh` استفاده کن. ارتقا `upgrade.sh` است؛ روی نصب جدید اشتباهاً ارتقا اجرا نکن.
- Cloudflare و Caddy اختیاری‌اند. `fresh-cloudflare-cutover.py` در حالت پیش‌فرض Dry-run است و برای تغییر هر رکورد به `--domain`, `--from-ip`, `--to-ip`, `--apply` و تأیید دقیق نیاز دارد.
- یک دامنه را هم‌زمان برای دو سرور به‌شکل مستقل استفاده نکن؛ واگذاری NS هر زیردامنه به یک IP می‌رسد. برای اجرای موازی از زیرساخت DNS مستقل یا migration کنترل‌شده استفاده کن.
- در نصب تازه هویت رمزنگاری جدید ساخته می‌شود؛ بدون کلیدهای قبلی، فایل‌های کلاینت قبلی معتبر نیستند. تا انتهای مهاجرت سرور قدیمی و کلاینت‌های قبلی را نگه‌دار.
- TUI و Web فقط کنترل‌کننده‌های یک Agent هستند. هیچ Gateway سمت کلاینت افزوده نمی‌شود؛ Dante فقط loopback و احرازهویت‌دار است.

## تضمین‌ها و محدودیت‌ها

- تست‌های خودکار فقط رفتار کد روی محیط توسعه را می‌سنجند؛ نصب روی توزیع/Provider دیگر، شبکه فایروال، DNS، TLS و موتورهای خاص باید جدا بررسی شوند.
- هنوز DEB/RPM رسمی، install atomic، rollback خودکار کل VPS، و آزمون end-to-end در CI برای همه موتورها وجود ندارد. این موارد برای محصول پایدار 1.0.0 لازم‌اند.
- Credential/Tokenها را در `instance.json` یا آرگومان command line ذخیره نکن. هیچ رمز خصوصی نباید در ZIP کلاینت عمومی قرار گیرد.

## دستور انتقال DNS مشروط و ایمن

```bash
python3 scripts/fresh-cloudflare-cutover.py --domain EXAMPLE.COM --label panel --from-ip OLD_PUBLIC_IPV4 --to-ip NEW_PUBLIC_IPV4
# بعد از Dry-run و تست readiness و backup، فقط در صورت تصمیم آگاهانه --apply
```

این ابزار فقط یک رکورد A مدیریت‌شده با marker را تغییر می‌دهد، NSها را دست نمی‌زند و ممکن است روی DNS موجود بدون marker اجرا را رد کند؛ این رفتار حفاظتی است.
