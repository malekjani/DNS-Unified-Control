# DNS Unified Control — TUI عملیاتی v0.9.8

TUI نسخهٔ 0.9.8 یک رابط **متنی/منویی واقعی** و یک CLI ساده روی خود VPS است. به سیستم عامل root یا کاربری که دسترسی مجاز به Unix Socket گروه `dns-unified` دارد نیاز دارد. نه پورت HTTP جدید باز می‌کند، نه کلید/رمز Dante را چاپ می‌کند، و نه مستقیم `systemctl` را اجرا می‌کند.

## پیش‌نیاز و راه‌اندازی

```bash
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh
```

دستورات غیرتعاملی (برای مانیتورینگ و اسکریپت‌های آینده):

```bash
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh status
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh --json status
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh dante
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh clients noizdns
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh jobs noizdns
```

`duc-tui.sh` از هر پوشه‌ای قابل اجراست و برای ارتباط با Agent از `/run/dns-unified-agent.sock` و از کتابخانهٔ استاندارد Python استفاده می‌کند. نیازی به `requests`, `curses`, Node.js یا TOTP ورود وب ندارد؛ دسترسی محلی با مجوز فایل Socket کنترل می‌شود. **اگر یک کاربر را به گروه `dns-unified` اضافه کنی، همان کاربر به عملیات سطح root Agent دسترسی پیدا می‌کند؛ این گروه را فقط به مدیرهای معتمد بده.**

## تغییر موتور (تعاملی و پرخطر)

```bash
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh switch noizdns
```

TUI ابتدا وضعیت `readiness` را بررسی کرده و برای سوئیچ عبارت تأییدی دقیق `SWITCH noizdns` را درخواست می‌کند. `switch none` برای توقف همهٔ موتورها، تأیید `STOP DNS` می‌خواهد. **از SSH جداگانه و مستقل از تونل DNS استفاده کن.** تغییر موتور اتصالات جاری را قطع می‌کند؛ جایگزینی کلاینت به‌شکل خودکار انجام نمی‌شود. Rollback همان منطق Agent/Web در `duc.core` است.

## ساخت دو نوع کلاینت

```bash
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh build noizdns slipnet --resolver 1.1.1.1:53 --port 2080
sudo bash /opt/dns-unified-control/scripts/duc-tui.sh build noizdns dnstt --resolver 8.8.8.8:53 --port 2233
```

انتخاب نوع کلاینت به رجیستری مشترک `duc.client_catalog` وابسته است؛ Jobهای `build-client` و `build-alternate` مستقل می‌مانند. TUI Job را شروع می‌کند اما باینری را به‌صورت خودکار اجرا نمی‌کند. پس از موفقیت، ZIP را از پنل وب **پس از ورود با MFA** دانلود کن. ساختن ZIP موتور را Start نمی‌کند.

## خلاصه سلامت یکسان برای وب و TUI

Agent: `GET /workflow/readiness`
Web: `GET /api/workflow/readiness` (نیازمند لاگین + MFA)

قرارداد `schema=1` شامل این موارد است: `exclusive_healthy`, `active`, `dante.ready`, `dante.auth_verified`, `engines[].server_ready`, `engines[].active`, `engines[].clients[].build_state`, `engines[].clients[].field_tested`. هیچ رمز یا کلید خصوصی ارسال نمی‌شود. **آماده بودن سرور، وجود ZIP و فعال بودن سرویس، هیچ‌کدام به معنی تست اینترنت زنده نیستند.**

## مرزهای نسخه

- TUI یک MVP منویی استاندارد، نه رابط تمام‌صفحهٔ curses است. اجرا و دریافت خروجی از طریق Unix Socket روی VPS؛ ویندوز می‌تواند ZIP کلاینت‌های سازگار را دریافت کند، اما خود TUI ویندوزی نیست.
- ویرایش همهٔ پروفایل‌های موتور، ثبت لاگ Client Probe و گردش رمز Dante هنوز در UI متنی پیاده‌سازی نشده‌اند؛ Agent API مربوطه پایهٔ توسعهٔ بعدی است.
- نسخهٔ فعلی اجرای عملیاتی روی VPS کاربر را نداشته است. قبل از استقرار، یک snapshot/backup و دسترسی SSH مستقل داشته باش.
