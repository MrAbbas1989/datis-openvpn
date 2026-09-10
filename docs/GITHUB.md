# مخزن پروژه و مشارکت

مخزن رسمی این پروژه: https://github.com/MrAbbas1989/datis-openvpn

## دریافت

```bash
git clone https://github.com/MrAbbas1989/datis-openvpn.git
cd datis-openvpn
```

نصب و راهنمای فارسی در `README.md` قرار دارد. برای گزارش خطا، یک Issue با نسخه Ubuntu، نسخه OpenVPN و لاگ پاک‌سازی‌شده باز کنید. رمزها، کلیدهای خصوصی، فایل اتصال و اطلاعات مشتریان را منتشر نکنید.

## آزمون‌ها

گردش‌کار `Tests` روی push و pull request برای Python 3.10 و 3.12 روی Ubuntu 22.04 تعریف شده است. نتیجه هر اجرا در بخش Actions مخزن قابل مشاهده است. قبولی این آزمون‌ها جایگزین آزمون اتصال واقعی VPN در `docs/ACCEPTANCE.md` نیست.

## فایل‌های خصوصی

دیتابیس، backup، `.env` و فایل‌های تولیدشده `.ovpn` و کلیدها را commit نکنید. رمزهای داخل تست‌ها فقط داده آزمایشی هستند. `.gitignore` اولیه فراهم شده است.
