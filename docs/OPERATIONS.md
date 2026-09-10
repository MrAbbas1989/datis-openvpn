# عملیات و نگهداری

## فایل‌ها

| مسیر | محتوا |
|---|---|
| `/opt/datisvpn` | کد و محیط Python؛ متعلق به root |
| `/etc/datisvpn/panel.env` | کلید نشست و مسیرها؛ خصوصی |
| `/etc/datisvpn/openvpn.conf` | تنظیمات OpenVPN |
| `/etc/datisvpn/easy-rsa` | CA و مواد PKI؛ root-only |
| `/etc/datisvpn/client.ovpn` | پروفایل مشترک قابل دانلود توسط مدیر |
| `/var/lib/datisvpn/panel.db` | کاربران، نشست‌ها، شمارنده‌ها و audit |
| `/run/datisvpn/management.sock` | سوکت زنده مدیریت؛ داخل backup لازم نیست |

## پشتیبان

دیتابیس WAL را با `cp panel.db` به‌تنهایی کپی نکنید؛ ممکن است آخرین تراکنش‌ها فقط در WAL باشند. از دستور زیر استفاده کنید:

```bash
sudo datisvpn backup /var/lib/datisvpn/backup-2026-09-10.sqlite
```

فایل باید جدید باشد. برای پشتیبان تنظیمات/گواهی‌ها، در مسیر خصوصی root و با umask محدود:

```bash
sudo bash -c 'umask 077; tar -czf /root/datisvpn-config-backup.tar.gz /etc/datisvpn /etc/systemd/system/datis-*.service /etc/tmpfiles.d/datisvpn.conf /etc/sysctl.d/90-datisvpn.conf'
```

این آرشیو **کلیدهای خصوصی** دارد؛ در GitHub، وب‌روت یا کانال عمومی قرار ندهید. بکاپ دیتابیس و تنظیمات را از سرور خارج و رمزگذاری کنید. تکرار دستور tar همان آرشیو را جایگزین می‌کند؛ برای نگهداری تاریخچه نام تاریخ‌دار انتخاب کنید.

## بازیابی دیتابیس

۱. ابتدا از وضعیت فعلی backup بگیرید و دسترسی فایل backup موردنظر را بررسی کنید.
۲. `sudo systemctl stop datis-panel datis-agent datis-openvpn`؛ همه نشست‌های VPN قطع می‌شوند.
۳. دیتابیس فعلی و فایل‌های `panel.db-wal` و `panel.db-shm` را به پوشه قرنطینه خصوصی منتقل کنید؛ تا توقف سرویس‌ها به WAL دست نزنید.
۴. backup سازگار را با نام `/var/lib/datisvpn/panel.db` قرار دهید، مالک `datisvpn:datisvpn` و دسترسی `0600` تعیین کنید.
۵. با SQLite روی فایل بازیابی `PRAGMA integrity_check` اجرا کنید. سپس `sudo systemctl start datis-openvpn datis-agent datis-panel`.
۶. تست اتصال، سهمیه و انقضا را تکرار کنید. مصرف پس از زمان backup قابل بازیابی نیست.

برای انتقال کامل به سرور جدید، CA/کلیدها/پروفایل و محیط تنظیمات هم لازم‌اند. این نسخه نصاب مهاجرت خودکار ندارد.

## به‌روزرسانی کد

`install.sh` نصاب اولیه است، نه updater. نسخه ۰.۱ migration خودکار schema ندارد. پیش از ارتقا release notes را بخوانید، نسخه فعلی و backup را حفظ کنید. وب و Agent را متوقف، کد و وابستگی‌های نسخه بررسی‌شده را با مالکیت root جایگزین، سپس سرویس‌ها را شروع و آزمون پذیرش را اجرا کنید. اگر schema نسخه جدید ناسازگار باشد، برنامه متوقف می‌شود. کلیدها و دیتابیس را با فایل‌های مخزن جایگزین نکنید.

## گواهی سرور OpenVPN

گواهی سرور اولیه ۸۲۵ روز اعتبار دارد. این گواهی از گواهی HTTPS پنل جداست؛ Certbot آن را تمدید نمی‌کند. وضعیت:

```bash
sudo openssl x509 -in /etc/datisvpn/server.crt -noout -dates
sudo openssl x509 -in /etc/datisvpn/server.crt -checkend 2592000 -noout
```

تمدید در پنجره نگهداری و پس از backup:

```bash
sudo bash -c 'cd /etc/datisvpn/easy-rsa && EASYRSA_BATCH=1 EASYRSA_CERT_EXPIRE=825 ./easyrsa renew datis-server nopass'
sudo install -m 0644 /etc/datisvpn/easy-rsa/pki/issued/datis-server.crt /etc/datisvpn/server.crt
sudo install -m 0600 /etc/datisvpn/easy-rsa/pki/private/datis-server.key /etc/datisvpn/server.key
sudo systemctl restart datis-openvpn
```

این دستور باید با نسخه نصب‌شده Easy-RSA بررسی شود؛ پیش از restart تطابق کلید و گواهی را کنترل کنید. تا وقتی CA و نام سرور تغییر نکنند پروفایل‌های کاربران نیاز به CA جدید ندارند. انقضای CA هم جداگانه پایش شود. چرخش CA/کلید tls-crypt نیاز به توزیع مجدد پروفایل دارد.

## HTTPS و فایروال

- پنل backend روی `127.0.0.1:8080` است. آن را با تغییر bind بدون HTTPS روی اینترنت باز نکنید.
- حالت دامنه `DATIS_SECURE_COOKIE=1` دارد. اگر Certbot ناموفق بود، ابتدا DNS و فایروال 80/443 را اصلاح و Certbot را دوباره اجرا کنید؛ برای ورود در HTTP عمومی، Secure را غیرفعال نکنید.
- حالت SSH از HTTP فقط روی localhost استفاده می‌کند و مسیر خارجی SSH رمزگذاری‌شده است.
- نصاب جدول iptables را flush نمی‌کند؛ فقط قوانین دارای کامنت `datisvpn` و مسیرهای VPN خودش را اضافه می‌کند. `datis-firewall` در توقف فقط همین قوانین را برمی‌دارد.
- نصب روی UFW فعال عمداً پشتیبانی خودکار ندارد. فایروال شرکت میزبان از داخل VPS قابل تغییر نیست.
- نصاب IPv4 forwarding را فعال می‌کند. هنگام حذف، بدون بررسی سرویس‌های دیگر آن را خاموش نکنید.

## نصب نیمه‌تمام / حذف

نصاب بعد از شکست خودش کلیدها یا دیتابیس را حذف نمی‌کند و اجرای دوباره را مسدود می‌کند. خطای گزارش‌شده را بررسی کنید؛ این رفتار برای جلوگیری از تولید دوباره هویت سرور است. پیش از هر پاک‌سازی، `/etc/datisvpn` و `/var/lib/datisvpn` را ذخیره کنید.

برای توقف سرویس اختصاصی:

```bash
sudo systemctl disable --now datis-panel datis-agent datis-openvpn datis-firewall
```

حذف فایل‌ها/حساب سیستم‌عامل مرحله جداگانه و دستی است؛ اسکریپت حذف کور وجود ندارد. فایل Nginx و گواهی وب را تنها اگر مخصوص همین نصب‌اند بردارید. نصب مجدد روی همان مسیر بدون برنامه بازیابی انجام نشود.

## حریم خصوصی و لاگ‌ها

audit شامل نام مدیر، زمان و عملیات است و رمز ندارد. دیتابیس نشست‌ها شامل IP مبدا و مصرف است. در نسخه ۰.۱ پاک‌سازی دوره‌ای خودکار تاریخچه وجود ندارد؛ رشد دیسک را پایش کنید و سیاست نگهداری داده را تعیین کنید. هیچ مسیر دانلود backup عمومی وجود ندارد.
