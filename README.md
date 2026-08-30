# PhantomVLESS Xray Manager

PhantomVLESS is a single-file Bash manager for operating **Xray Core** on a Linux VPS with **VLESS**, **XTLS-Vision**, **REALITY**, and platform-focused client profiles.

The current manager version is **3.3.1**.

## Quick Install

Run this on a Debian/Ubuntu VPS with root access:

```bash
sudo apt-get update && sudo apt-get install -y bash curl ca-certificates unzip jq qrencode openssl iproute2 net-tools bc iperf3 && curl -fsSL https://raw.githubusercontent.com/HaMeD1379/my_vps/main/xray-manager.sh -o /tmp/xray-manager.sh && sudo bash /tmp/xray-manager.sh
```

The first run installs the manager atomically to:

```text
/usr/local/bin/xray-manager.sh
```

After that, open the manager anytime with:

```bash
sudo xray-manager.sh
```

## What It Manages

- Xray binary: `/usr/local/bin/xray`
- Xray config: `/usr/local/etc/xray/config.json`
- Client database: `/usr/local/etc/xray/clients.json`
- REALITY public key cache: `/usr/local/etc/xray/public_key.txt`
- Runtime helper files: `sni.txt`, `port.txt`, `server_name.txt`, `server_address.txt`
- Systemd service: `/etc/systemd/system/xray.service`
- Xray logs: `/var/log/xray/access.log` and `/var/log/xray/error.log`
- Config backups: `/usr/local/etc/xray/backups`
- Complete manager/update backups: `/usr/local/etc/xray/manager-backups`

## Main Features

- One-line install and self-install to `/usr/local/bin/xray-manager.sh`
- Interactive terminal dashboard with manager version, Xray version, service state, boot state, OS, kernel, and configured profiles
- Latest stable Xray Core installation from official GitHub releases
- Stable version switching, experimental prerelease install option, and rollback from complete backups
- Existing VLESS + XTLS-Vision + REALITY configuration migration and verification
- Automatic REALITY public key derivation from the server private key, including repair of stale cached public keys
- Compatibility safeguard for newer Xray releases by setting REALITY `minClientVer` to `0.0.0`
- Multi-platform profile migration and verification
- Legacy TCP/Vision/REALITY profile preservation for existing clients
- iOS / Shadowrocket-compatible profile handling
- Advanced Android/Desktop profile support with XHTTP and VLESS Encryption when the installed Xray supports it
- Add, list, inspect, and remove client profiles
- Mass client generation, bulk QR export, and mass removal tools
- Per-client VLESS URLs and terminal QR codes
- QR generation for every client with an HTML index
- Export and import clients for VPS migration
- Service control: start, stop, restart, enable at boot, disable at boot
- Log viewing, saving, and clearing
- Redacted config viewer
- Complete configuration backup and restore
- Full system diagnostics, REALITY key verification, and DPI/leak checks
- Server benchmark and system performance optimizer
- Optional cleanup for old WireGuard, Caddy, and wstunnel setups
- Admin help explaining the components managed by the script

## Requirements

- Debian or Ubuntu-style Linux VPS
- `systemd`
- Root privileges, usually through `sudo`
- Public IPv4 or reachable domain/IP
- Outbound internet access to GitHub
- Supported CPU architecture for automatic Xray binary updates:
  - `x86_64` / `amd64`
  - `aarch64` / `arm64`

The quick install command installs the tools the current script expects: `bash`, `curl`, `ca-certificates`, `unzip`, `jq`, `qrencode`, `openssl`, `iproute2`, `net-tools`, `bc`, and `iperf3`.

## First Run

1. Run the quick install command.
2. In the menu, choose `1` to install or update the latest stable Xray Core.
3. If `/usr/local/etc/xray/config.json` already exists, choose `2` to migrate and verify multi-platform profiles.
4. Open each configured TCP port in your VPS provider firewall.
5. Use menu options `8` and `5` to enable and start the service.
6. Use option `13`, `14`, `15`, or `35` to get client connection details.

The current production manager preserves and migrates an existing REALITY identity. It does not synthesize a brand-new server configuration when no existing Xray config is present.

## Current Menu

| Option | Action |
| --- | --- |
| `1` | Install or update latest stable Xray Core |
| `2` | Migrate and verify multi-platform profiles |
| `3` | Uninstall Xray |
| `4` | Version management and rollback |
| `5` | Start service |
| `6` | Stop service |
| `7` | Restart service |
| `8` | Enable service at boot |
| `9` | Disable service at boot |
| `10` | Add client / platform bundle |
| `11` | Remove a client profile |
| `12` | List all client profiles |
| `13` | Show client connection details |
| `14` | Generate a client QR code |
| `15` | Platform setup guides |
| `16` | Client profile statistics |
| `17` | View service logs |
| `18` | Save logs to a file |
| `19` | Clear logs |
| `20` | Detailed system status |
| `21` | Back up complete configuration |
| `22` | Restore complete configuration |
| `23` | View redacted configuration |
| `24` | Remove old VPN systems |
| `25` | Admin help and component explanations |
| `26` | Run full system diagnostics |
| `27` | Verify REALITY key relationships |
| `28` | DPI and leak security checks |
| `29` | Server benchmark and recommendations |
| `30` | Optimize system performance |
| `31` | Mass client generator and QR export |
| `32` | Mass client remover |
| `33` | Export clients for VPS migration |
| `34` | Import clients from an export |
| `35` | Generate QR codes for every client |
| `36` | Migrate legacy clients to compatibility bundles |
| `0` | Exit |

## Command-Line Usage

Run without arguments for the interactive menu:

```bash
sudo xray-manager.sh
```

Useful direct commands:

```bash
sudo xray-manager.sh install
sudo xray-manager.sh configure
sudo xray-manager.sh start
sudo xray-manager.sh restart
sudo xray-manager.sh status
sudo xray-manager.sh add-client
sudo xray-manager.sh list-clients
sudo xray-manager.sh client-info
sudo xray-manager.sh qr
sudo xray-manager.sh qr-all
sudo xray-manager.sh export-clients
sudo xray-manager.sh import-clients
sudo xray-manager.sh diagnostics
sudo xray-manager.sh benchmark
sudo xray-manager.sh optimize
sudo xray-manager.sh migrate
sudo xray-manager.sh versions
sudo xray-manager.sh manager-version
```

## Version Management

The manager installs Xray directly from official `XTLS/Xray-core` release assets.

- Normal updates use the latest stable release.
- Specific stable versions can be installed from the version menu or with `switch-version`.
- Experimental prereleases require the explicit experimental action.
- Before updates, removals, imports, migrations, and self-updates, the manager can create complete state backups under `/usr/local/etc/xray/manager-backups`.
- If an update fails validation or health checks, the manager restores the previous state when possible.

## Firewall Notes

You must allow inbound **TCP** traffic to the configured Xray port.

Open the port in both places when applicable:

- Your VPS provider firewall or security group
- Your server firewall, such as `ufw`, `iptables`, or `firewalld`

When local firewall automation is available, the manager can help with server-side rules; provider firewalls must usually be updated manually from the cloud dashboard.

## Client Profiles

The manager stores clients in `clients.json` and keeps them synchronized with `config.json`.

Current profile concepts:

- **Legacy / Existing:** Preserves existing TCP + Vision + REALITY clients.
- **iOS / Shadowrocket:** Uses a Shadowrocket-friendly REALITY profile, currently sharing the stable legacy listener when appropriate.
- **Android + Desktop / Advanced:** Uses XHTTP and VLESS Encryption when the installed Xray binary supports it.

Use the add-client wizard to create a platform bundle, or use the migration options to preserve older clients while adding newer companion profiles.

## Backups, Export, and Migration

- Option `21` creates a complete configuration backup.
- Option `22` restores a configuration backup.
- Option `33` exports client names and migration data.
- Option `34` imports clients from an export.
- Option `36` migrates legacy clients to compatibility bundles.
- Xray updates and manager self-updates use complete state backups in `manager-backups`.

## Troubleshooting

Use these checks first:

```bash
sudo xray-manager.sh diagnostics
sudo xray-manager.sh status
sudo xray-manager.sh logs
systemctl status xray --no-pager -l
ss -tlnp | grep xray
```

Common issues:

- If the service does not start, run diagnostics and view the systemd logs.
- If clients cannot connect, confirm the server address, port, UUID, short ID, REALITY public key, SNI, and firewall rules.
- If QR codes or URLs look wrong, run `sudo xray-manager.sh fix-key` to verify the REALITY key relationship.
- If a new Xray version breaks compatibility, use the rollback option from the version menu.

## Security Notes

- This script is designed to run as root. Review it before running it on a server.
- Do not share `config.json`, `clients.json`, private keys, exported client files, or QR codes publicly.
- VLESS URLs and QR codes grant access to your proxy.
- Keep SSH access protected before changing firewall rules.
- Back up `/usr/local/etc/xray` before major changes.

---

<div dir="rtl" lang="fa">

# راهنمای فارسی PhantomVLESS Xray Manager

PhantomVLESS یک اسکریپت Bash تک‌فایلی برای مدیریت Xray Core روی VPS است. این ابزار پیکربندی‌های VLESS، XTLS-Vision، REALITY و پروفایل‌های مخصوص اندروید، iOS و دسکتاپ را از داخل ترمینال مدیریت می‌کند.

نسخه فعلی مدیر: <strong>3.3.1</strong>

## نصب سریع

این دستور را روی VPS دبیان/اوبونتو با دسترسی روت اجرا کنید:

<pre dir="ltr"><code>sudo apt-get update && sudo apt-get install -y bash curl ca-certificates unzip jq qrencode openssl iproute2 net-tools bc iperf3 && curl -fsSL https://raw.githubusercontent.com/HaMeD1379/my_vps/main/xray-manager.sh -o /tmp/xray-manager.sh && sudo bash /tmp/xray-manager.sh</code></pre>

بعد از اولین اجرا، اسکریپت در مسیر زیر نصب می‌شود:

<pre dir="ltr"><code>/usr/local/bin/xray-manager.sh</code></pre>

برای اجرای دوباره:

<pre dir="ltr"><code>sudo xray-manager.sh</code></pre>

## امکانات اصلی

- نصب یک‌خطی و نصب خودکار مدیر در مسیر استاندارد
- داشبورد ترمینالی برای نمایش نسخه مدیر، نسخه Xray، وضعیت سرویس، وضعیت اجرای خودکار، سیستم‌عامل و پروفایل‌های فعال
- نصب یا به‌روزرسانی آخرین نسخه پایدار Xray Core
- مدیریت نسخه‌ها، نصب نسخه پایدار مشخص، نصب نسخه آزمایشی با تایید صریح، و بازگشت به نسخه قبلی
- مهاجرت و بررسی پیکربندی موجود VLESS + XTLS-Vision + REALITY
- استخراج و اصلاح خودکار کلید عمومی REALITY از روی کلید خصوصی سرور
- حفظ سازگاری کلاینت‌های قدیمی با تنظیم مقدار <code dir="ltr">minClientVer</code> روی <code dir="ltr">0.0.0</code>
- مهاجرت و بررسی پروفایل‌های چندپلتفرمی
- حفظ کلاینت‌های قدیمی TCP/Vision/REALITY
- پشتیبانی از پروفایل مناسب iOS و Shadowrocket
- پشتیبانی از پروفایل پیشرفته اندروید و دسکتاپ با XHTTP و VLESS Encryption، در صورت پشتیبانی نسخه نصب‌شده Xray
- افزودن، نمایش، بررسی و حذف کلاینت‌ها
- ساخت انبوه کانفیگ و خروجی QR
- ساخت QR برای همه کلاینت‌ها همراه با فایل HTML
- خروجی گرفتن و وارد کردن کلاینت‌ها برای مهاجرت به VPS دیگر
- کنترل سرویس: شروع، توقف، راه‌اندازی دوباره، فعال‌سازی در زمان بوت و غیرفعال‌سازی
- مشاهده، ذخیره و پاک کردن لاگ‌ها
- نمایش نسخه امن و مخفی‌شده پیکربندی
- بکاپ کامل و بازیابی پیکربندی
- عیب‌یابی کامل سیستم، بررسی کلیدهای REALITY و تست‌های DPI/Leak
- بنچمارک سرور و بهینه‌سازی عملکرد سیستم
- پاک‌سازی اختیاری WireGuard، Caddy و wstunnel قدیمی

## اجرای اولیه

۱. دستور نصب سریع را اجرا کنید.
۲. از منو گزینه <code dir="ltr">1</code> را برای نصب یا به‌روزرسانی آخرین نسخه پایدار Xray انتخاب کنید.
۳. اگر فایل <code dir="ltr">/usr/local/etc/xray/config.json</code> از قبل وجود دارد، گزینه <code dir="ltr">2</code> را برای مهاجرت و بررسی پروفایل‌های چندپلتفرمی انتخاب کنید.
۴. پورت یا پورت‌های TCP پیکربندی‌شده را در فایروال پنل ارائه‌دهنده VPS باز کنید.
۵. با گزینه‌های <code dir="ltr">8</code> و <code dir="ltr">5</code> سرویس را برای بوت فعال و سپس اجرا کنید.
۶. برای دریافت لینک یا QR کلاینت از گزینه‌های <code dir="ltr">13</code>، <code dir="ltr">14</code>، <code dir="ltr">15</code> یا <code dir="ltr">35</code> استفاده کنید.

نسخه فعلی مدیر برای حفظ و مهاجرت هویت REALITY موجود طراحی شده است. اگر هیچ پیکربندی Xray از قبل وجود نداشته باشد، این نسخه پیکربندی کاملا جدید تولید نمی‌کند.

## نکات فایروال

باید پورت انتخاب‌شده Xray را برای ورودی TCP باز کنید. اگر فایروال محلی مثل ufw، iptables یا firewalld فعال باشد، اسکریپت تلاش می‌کند قانون لازم را اضافه کند؛ اما فایروال پنل VPS معمولا باید دستی تنظیم شود.

## دستورات کاربردی

<pre dir="ltr"><code>sudo xray-manager.sh status
sudo xray-manager.sh diagnostics
sudo xray-manager.sh add-client
sudo xray-manager.sh list-clients
sudo xray-manager.sh qr
sudo xray-manager.sh qr-all
sudo xray-manager.sh export-clients
sudo xray-manager.sh import-clients
sudo xray-manager.sh versions</code></pre>

## نکات امنیتی

- این اسکریپت با دسترسی روت اجرا می‌شود؛ قبل از اجرا آن را بررسی کنید.
- فایل‌های <code dir="ltr">config.json</code>، <code dir="ltr">clients.json</code>، کلیدهای خصوصی، لینک‌ها و QRها را عمومی منتشر نکنید.
- لینک VLESS و QR دسترسی مستقیم به پروکسی شما ایجاد می‌کنند.
- قبل از تغییر فایروال، مطمئن شوید دسترسی SSH شما حفظ می‌شود.
- قبل از تغییرات مهم از مسیر <code dir="ltr">/usr/local/etc/xray</code> بکاپ بگیرید.

</div>
