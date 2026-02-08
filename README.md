# Xray Manager (VLESS + REALITY Control Panel)

This project is a single, feature-rich Bash script that turns a plain Linux VPS into a managed Xray Core server using a modern stack:

- **Protocol:** VLESS
- **Security:** XTLS-Vision + REALITY + uTLS
- **Entry point:** `xray-manager.sh`

It wraps Xray Core, systemd, and a small set of helper files into a cohesive "control panel" you can run directly in your terminal.

> **TL;DR:** Run one script on a fresh Debian/Ubuntu VPS, answer a few questions, and get a fully configured VLESS+REALITY server with client QR codes, mass config generation, and connection guides.

---

## Overview

<img src="UI Screenshots/Dashboard.png" width="800" alt="Dashboard">

### What This Project Is

`xray-manager.sh` is an interactive Bash-based manager for **Xray Core** configured as a:

- VLESS inbound
- Secured by REALITY (X25519 key pair)
- Typically on port 443
- Impersonating popular TLS websites (e.g., Google, Cloudflare) without needing a real certificate or domain

### Key Features

#### Core Features ✨
- One-command **install** and **configure** flow for VLESS + REALITY
- **Smart port selection** with automatic system scanning
- **Auto-apply firewall rules** (UFW, iptables, firewalld)
- **IPv4 prioritization** to prevent IPv6-only issues
- **Comprehensive firewall guide** for 7 major VPS providers
- Intuitive **TUI menu** with 32 numbered actions

#### Client Management ✨
- **Client management** (add/list/remove) with automatic UUID & short ID generation
- **Mass Client Remover** (NEW): Remove by pattern, range, or interactive selection
- **Connection export**: VLESS URLs, QR codes (ASCII & PNG)

#### Version Management (NEW ✨)
- **Install specific Xray Core version** (e.g., 25.10.15 vs 26)
- **Automatic backup on version change**
- **Rollback to previous version**
- **Preserve existing clients** across version switches

#### Performance Optimization (NEW ✨)
- **BBR Congestion Control** (2-3x throughput improvement)
- **Network buffer tuning** (64MB for high-latency connections)
- **File descriptor optimization** (1M+ concurrent connections)
- **TCP/IP stack tuning** for proxy server workloads
- **Verification checklist** (10-point audit)
- **Graceful reboot** with countdown

#### Bulk Operations (NEW ✨)
- **Mass Config Generator**: Create 1-1000 configs with QR codes
- **HTML visual gallery** for client organization
- **Complete configs list** with VLESS URLs

#### System Management ✨
- **Server Benchmark** (CPU, memory, disk, network analysis)
- **Performance tier classification**
- **Concurrent connection recommendations**
- **Systemd integration** with proper resource limits
- **DPI/security evasion tests**
- **Connection guides** for all platforms (Android/iOS/Windows/macOS/Linux)

---

## Quick Start

### Installation

```bash
curl -sL https://raw.githubusercontent.com/HaMeD1379/PhantomVLESS/main/xray-manager.sh | sudo bash
```

This single command will:
1. Download the script
2. **Automatically install** it to `/usr/local/bin/xray-manager.sh`
3. Launch the interactive menu automatically

After installation, you can run it anytime with:
```bash
sudo xray-manager.sh
```

<details>
<summary>Alternative: Manual Installation</summary>

**Option A: Clone and run (auto-installs)**
```bash
git clone https://github.com/HaMeD1379/PhantomVLESS.git
cd PhantomVLESS
sudo bash xray-manager.sh
```
The script will automatically copy itself to `/usr/local/bin/` on first run.

**Option B: Direct download**
```bash
sudo curl -sL https://raw.githubusercontent.com/HaMeD1379/PhantomVLESS/main/xray-manager.sh -o /usr/local/bin/xray-manager.sh
sudo chmod +x /usr/local/bin/xray-manager.sh
sudo xray-manager.sh
```
</details>

### First-Time Setup

```bash
sudo xray-manager.sh

```

Then:
1. **Option 1**: Install Xray Core
2. **Option 2**: Configure VLESS + REALITY
3. **Option 30** (Optional): Optimize System for Maximum Performance
4. **Option 8**: Enable auto-start
5. **Option 5**: Start service
6. Configure your VPS provider firewall (instructions provided)
7. **Option 14**: Generate QR code for first client

---

## Menu Options (32 Total)

### Installation & Setup (1-4)
- 1) Install Xray Core
- 2) Configure VLESS + REALITY
- 3) Uninstall Xray
- 4) Version Management (Install/Switch/Rollback) **NEW**

### Service Control (5-9)
- 5) Start service
- 6) Stop service
- 7) Restart service
- 8) Enable auto-start
- 9) Disable auto-start

### Client Management (10-16)

<img src="UI Screenshots/QRCode Gen.png" width="600" alt="QRCode Generation">

- 10) Add new client (Wizard)
- 11) Remove client
- 12) List all clients
- 13) Show client connection info
- 14) Generate QR code
- 15) Connection guides (Android/iOS/Desktop)
- 16) Client traffic statistics

### Logs & Monitoring (17-20)
- 17) View logs
- 18) Save logs to file
- 19) Clear logs
- 20) Detailed system status

### Configuration (21-23)
- 21) Backup configuration
- 22) Restore configuration
- 23) View current config

### System & Advanced (24-28)
- 24) Remove old VPN systems (WireGuard/Caddy/wstunnel)
- 25) Admin help (component explanations)
- 26) Run system diagnostics
- 27) Check and fix private key
- 28) DPI & Leak Security Test

### Performance & Mass Tools (29-32) **NEW**
- 29) Server Benchmark & Recommendations
- 30) Optimize System for Maximum Performance
- 31) Mass Config Generator (Bulk + QR Codes)
- 32) Mass Client Remover

---

## Advanced Features

### Version Management

Switch between any Xray Core version:

```bash
sudo ./xray-manager.sh switch-version 25.10.15
```

Or use the interactive menu (Option 4):
- Install specific version
- Automatic backup before switching
- Rollback to previous version
- All clients remain valid

### Mass Config Generation

Generate 1-1000 client configs in seconds:
- Menu Option 31
- Automatic naming (PREFIX_001, PREFIX_002, etc.)
- PNG QR codes for each client
- HTML visual gallery
- Complete VLESS URL list

### System Optimization

Enable BBR + network tuning + file descriptor limits:
- Menu Option 30
- 2-3x throughput improvement with BBR
- 64MB network buffers for high-latency connections
- 1M file descriptor support
- 10-point verification checklist
- Graceful reboot with countdown

### Server Benchmarking

Analyze your server capabilities:
- Menu Option 29
- CPU/Memory/Disk/Network analysis
- Performance tier classification
- Concurrent connection recommendations
- Optimization status check

---

## File Structure

After running the script, you'll have:

```
/usr/local/bin/xray-manager.sh          # Main script
/usr/local/bin/xray                      # Xray binary
/usr/local/etc/xray/
├── config.json                          # Main Xray config
├── clients.json                         # Client registry
├── public_key.txt                       # REALITY public key
├── sni.txt                              # SNI/server name
├── port.txt                             # Listening port
├── server_name.txt                      # Friendly hostname
├── versions/                            # Version backups
├── backups/                             # Config backups
└── benchmark_results.json               # Performance data (NEW)

/etc/systemd/system/xray.service                # Service unit
/etc/systemd/system/xray.service.d/override.conf  # Limits override
/etc/sysctl.d/99-xray-performance.conf           # Kernel tuning (NEW)
/etc/security/limits.d/99-xray-performance.conf  # File limits (NEW)

/var/log/xray/
├── access.log                           # Connection log
└── error.log                            # Error log
```

---

## Configuration

<img src="UI Screenshots/Configuration.png" width="800" alt="Configuration">

### Main Configuration Files

**`/usr/local/etc/xray/config.json`**
- VLESS + REALITY inbound configuration
- Outbound routing rules
- Logging configuration

**`/usr/local/etc/xray/clients.json`**
- Client registry (uuid, email, shortId, created, mass_generated)
- Used by script for client management

**Helper state files:**
- `public_key.txt` — REALITY public key
- `sni.txt` — SNI/server name
- `port.txt` — Listening port
- `server_name.txt` — Friendly name

### Performance Optimization (NEW)

When you run Option 30, the script configures:

**BBR Congestion Control**
- `net.ipv4.tcp_congestion_control = bbr`
- `net.core.default_qdisc = fq`
- Expected: 2-3x throughput improvement

**Network Buffers**
- `net.core.rmem_max = 67108864` (64MB)
- `net.core.wmem_max = 67108864` (64MB)
- Great for high-latency connections

**File Descriptor Limits**
- `fs.file-max = 2097152`
- Supports 1M+ concurrent connections

**Systemd Limits**
- `DefaultLimitNOFILE=1048576`
- Service and per-user limits

---

## Common Workflows

### Add a Single Client

1. Menu → Option 10 (Add new client)
2. Enter label/email (or accept default)
3. Script generates UUID + Short ID
4. Get VLESS URL and QR code

### Bulk Generate 100 Clients

1. Menu → Option 31 (Mass Config Generator)
2. Enter base name (e.g., "TRIAL")
3. Enter count (100)
4. Output: `~/xray_mass_TRIAL_TIMESTAMP/`
   - `qrcodes/` — PNG QR codes
   - `configs/` — Text config files
   - `index.html` — Visual gallery
   - `configs_list.txt` — All VLESS URLs

### Remove 50 Clients Safely

1. Menu → Option 32 (Mass Client Remover)
2. Choose removal method:
   - By pattern: `TRIAL_*`
   - By range: `TRIAL_001` to `TRIAL_050`
   - Interactive: Pick from list
3. Confirm deletion
4. Done!

### Switch Xray Version

1. Menu → Option 4 (Version Management)
2. Option 1: Install/Switch Version
3. Choose version (e.g., 25.10.15)
4. Script:
   - Backs up current version
   - Downloads new version
   - Preserves all clients
   - Restarts service

### Optimize System Performance

1. Menu → Option 30 (Optimize System)
2. Review optimizations
3. Script applies BBR + tuning + limits
4. If reboot needed:
   - 10-second countdown
   - Press Ctrl+C to cancel
   - SSH reconnects in ~30 seconds

---

## Troubleshooting

### Client Cannot Connect
**Most common cause: Firewall!**
1. Check VPS provider firewall (Hetzner, DigitalOcean, etc.)
2. Verify local firewall: `ss -tlnp | grep xray`
3. Run Option 26 (Diagnostics)
4. Run Option 28 (DPI Test)

### Service Won't Start
1. Run Option 26 (System Diagnostics)
2. Check logs: `journalctl -u xray -n 50`
3. Validate config: `xray -test -c /usr/local/etc/xray/config.json`

### Slow Performance
1. Run Option 29 (Server Benchmark)
2. Run Option 30 (System Optimization)
3. Check if BBR is active: `sysctl net.ipv4.tcp_congestion_control`
4. Try different SNI destination

### After Switching Versions
- Always regenerate QR codes (Option 14)
- All clients remain valid
- No reconfiguration needed

---

## Security Notes

- Script runs as **root** — only trust what you inspect
- Protect sensitive files:
  - `config.json`
  - `clients.json`
  - `public_key.txt`
- Don't share VLESS URLs publicly
- Rotate clients/keys periodically
- Backups are created automatically for major operations

---

## System Requirements

- **OS:** Debian/Ubuntu with systemd
- **Network:** Public IPv4 address
- **Tools:** bash, curl, wget, unzip, jq, qrencode, net-tools, bc

The script installs missing dependencies automatically.

---

## Changelog

### Version 2.0 (February 2026)
- ✨ Version Management (install/switch/rollback)
- ✨ Mass Config Generator (1-1000 configs)
- ✨ Mass Client Remover (pattern/range/interactive)
- ✨ System Performance Optimization (BBR + tuning)
- ✨ Server Benchmark & Recommendations
- 🔧 Graceful reboot with countdown
- 🔧 10-point verification checklist
- 🐛 Fixed color escape sequences in menus

### Version 1.0 (Initial Release)
- Core: Install, Configure, Add/Remove clients
- QR code generation, Service management
- DPI security tests, Connection guides

---

## Support & Help

1. Run **Option 26**: System Diagnostics
2. Run **Option 28**: DPI & Security Test
3. Save logs: **Option 18**
4. Check `/var/log/xray/error.log`

For detailed help, run: **Option 25** (Admin Help)

---

## License

This project currently has no explicit license. Modify and distribute as needed, with appropriate attribution.

---

<div dir="rtl">

# نسخه فارسی (Persian Version)

# مدیریت Xray (پنل کنترل VLESS + REALITY)

این پروژه یک اسکریپت Bash تک‌فایلی و پرامکانات است که یک سرور لینوکس (VPS) خام را با استفاده از پشته‌ای مدرن به یک سرور مدیریت‌شده Xray Core تبدیل می‌کند:

- **پروتکل:** VLESS
- **امنیت:** XTLS-Vision + REALITY + uTLS
- **نقطه ورود:** `xray-manager.sh`

این اسکریپت Xray Core، systemd و مجموعه‌ای کوچک از فایل‌های کمکی را در قالب یک "پنل کنترل" منسجم که می‌توانید مستقیماً در ترمینال اجرا کنید، بسته‌بندی می‌کند.

> **خلاصه:** یک اسکریپت را روی یک VPS تازه دبیان/اوبونتو اجرا کنید، به چند سوال پاسخ دهید و یک سرور VLESS+REALITY کاملاً پیکربندی شده همراه با کدهای QR برای کلاینت، تولید کانفیگ انبوه و راهنمای اتصال دریافت کنید.

---

## بررسی اجمالی (Overview)

<img src="UI Screenshots/Dashboard.png" width="800" alt="Dashboard">

### این پروژه چیست

`xray-manager.sh` یک مدیر تعاملی مبتنی بر Bash برای **Xray Core** است که به صورت زیر پیکربندی شده است:

- ورودی VLESS
- ایمن شده توسط REALITY (جفت کلید X25519)
- معمولاً روی پورت 443
- جعل وب‌سایت‌های محبوب TLS (مانند Google، Cloudflare) بدون نیاز به گواهی یا دامنه واقعی

### ویژگی‌های کلیدی

#### ویژگی‌های اصلی ✨
- جریان **نصب** و **پیکربندی** VLESS + REALITY فقط با یک دستور
- **انتخاب هوشمند پورت** با اسکن خودکار سیستم
- **اعمال خودکار قوانین فایروال** (UFW, iptables, firewalld)
- **اولویت‌بندی IPv4** برای جلوگیری از مشکلات IPv6-only
- **راهنمای جامع فایروال** برای 7 ارائه دهنده محبوب VPS
- **منوی متنی (TUI)** بصری با 32 عملکرد شماره‌گذاری شده

#### مدیریت کلاینت ✨
- **مدیریت کلاینت** (افزودن/لیست/حذف) با تولید خودکار UUID و Short ID
- **حذف کننده انبوه کلاینت** (جدید): حذف بر اساس الگو، محدوده یا انتخاب تعاملی
- **خروجی اتصال**: لینک‌های VLESS، کدهای QR (ASCII و PNG)

#### مدیریت نسخه (جدید ✨)
- **نصب نسخه خاص Xray Core** (مثلاً 25.10.15 در مقابل 26)
- **بکاپ خودکار هنگام تغییر نسخه**
- **بازگشت به نسخه قبلی (Rollback)**
- **حفظ کلاینت‌های موجود** هنگام تغییر نسخه

#### بهینه‌سازی عملکرد (جدید ✨)
- **کنترل ازدحام BBR** (بهبود 2 تا 3 برابری پهنای باند)
- **تنظیم بافر شبکه** (64MB برای اتصالات با تاخیر بالا)
- **بهینه‌سازی توصیف‌گر فایل** (پشتیبانی از بیش از 1 میلیون اتصال همزمان)
- **تنظیم پشته TCP/IP** برای بارهای کاری سرور پروکسی
- **چک‌لیست تایید** (ممیزی 10 نقطه‌ای)
- **ریستارت نرم** با شمارش معکوس

#### عملیات انبوه (جدید ✨)
- **تولید کننده کانفیگ انبوه**: ایجاد 1 تا 1000 کانفیگ با کدهای QR
- **گالری تصویری HTML** برای سازماندهی کلاینت‌ها
- **لیست کامل کانفیگ‌ها** با لینک‌های VLESS

#### مدیریت سیستم ✨
- **بنچمارک سرور** (تحلیل CPU، حافظه، دیسک، شبکه)
- **طبقه‌بندی سطح عملکرد**
- **توصیه‌های اتصال همزمان**
- **یکپارچه‌سازی با systemd** با محدودیت‌های منابع مناسب
- **تست‌های فرار از DPI/امنیت**
- **راهنمای اتصال** برای همه پلتفرم‌ها (Android/iOS/Windows/macOS/Linux)

---

## شروع سریع (Quick Start)

### نصب (Installation)

```bash
curl -sL https://raw.githubusercontent.com/HaMeD1379/PhantomVLESS/main/xray-manager.sh | sudo bash
```

این دستور به صورت خودکار:
1. اسکریپت را دانلود می‌کند
2. آن را در `/usr/local/bin/xray-manager.sh` نصب می‌کند
3. منوی تعاملی را راه‌اندازی می‌کند

بعد از نصب، می‌توانید هر زمان با این دستور اجرا کنید:
```bash
sudo xray-manager.sh
```

<details>
<summary>روش جایگزین: نصب دستی</summary>

```bash
git clone https://github.com/HaMeD1379/PhantomVLESS.git
cd PhantomVLESS
sudo cp xray-manager.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/xray-manager.sh
sudo xray-manager.sh
```
</details>

### تنظیم اولیه (First-Time Setup)

```bash
sudo /usr/local/bin/xray-manager.sh
```

سپس:
1. **گزینه 1**: نصب Xray Core
2. **گزینه 2**: پیکربندی VLESS + REALITY
3. **گزینه 30** (اختیاری): بهینه‌سازی سیستم برای حداکثر عملکرد
4. **گزینه 8**: فعال‌سازی شروع خودکار
5. **گزینه 5**: استارت سرویس
6. پیکربندی فایروال ارائه دهنده VPS خود (دستورالعمل‌ها ارائه شده است)
7. **گزینه 14**: تولید کد QR برای اولین کلاینت

---

## گزینه‌های منو (32 مورد)

### نصب و راه‌اندازی (1-4)
- 1) نصب Xray Core
- 2) پیکربندی VLESS + REALITY
- 3) حذف Xray
- 4) مدیریت نسخه (نصب/تغییر/بازگشت) **جدید**

### کنترل سرویس (5-9)
- 5) شروع سرویس
- 6) توقف سرویس
- 7) ریستارت سرویس
- 8) فعال‌سازی شروع خودکار
- 9) غیرفعال‌سازی شروع خودکار

### مدیریت کلاینت (10-16)

<img src="UI Screenshots/QRCode Gen.png" width="600" alt="QRCode Generation">

- 10) افزودن کلاینت جدید (ویزارد)
- 11) حذف کلاینت
- 12) لیست همه کلاینت‌ها
- 13) نمایش اطلاعات اتصال کلاینت
- 14) تولید کد QR
- 15) راهنمای اتصال (Android/iOS/Desktop)
- 16) آمار ترافیک کلاینت‌ها

### لاگ‌ها و نظارت (17-20)
- 17) مشاهده لاگ‌ها
- 18) ذخیره لاگ‌ها در فایل
- 19) پاک کردن لاگ‌ها
- 20) وضعیت دقیق سیستم

### پیکربندی (21-23)
- 21) بکاپ‌گیری از پیکربندی
- 22) بازیابی پیکربندی
- 23) مشاهده کانفیگ فعلی

### سیستم و پیشرفته (24-28)
- 24) حذف سیستم‌های VPN قدیمی (WireGuard/Caddy/wstunnel)
- 25) راهنمای ادمین (توضیحات اجزا)
- 26) اجرای عیب‌یابی سیستم
- 27) بررسی و تعمیر کلید خصوصی
- 28) تست امنیت و نشت DPI

### عملکرد و ابزارهای انبوه (29-32) **جدید**
- 29) بنچمارک سرور و توصیه‌ها
- 30) بهینه‌سازی سیستم برای حداکثر عملکرد
- 31) تولید کننده کانفیگ انبوه (انبوه + کدهای QR)
- 32) حذف کننده انبوه کلاینت

---

## ویژگی‌های پیشرفته

### مدیریت نسخه

تغییر بین هر نسخه Xray Core:

```bash
sudo ./xray-manager.sh switch-version 25.10.15
```

یا استفاده از منوی تعاملی (گزینه 4):
- نصب نسخه خاص
- بکاپ خودکار قبل از تغییر
- بازگشت به نسخه قبلی
- همه کلاینت‌ها معتبر باقی می‌مانند

### تولید کانفیگ انبوه

تولید 1 تا 1000 کانفیگ کلاینت در چند ثانیه:
- گزینه منو 31
- نام‌گذاری خودکار (PREFIX_001, PREFIX_002, etc.)
- کدهای QR PNG برای هر کلاینت
- گالری تصویری HTML
- لیست کامل لینک‌های VLESS

### بهینه‌سازی سیستم

فعال‌سازی BBR + تنظیم شبکه + محدودیت‌های توصیف‌گر فایل:
- گزینه منو 30
- بهبود 2 تا 3 برابری پهنای باند با BBR
- بافرهای شبکه 64MB برای اتصالات با تاخیر بالا
- پشتیبانی از 1 میلیون توصیف‌گر فایل
- چک‌لیست تایید 10 نقطه‌ای
- ریستارت نرم با شمارش معکوس

### بنچمارک سرور

تحلیل قابلیت‌های سرور شما:
- گزینه منو 29
- تحلیل CPU/حافظه/دیسک/شبکه
- طبقه‌بندی سطح عملکرد
- توصیه‌های اتصال همزمان
- بررسی وضعیت بهینه‌سازی

---

## ساختار فایل

پس از اجرای اسکریپت، موارد زیر را خواهید داشت:

```
/usr/local/bin/xray-manager.sh          # Main script
/usr/local/bin/xray                      # Xray binary
/usr/local/etc/xray/
├── config.json                          # Main Xray config
├── clients.json                         # Client registry
├── public_key.txt                       # REALITY public key
├── sni.txt                              # SNI/server name
├── port.txt                             # Listening port
├── server_name.txt                      # Friendly hostname
├── versions/                            # Version backups
├── backups/                             # Config backups
└── benchmark_results.json               # Performance data (NEW)

/etc/systemd/system/xray.service                # Service unit
/etc/systemd/system/xray.service.d/override.conf  # Limits override
/etc/sysctl.d/99-xray-performance.conf           # Kernel tuning (NEW)
/etc/security/limits.d/99-xray-performance.conf  # File limits (NEW)

/var/log/xray/
├── access.log                           # Connection log
└── error.log                            # Error log
```

---

## پیکربندی (Configuration)

<img src="UI Screenshots/Configuration.png" width="800" alt="Configuration">

### فایل‌های اصلی پیکربندی

**`/usr/local/etc/xray/config.json`**
- پیکربندی ورودی VLESS + REALITY
- قوانین مسیریابی خروجی
- پیکربندی لاگ‌ها

**`/usr/local/etc/xray/clients.json`**
- ثبت کلاینت‌ها (uuid, email, shortId, created, mass_generated)
- استفاده شده توسط اسکریپت برای مدیریت کلاینت

**فایل‌های وضعیت کمکی:**
- `public_key.txt` — کلید عمومی REALITY
- `sni.txt` — SNI/نام سرور
- `port.txt` — پورت شنود
- `server_name.txt` — نام دوستانه

### بهینه‌سازی عملکرد (جدید)

وقتی گزینه 30 را اجرا می‌کنید، اسکریپت موارد زیر را تنظیم می‌کند:

**کنترل ازدحام BBR**
- `net.ipv4.tcp_congestion_control = bbr`
- `net.core.default_qdisc = fq`
- انتظار: بهبود 2 تا 3 برابری پهنای باند

**بافرهای شبکه**
- `net.core.rmem_max = 67108864` (64MB)
- `net.core.wmem_max = 67108864` (64MB)
- عالی برای اتصالات با تاخیر بالا

**محدودیت‌های توصیف‌گر فایل**
- `fs.file-max = 2097152`
- پشتیبانی از بیش از 1 میلیون اتصال همزمان

**محدودیت‌های Systemd**
- `DefaultLimitNOFILE=1048576`
- محدودیت‌های سرویس و هر کاربر

---

## جریان‌های کاری رایج

### افزودن یک کلاینت تکی

1. منو → گزینه 10 (Add new client)
2. وارد کردن برچسب/ایمیل (یا پذیرش پیش‌فرض)
3. اسکریپت UUID + Short ID را تولید می‌کند
4. دریافت لینک VLESS و کد QR

### تولید انبوه 100 کلاینت

1. منو → گزینه 31 (Mass Config Generator)
2. وارد کردن نام پایه (مثلاً "TRIAL")
3. وارد کردن تعداد (100)
4. خروجی: `~/xray_mass_TRIAL_TIMESTAMP/`
   - `qrcodes/` — کدهای QR PNG
   - `configs/` — فایل‌های کانفیگ متنی
   - `index.html` — گالری تصویری
   - `configs_list.txt` — همه لینک‌های VLESS

### حذف ایمن 50 کلاینت

1. منو → گزینه 32 (Mass Client Remover)
2. انتخاب روش حذف:
   - با الگو: `TRIAL_*`
   - با محدوده: `TRIAL_001` تا `TRIAL_050`
   - تعاملی: انتخاب از لیست
3. تایید حذف
4. تمام!

### تغییر نسخه Xray

1. منو → گزینه 4 (Version Management)
2. گزینه 1: نصب/تغییر نسخه
3. انتخاب نسخه (مثلاً 25.10.15)
4. اسکریپت:
   - از نسخه فعلی بکاپ می‌گیرد
   - نسخه جدید را دانلود می‌کند
   - تمام کلاینت‌ها را حفظ می‌کند
   - سرویس را ریستارت می‌کند

### بهینه‌سازی عملکرد سیستم

1. منو → گزینه 30 (Optimize System)
2. بررسی بهینه‌سازی‌ها
3. اسکریپت BBR + تنظیمات + محدودیت‌ها را اعمال می‌کند
4. اگر نیاز به ریبوت باشد:
   - شمارش معکوس 10 ثانیه‌ای
   - برای لغو Ctrl+C را فشار دهید
   - اتصال SSH مجدداً در حدود 30 ثانیه برقرار می‌شود

---

## عیب‌یابی (Troubleshooting)

### کلاینت نمی‌تواند متصل شود
**شایع‌ترین دلیل: فایروال!**
1. فایروال ارائه دهنده VPS را بررسی کنید (Hetzner, DigitalOcean, etc.)
2. فایروال محلی را بررسی کنید: `ss -tlnp | grep xray`
3. اجرای گزینه 26 (Diagnostics)
4. اجرای گزینه 28 (DPI Test)

### سرویس استارت نمی‌شود
1. اجرای گزینه 26 (System Diagnostics)
2. بررسی لاگ‌ها: `journalctl -u xray -n 50`
3. اعتبارسنجی کانفیگ: `xray -test -c /usr/local/etc/xray/config.json`

### عملکرد کند
1. اجرای گزینه 29 (Server Benchmark)
2. اجرای گزینه 30 (System Optimization)
3. بررسی فعال بودن BBR: `sysctl net.ipv4.tcp_congestion_control`
4. امتحان کردن مقصد SNI متفاوت

### پس از تغییر نسخه‌ها
- همیشه کدهای QR را مجدداً تولید کنید (گزینه 14)
- همه کلاینت‌ها معتبر باقی می‌مانند
- نیازی به پیکربندی مجدد نیست

---

## نکات امنیتی

- اسکریپت به عنوان **root** اجرا می‌شود — فقط به چیزی که بررسی می‌کنید اعتماد کنید
- محافظت از فایل‌های حساس:
  - `config.json`
  - `clients.json`
  - `public_key.txt`
- لینک‌های VLESS را به صورت عمومی به اشتراک نگذارید
- کلاینت‌ها/کلیدها را به صورت دوره‌ای تغییر دهید
- بکاپ‌ها به صورت خودکار برای عملیات‌های اصلی ایجاد می‌شوند

---

## نیازمندی‌های سیستم

- **سیستم عامل:** Debian/Ubuntu با systemd
- **شبکه:** آدرس IPv4 عمومی
- **ابزارها:** bash, curl, wget, unzip, jq, qrencode, net-tools, bc

اسکریپت وابستگی‌های گمشده را به صورت خودکار نصب می‌کند.

---

## تغییرات (Changelog)

### نسخه 2.0 (فوریه 2026)
- ✨ مدیریت نسخه (نصب/تغییر/بازگشت)
- ✨ تولید کننده کانفیگ انبوه (1 تا 1000 کانفیگ)
- ✨ حذف کننده انبوه کلاینت (الگو/محدوده/تعاملی)
- ✨ بهینه‌سازی عملکرد سیستم (BBR + تیونینگ)
- ✨ بنچمارک سرور و توصیه‌ها
- 🔧 ریستارت نرم با شمارش معکوس
- 🔧 چک‌لیست تایید 10 نقطه‌ای
- 🐛 رفع توالی‌های فرار رنگ در منوها

### نسخه 1.0 (انتشار اولیه)
- هسته اصلی: نصب، پیکربندی، افزودن/حذف کلاینت
- تولید کد QR، مدیریت سرویس
- تست‌های امنیتی DPI، راهنمای اتصال

---

## پشتیبانی و راهنما

1. اجرای **گزینه 26**: عیب‌یابی سیستم (System Diagnostics)
2. اجرای **گزینه 28**: تست امنیت و DPI
3. ذخیره لاگ‌ها: **گزینه 18**
4. بررسی `/var/log/xray/error.log`

برای راهنمایی دقیق، اجرا کنید: **گزینه 25** (راهنمای ادمین)

---

## لایسنس

این پروژه در حال حاضر هیچ لایسنس صریحی ندارد. در صورت نیاز تغییر دهید و توزیع کنید، با ذکر منبع مناسب.

</div>
