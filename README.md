# Xray Manager (VLESS + REALITY Control Panel)

This project is a single, feature-rich Bash script that turns a plain Linux VPS into a managed Xray Core server using a modern stack:

- **Protocol:** VLESS
- **Security:** XTLS-Vision + REALITY + uTLS
- **Entry point:** `xray-manager.sh`

It wraps Xray Core, systemd, and a small set of helper files into a cohesive "control panel" you can run directly in your terminal.

> **TL;DR:** Run one script on a fresh Debian/Ubuntu VPS, answer a few questions, and get a fully configured VLESS+REALITY server with client QR codes, mass config generation, and connection guides.

---

## Overview

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
sudo mkdir -p /usr/local/bin
sudo cp xray-manager.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/xray-manager.sh
```

### First-Time Setup

```bash
sudo /usr/local/bin/xray-manager.sh
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
