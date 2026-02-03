# Xray Manager (VLESS + REALITY Control Panel)

This project is a single, feature-rich Bash script that turns a plain Linux VPS into a managed Xray Core server using a modern stack:

- **Protocol:** VLESS
- **Security:** XTLS-Vision + REALITY + uTLS
- **Entry point:** `xray-manager.sh`

It wraps Xray Core, systemd, and a small set of helper files into a cohesive “control panel” you can run directly in your terminal.

> **TL;DR:** Run one script on a fresh Debian/Ubuntu VPS, answer a few questions, and get a fully configured VLESS+REALITY server with client QR codes and connection guides.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [How It Works at Runtime](#how-it-works-at-runtime)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage & Common Workflows](#usage--common-workflows)
7. [Maintenance & Troubleshooting](#maintenance--troubleshooting)
8. [Limitations & Security Notes](#limitations--security-notes)

---

## Overview

### What This Project Is

`xray-manager.sh` is an interactive Bash-based manager for **Xray Core** configured as a:

- VLESS inbound
- secured by REALITY (X25519 key pair)
- typically on port 443
- impersonating popular TLS websites (e.g., Google, Cloudflare) without needing a real certificate or domain

The script is designed to be:

- **Beginner-friendly:** interactive menus, wizards, and detailed help text.
- **Opinionated but flexible:** provides safe defaults while allowing customization.
- **Self-contained:** no external web UI; everything is CLI-based.

### Problems It Solves

- Installing Xray Core correctly on a new VPS.
- Generating and maintaining a secure REALITY configuration.
- Managing clients (UUIDs/short IDs) and generating shareable connection info.
- Starting/stopping and enabling/disabling the Xray systemd service.
- Viewing logs and basic per-client statistics.
- Running diagnostics and optionally removing old VPN setups (WireGuard, Caddy, wstunnel).

### Key Features

- One-command **install** and **configure** flow for VLESS + REALITY.
- **Smart port selection**: Automatically scans system and suggests available high ports (443, 8443, 2053, 2083, 2087, 2096, 51820, 41234, 32145).
- **Port validation**: Checks if chosen port is already in use and warns before proceeding.
- **Auto-apply firewall rules**: Automatically configures UFW, iptables, or firewalld rules when available.
- **IPv4 prioritization**: Forces IPv4 connections to prevent IPv6-only issues; handles dual-stack servers correctly.
- **IP forwarding auto-enable**: Automatically enables kernel IP forwarding required for proxy traffic routing.
- **Comprehensive firewall guide**: Displays step-by-step instructions for 7 major VPS providers (Hetzner, DigitalOcean, Vultr, AWS, Oracle, GCP, Linode).
- Intuitive **TUI menu** with numbered actions.
- **Client management** (add/list/remove) with automatic UUID & short ID generation.
- **Connection export**:
  - VLESS URLs
  - Terminal QR codes
  - Optional PNG QR files
- **Systemd integration**:
  - `xray.service` creation
  - enable/disable/start/stop/restart helpers
- **Logs & stats**:
  - view, save, clear logs
  - basic per-client connection stats
- **Diagnostics & repair**:
  - system and configuration diagnostics
  - REALITY private key self-healing
  - legacy VPN cleanup helper
  - DPI/security evasion tests
- Built-in **connection guides** for major platforms (Android, iOS, Windows, macOS, Linux).

---

## Architecture

### High-Level Layout

While the repository only contains `xray-manager.sh`, at runtime the script manages a small ecosystem of files and services:

- **Manager script** (entry point)
  - `/usr/local/bin/VPS_V2/xray-manager.sh`
- **Xray Core binary**
  - `/usr/local/bin/xray`
- **Xray configuration & state** (under `/usr/local/etc/xray`)
  - `config.json` — main Xray configuration (inbounds/outbounds/routing/logs)
  - `clients.json` — higher-level client registry
  - `public_key.txt` — REALITY public key (exported)
  - `sni.txt` — SNI/server name used by clients
  - `port.txt` — listening port (e.g., 443)
  - `server_name.txt` — friendly name/hostname reference
  - `backups/` — configuration backup archives
- **Service definition**
  - `/etc/systemd/system/xray.service` — systemd unit
- **Logs**
  - `/var/log/xray/access.log` — Xray access log
  - `/var/log/xray/error.log` — Xray error log
  - `journalctl -u xray` — systemd journal for the service

The Bash script acts as a **control center** around these components: it reads/modifies JSON via `jq`, writes systemd units, and drives the Xray binary via systemd.

### Main Script Components

Internally, `xray-manager.sh` is organized into logical function groups. Names may vary slightly, but conceptually they fall into:

1. **Environment & helpers**
   - Root and environment checks
   - Colored output helpers
   - Utility wrappers for `systemctl`, `ss`, `curl`, `jq`, etc.

2. **Install & setup**
   - Install required packages
   - Download and install Xray Core via the official script
   - Create and enable the `xray.service` unit
   - Enable kernel IP forwarding for proper traffic routing

3. **Configuration & REALITY**
   - Smart port selection with system scanning
   - Port validation and conflict detection
   - Interactive configuration wizard
   - REALITY x25519 key generation
   - Initial client UUID + short ID
   - Writing `config.json`, `clients.json`, and helper text files
   - Automatic local firewall rule application (UFW, iptables, firewalld)

4. **Firewall & Network**
   - System port scanner and availability checker
   - Automatic local firewall configuration (UFW, iptables, firewalld)
   - Comprehensive VPS provider firewall instructions (7 providers)
   - IPv4-only connectivity verification

5. **Client management**
   - Add/remove/list clients
   - Keep `config.json` and `clients.json` in sync
   - Generate VLESS+REALITY URLs (with forced IPv4)
   - Generate ASCII and (optionally) PNG QR codes

6. **Service control**
   - Start/stop/restart Xray
   - Enable/disable on boot
   - Basic status checks (is the binary installed, is the port open, etc.)

6. **Monitoring, logs & stats**
   - Colorful status dashboard (ports, processes, resource usage)
   - View/tail/vacuum logs
   - Export logs for support/debugging
   - Basic per-client stats from the access log

7. **Diagnostics & maintenance**
   - System diagnostics ("health check")
   - DPI/security evasion tests
   - REALITY key sanity checks and repair
   - Backups and restore of configuration
   - Optional cleanup of legacy VPN tools
   - Full uninstall flow for Xray

### How Components Interact

- The **script** is the only thing you run; it calls:
  - **Xray** for config testing and actual packet handling.
  - **systemd** for service management.
  - **`jq`** to read and modify `config.json` and `clients.json`.
- **REALITY** state (public key, SNI, port) is mirrored from `config.json` into small text files for easier reuse when building client URLs and QR codes.
- **Client operations** always update both `config.json` and `clients.json`, then restart or reload the Xray service when needed.
- **Logs** are written by Xray and systemd; the script only displays, archives, or truncates them.

---

## How It Works at Runtime

### Entry Points

You typically invoke the script via:

```bash
sudo /usr/local/bin/VPS_V2/xray-manager.sh
```

With no arguments, it shows an **interactive menu** (TUI-like) containing options such as:

- Install / Update Xray
- Configure VLESS + REALITY
- Add / List / Remove clients
- Show status dashboard
- Manage service (start/stop/restart/enable/disable)
- View / Save / Clear logs
- Run diagnostics and DPI/security tests
- Remove old VPN systems
- Uninstall Xray

Some operations can also be wired to **direct subcommands** (depending on how you extend it), for example:

- `xray-manager.sh add-client`
- `xray-manager.sh list-clients`
- `xray-manager.sh client-info`
- `xray-manager.sh qr`

The main design assumption is interactive, menu-driven use.

### First-Time Setup Flow

For a clean VPS:

1. **Run the script as root.**  
   It verifies root access and required utilities.

2. **Install Xray & dependencies.**  
   Via an "Install Xray" menu option, it:
   - Installs tools such as `curl`, `wget`, `unzip`, `jq`, `qrencode`, `net-tools` if missing.
   - Uses the official Xray install script to fetch the latest Xray Core.

3. **Run the configuration wizard.**  
   The VLESS+REALITY wizard will:
   - **Smart port selection**: Scans your system for available ports and suggests the best option (443, 8443, 2053, 51820, etc.)
   - Validates your port choice and warns if it's already in use
   - Ask which **destination/SNI** to impersonate (Google, Cloudflare, or custom).
   - Ask for a **server name** (often same as SNI or a domain you control).
   - Generate the **REALITY key pair** and the first client's **UUID** and **short ID**.
   - Write `config.json`, `clients.json`, and helper text files.
   - Create or update `/etc/systemd/system/xray.service`.
   - **Auto-apply local firewall rules** (ufw, iptables, or firewalld)
   - Display comprehensive firewall instructions for major VPS providers

4. **Enable and start the service.**  
   With menu options for:
   - Enable on boot.
   - Start now.

5. **Configure VPS provider firewall.**  
   The script provides detailed, step-by-step instructions for:
   - Hetzner Cloud
   - DigitalOcean
   - Vultr
   - AWS EC2
   - Oracle Cloud (OCI)
   - Google Cloud (GCP)
   - Linode/Akamai
   
   Plus verification commands to confirm your port is accessible.

After this, the server is ready; you only need to create clients and export their connection info.

### Ongoing Operations

Most day-to-day interaction is:

- Adding/removing clients.
- Viewing their connection URLs/QR codes.
- Checking status and logs.
- Running diagnostics if something stops working.

The script uses **`set -e`** and internal checks to fail early when something is misconfigured. It also performs small automatic repairs (e.g., REALITY private key) when possible.

---

## Installation

### Requirements

- **OS:** A modern Debian/Ubuntu-like Linux distribution.
- **Init system:** `systemd`.
- **Network:** Public IPv4 with outbound internet access.
- **Privileges:** Must be run as **root** (or via `sudo`).

### Dependencies

The script relies on several common tools:

- `bash` — shell interpreter
- `curl`, `wget` — downloading installer and performing network checks
- `unzip` — unpacking Xray releases
- `jq` — JSON parsing and manipulation
- `qrencode` — generating QR codes for clients
- `net-tools` or `iproute2` (`ss`, `netstat`) — checking ports

If any of these are missing, the **install flow** tries to install them via your package manager.

### Installing the Script

1. Place the script on your server, for example:

   ```bash
   sudo mkdir -p /usr/local/bin/VPS_V2
   sudo cp xray-manager.sh /usr/local/bin/VPS_V2/
   sudo chmod +x /usr/local/bin/VPS_V2/xray-manager.sh
   ```

2. Run it as root:

   ```bash
   sudo /usr/local/bin/VPS_V2/xray-manager.sh
   ```

3. From the menu, choose:
   - **Install Xray**
   - Then **Configure VLESS + REALITY**

4. Follow the wizard prompts until configuration is complete.

### Firewall / Cloud Provider Rules

After installation and configuration:

- Allow **TCP** inbound on the chosen Xray port (commonly `443`).
- Configure this both on:
  - Your VPS provider firewall (e.g., Hetzner Cloud, OVH, etc.).
  - Any local firewall tool you use (`ufw`, `iptables`, etc.).

---

## Configuration

### Main Files

All key configuration is stored under `/usr/local/etc/xray`:

- `config.json`  
  The **primary Xray configuration**. Important sections:
  - `log` — log level and file paths.
  - `inbounds` — VLESS + REALITY inbound:
    - `port` — the listening port.
    - `protocol` — `"vless"`.
    - `settings.clients` — list of clients with `id`, `flow`, `email`.
    - `streamSettings.security` — `"reality"`.
    - `realitySettings` — `dest`, `serverNames`, `privateKey`, `shortIds`.
  - `outbounds` — usually `freedom` and `blackhole`.
  - `routing.rules` — simple rules (e.g., blocking BitTorrent).

- `clients.json`  
  A **client registry** used by the script. Each entry typically has:
  - `uuid` — Xray client ID.
  - `email` — label/username.
  - `shortId` — REALITY short ID.
  - `flow` — usually `xtls-rprx-vision`.
  - `created` — timestamp.

- Helper state files:
  - `public_key.txt` — REALITY public key.
  - `sni.txt` — SNI that clients should use.
  - `port.txt` — port number.
  - `server_name.txt` — descriptive name/hostname.

- Backups:
  - `backups/config_backup_YYYYMMDD_HHMMSS.tar.gz` — archived configs.

### Systemd Unit

The script writes `/etc/systemd/system/xray.service`, which typically:

- Runs: `/usr/local/bin/xray run -config /usr/local/etc/xray/config.json`
- Grants minimal required capabilities (`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`).
- Sets restart policy (`Restart=on-failure`) and resource limits.

You normally don’t edit this by hand; instead, let the script manage it.

### Interactive Configuration Wizard

The configuration wizard:

1. Reads any existing setup and backs it up when appropriate.
2. Asks for minimal inputs:
   - Listening port
   - Destination/SNI to impersonate
   - Optional custom server name/domain
3. Automatically:
   - Generates REALITY keys
   - Generates a first client
   - Writes `config.json` and `clients.json`
   - Writes service unit and reloads systemd
4. Prints a summary and next steps.

If needed, you can re-run the wizard to adjust configuration. Existing files may be backed up before overwriting.

---

## Usage & Common Workflows

### Starting the Manager

Run the interactive menu:

```bash
sudo /usr/local/bin/VPS_V2/xray-manager.sh
```

Use the numeric choices shown on-screen to navigate.

### 1. First-Time Install & Setup

1. **Select** the option to install Xray.
2. **Wait** for the installer to complete.
3. **Select** the configuration wizard for VLESS + REALITY.
4. **Provide** port and destination/SNI when prompted.
5. **Confirm** the summary and let it create/update config and service.
6. **Enable & start** the service via the menu.
7. **Open firewall** on your provider and/or OS.

### 2. Adding a New Client

From the main menu:

1. Choose **Add client**.
2. Enter a label/email for the client (or accept defaults).
3. The script:
   - Generates UUID + short ID.
   - Updates `config.json` and `clients.json`.
   - Restarts/reloads Xray if needed.
4. It prints or offers:
   - The full VLESS URL.
   - Option to show QR code.

You can then share the URL or QR code for client configuration.

### 3. Listing / Inspecting / Removing Clients

- **List clients**: menu option to see all known clients with UUID/email.
- **Show client info**: select a specific client to see detailed connection info.
- **Remove client**:
  1. Choose the remove option.
  2. Enter the client identifier.
  3. Confirm the deletion.
  4. The script updates both Xray config and clients DB.

### 4. Generating QR Codes

There’s a menu entry to **generate QR codes** for one of the clients:

1. Select the client.
2. The script shows:
   - Human-readable connection details.
   - The full VLESS URL.
   - An ASCII QR code in the terminal.
3. Optionally, it can save a PNG QR file in your home directory.

### 5. Viewing Connection Guides

Another menu item opens **platform-specific connection guides** for:

- Android (e.g., v2rayNG)
- iOS (e.g., Shadowrocket, V2Box)
- Windows (e.g., v2rayN, Nekoray)
- macOS (e.g., V2RayXS, Qv2ray)
- Linux (using GUI clients or the Xray CLI)

These guides explain how to import the VLESS URL or QR code you generated.

### 6. Monitoring & Diagnostics

- **Status dashboard**: shows service status, ports, connection count, resource usage.
- **Client stats**: basic statistics derived from the access log, by client.
- **System diagnostics**: performs a series of checks:
  - Xray binary presence
  - Config syntax and structure
  - Systemd service status
  - Open port checks
  - REALITY configuration sanity
  - Log file presence and errors

There is also an advanced **DPI/security test** helper that runs more detailed checks related to REALITY and network behavior (some aspects may be environment-dependent).

### 7. Service Management

From the menu you can:

- **Start / Stop / Restart** the Xray service.
- **Enable / Disable** automatic start on boot.
- **Check status** via wrapped `systemctl` calls.

---

## Maintenance & Troubleshooting

### Backups & Restore

- **Backups:**
  - The script can create timestamped archives containing `config.json`, `clients.json`, and relevant helper files under `/usr/local/etc/xray/backups/`.
- **Restore:**
  - Choose a backup from the menu.
  - Confirm overwrite.
  - Restart Xray to apply the restored configuration.

### Logs

- **View logs:**
  - Tail or view Xray access/error logs.
  - View recent systemd journal entries for `xray.service`.
- **Save logs:**
  - Export logs to an archive in your home directory for sharing or offline analysis.
- **Clear logs:**
  - Truncate Xray logs.
  - Optionally vacuum related journal entries (irreversible, use with caution).

### REALITY Key Repair

A helper checks if the REALITY private key in `config.json` is missing or inconsistent and can:

- Regenerate a valid key pair.
- Update configuration files.
- Restart Xray.

Note: **Changing REALITY keys invalidates existing client configs**; regenerate URLs/QR codes afterwards.

### Removing Legacy VPN Systems

If you previously used other VPN tools on the same VPS, the script can help clean them up:

- Detect and remove WireGuard (interfaces, configs, services).
- Detect and remove Caddy (binary, service, configs).
- Detect and remove wstunnel.
- Optionally clean related firewall (`ufw`) rules.

Run this **only if you are sure you no longer need** these older setups.

### Uninstalling Xray

The uninstall routine:

1. Stops and disables the `xray` systemd service.
2. Uses the official Xray install script to remove binaries and configs.
3. Clears `/usr/local/etc/xray` and `/var/log/xray`.

The `xray-manager.sh` script itself is left in place; delete it manually if desired.

### Common Issues & Tips

- **Service wont start**
  - Use the menu option to view logs or run diagnostics.
  - Check `journalctl -u xray -n 50` for specific errors.
  - Validate config syntax with `xray -test -c /usr/local/etc/xray/config.json`.

- **Client cannot connect**
  - Ensure your VPS and local firewalls allow the chosen port.
  - **Firewall is the most common culprit!** Make sure to:
    - Configure your VPS provider firewall (Hetzner, DigitalOcean, etc.)
    - Run the local firewall configuration (auto-applied by the script)
    - Verify with: `ss -tlnp | grep xray`
  - Confirm the client is using the **correct**:
    - **IPv4 address** (not IPv6 - the script forces IPv4)
    - Port
    - UUID
    - REALITY public key
    - SNI / server name
    - Short ID
  - Run the built-in diagnostics for more hints.

- **"io: read/write on closed pipe" error on client**
  - This usually means the connection couldn't be established.
  - Likely causes:
    - VPS provider firewall not allowing the port (most common)
    - IPv6 address being used instead of IPv4
    - Port not actually listening (check: `ss -tlnp | grep 32145`)
  - Solution: Verify firewall rules and use IPv4 in client config.

- **Slow or unstable performance**
  - Check CPU and memory usage.
  - Try a different SNI/destination.
  - Investigate possible ISP throttling or packet inspection.

- **After changing keys/ports**
  - Always re-export URLs/QR codes and update all clients.

---

## Limitations & Security Notes

### Known Limitations

- Designed and tested primarily for **Debian/Ubuntu with systemd**.
- Assumes a **single inbound** REALITY-enabled VLESS configuration by default.
- Provides **basic** statistics only (no full bandwidth accounting).
- Depends on tools like `jq` and `qrencode`; behavior is degraded or unavailable without them.

### Security Considerations

- The script is usually run as **root**. Only trust scripts you have inspected.
- Protect all sensitive files:
  - `config.json`
  - `clients.json`
  - `public_key.txt` and REALITY keys
- Be careful when sharing VLESS URLs and QR codes; they grant direct access to your proxy.
- Rotate keys and clients periodically, and after any suspected compromise.

---

## Contributing & Customization

This project is delivered as a single Bash script and is easy to customize:

- Add or adjust menu entries.
- Extend diagnostics or logging behavior.
- Integrate with your own automation (e.g., Ansible, cloud-init).

Before making changes, its a good idea to **keep backups** of both:

- The script itself.
- Your Xray configuration directory.

---

## License

This repository currently does not include an explicit license file. If you plan to distribute modified versions, please add an appropriate license and attribution as needed.

