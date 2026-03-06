<h1 align="center">
  <br>
  🌐 Universal Tunnel Manager v3.0
  <br>
</h1>

<p align="center">
  <em>A zero-to-prod CLI for creating, persisting & healing GRE/IPIP tunnels on any modern Linux box.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/bash-5.0+-orange?style=for-the-badge&logo=gnu-bash" alt="Bash">
  <img src="https://img.shields.io/badge/platform-linux-lightgrey?style=for-the-badge&logo=linux" alt="Platform">
</p>

<div align="center">

| 🚀 One-liner | <code>bash &lt;(curl -sSL https://raw.githubusercontent.com/alisamani1378/gre-tunnel-manager/main/auto-gre.sh)</code> |
|---|---|
| ✅ Tested on | Ubuntu 20.04+ • Debian 11+ • Alma 9+ • any recent x86_64/arm64 kernel (5.4+) |
| 🔑 Requires | **root** or **sudo** privileges |

</div>

---

## 📸 Preview

```
    ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
    ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
       ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
       ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
       ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
       ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝

    ███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗
    ████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗
    ██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝
    ██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗
    ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
```

---

## 🤔 Why GRE?

Generic Routing Encapsulation shines when you need ultra-light virtual links between servers, BGP neighbors, firewalls, or even Kubernetes clusters.
But keeping those links alive after reboots—and coaxing firewalls, MTU, and route rules into place—can be a chore.

**This script packages all that boilerplate into one guided, interactive wizard with a beautiful TUI.**

---

## ✨ New in v3.0

| What's New | Details |
|---|---|
| **Stunning TUI** | Full-color ASCII art banner, styled prompts, progress bars, animated spinners, and Unicode box drawing |
| **Status Dashboard** | Real-time view of all tunnels with ping health checks, service status, and IP info |
| **Structured Logging** | All operations logged to `/var/log/tunnel-manager.log` with colored log viewer |
| **System Info Panel** | Auto-detects hostname, kernel, CPU cores, memory, uptime, and public IP on launch |
| **Expanded Menu** | 7-option main menu with restart services, log viewer, optimizer, and dashboard |
| **Progress Bars** | Visual feedback during tunnel provisioning and cleanup operations |
| **Cleanup Tiers** | 3-tier cleanup: Full Reset / Soft Reset / Skip — no more accidental nukes |
| **Smart Interface View** | Shows IP and link state for each network interface during selection |

---

## 🎯 Features at a Glance

| Capability | What it does |
|---|---|
| **Interactive Wizard** | Guided step-by-step setup — no prior GRE knowledge required |
| **GRE + IPIP** | Supports both tunnel protocols via simple menu selection |
| **Instant Install** | Run straight from GitHub; nothing to clone or edit manually |
| **System Persistence** | Two purpose-built `systemd` services: <br/>`tunnel-persistence.service` — rebuilds tunnels & firewall at boot<br/>`tunnel-monitor.service` — auto-heals flapping tunnels via health pings |
| **DNS-Aware** | Monitors domain endpoints for IP changes and auto-rebuilds tunnels |
| **Smart IP Planner** | Auto-assigns internal /30 tunnel subnets (or manual override) |
| **Port Forwarding** | DNAT/SNAT rules for Iran-side servers with easy port mapping syntax |
| **Kernel Optimizer** | BBR + FQ sysctl profiles for TCP or UDP workloads |
| **NAT/Firewall** | Tagged iptables rules (`TMGR` comment) for clean add/remove |
| **Full Lifecycle** | Create, monitor, restart, diagnose, or destroy — all from one menu |
| **Self-Discovery** | Detects public IP, candidate NICs, and shows them before you decide |
| **Zero Extra Deps** | Uses only `bash`, `curl`, `ip`, and `iptables` — no Python, Go, or packages |

---

## 📋 Menu Structure

```
  ⚙ Main Menu
  ─────────────────────────────────────────────────
    1)  🚀 Create / Reconfigure Tunnels
        Interactive wizard for GRE/IPIP tunnel setup

    2)  📊 Tunnel Status Dashboard
        View real-time status of all tunnels & services

    3)  ⚙ Restart Services
        Restart persistence & monitor daemons

    4)  🔥 Kernel Optimizer
        Apply optimized TCP/UDP sysctl profiles

    5)  📊 View Logs
        Recent tunnel manager & monitor logs

    6)  ✘ Delete Everything
        Remove all tunnels, rules, config & services

    0)  Exit
```

---

## 🛠 How to Use

### Quick Start (Remote)
```bash
bash <(curl -sSL https://raw.githubusercontent.com/alisamani1378/gre-tunnel-manager/main/auto-gre.sh)
```

### Manual (Local)
```bash
git clone https://github.com/alisamani1378/gre-tunnel-manager.git
cd gre-tunnel-manager
chmod +x auto-gre.sh
sudo ./auto-gre.sh
```

---

## 🔧 Wizard Walkthrough

The wizard guides you through **6 steps**:

| Step | What You Choose |
|---|---|
| **1. Protocol** | GRE (recommended) or IPIP |
| **2. Location** | Iran-side (`.1` suffix) or Abroad (`.2` suffix) |
| **3. Cleanup** | Full Reset / Soft Reset / Skip existing config |
| **4. Interface** | Pick your main NIC from a list (with IPs & states shown) |
| **5. Endpoints** | Enter remote server IPs or domains (unlimited) |
| **6. IP Mode** | Auto-assign `/30` subnets or manual entry |

After that, the script automatically:
- Creates all tunnels with progress bar feedback
- Configures NAT/MASQUERADE rules
- Optionally sets up port forwarding (Iran side)
- Installs & enables systemd persistence + monitor services
- Offers kernel optimization (TCP or UDP profile)

---

## 📂 File Locations

| File | Purpose |
|---|---|
| `/etc/tunnel-manager.conf` | All tunnel/NAT/forwarding configuration |
| `/var/log/tunnel-manager.log` | Script operation log (color-coded viewer built-in) |
| `/usr/local/bin/tunnel-persistence.sh` | Boot-time tunnel restoration script |
| `/usr/local/bin/tunnel-monitor.sh` | Background health-check & auto-heal daemon |
| `/etc/systemd/system/tunnel-persistence.service` | systemd oneshot unit for boot restore |
| `/etc/systemd/system/tunnel-monitor.service` | systemd always-running monitor unit |

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      auto-gre.sh v3.0                        │
├──────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Banner  │  │  System  │  │  Wizard  │  │  Status  │    │
│  │    UI    │  │   Info   │  │  Engine  │  │ Dashboard│    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ iptables │  │  Tunnel  │  │  Config  │  │   Log    │    │
│  │ Helpers  │  │ Helpers  │  │  Manager │  │  Viewer  │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
├──────────────────────────────────────────────────────────────┤
│  systemd services:                                           │
│  ┌─────────────────────────┐ ┌─────────────────────────┐    │
│  │ tunnel-persistence.svc  │ │  tunnel-monitor.svc     │    │
│  │ (oneshot @ boot)        │ │  (always-on pinger)     │    │
│  └─────────────────────────┘ └─────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Notes

- All iptables rules are tagged with `TMGR` comment for safe identification & removal
- `gre0` / `ipip0` system tunnels are never touched (prevents kernel crashes)
- IP forwarding is enabled only when tunnels are configured
- Kernel optimizer creates a backup of `/etc/sysctl.conf` before overwriting
- Config file permissions default to root-only

---

## 📜 License

[MIT](LICENSE) — do whatever you want with it.

---

## 👤 Author

**Ali Samani** — [GitHub](https://github.com/alisamani1378)

---

<p align="center">
  <sub>Made with ❤️ for the networking community</sub>
</p>
