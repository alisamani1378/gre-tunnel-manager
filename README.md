<h1 align="center">🌐 Universal GRE Tunnel Manager</h1>
<p align="center"><em>
A zero-to-prod CLI for creating, persisting & healing GRE tunnels on any modern Linux box.
</em></p>

<div align="center">

| 🚀 One-liner | <code>bash &lt;(curl -sSL https://raw.githubusercontent.com/alisamani1378/gre-tunnel-manager/main/auto-gre.sh)</code> |
|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ✅ Tested on | Ubuntu 20.04 + • Debian 11 + • Alma 9 + • any recent x86_64 / arm64 kernel (5.4 +) |
| 🔑 Requires | <strong>root</strong> or <strong>sudo</strong> privileges |
  
</div>

---

## Why GRE?

Generic Routing Encapsulation shines when you need ultra-light virtual links between servers, BGP neighbors, firewalls, or even Kubernetes clusters.  
But keeping those links alive after reboots—and coaxing firewalls, MTU, and route rules into place—can be a chore.  
**This script packages all that boilerplate into one guided, interactive wizard.**

---

## ✨ Features at a Glance

| Capability | What it does |
|------------|--------------|
| **Interactive wizard** | Step-by-step questions—no prior GRE kung-fu required. |
| **Instant install** | Run straight from GitHub; nothing to clone or edit manually. |
| **System persistence** | Creates two purpose-built `systemd` units: <br/>`gre-persistence.service` — re-builds tunnels & firewall rules at boot.<br/>`gre-monitor.service` — background pinger that auto-revives any flapping tunnel. |
| **Smart IP planner** | Auto-assigns internal /30 tunnel addresses based on whether the server is inside or outside Iran (editable). |
| **Full tunnel lifecycle** | Build, list, or nuke every tunnel & service from a single menu. |
| **Self-discovery** | Detects public IP, candidate NICs, and shows them before you decide. |
| **Zero extra deps** | Uses only `bash`, `curl`, `ip(route|link)`, and `iptables`; no Python, Go, or obscure packages. |

---

## 🛠 How to Use

```bash
bash <(curl -sSL https://raw.githubusercontent.com/alisamani1378/gre-tunnel-manager/main/auto-gre.sh)
