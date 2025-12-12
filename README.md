# isodhcp

**isodhcp** is a specialized, unnumbered DHCP server designed for secure
Linux routers hosting guest, IoT, or untrusted networks.

Unlike traditional DHCP servers that manage shared subnets (e.g., `/24`),
`isodhcp` is built to enforce strict **Layer 3 Client Isolation** at the
network edge. It allocates IP addresses and manages kernel routing tables
dynamically, forcing all client traffic to traverse the router gateway where
firewall policies can be enforced.

## Core Concepts

### 1. Isolated Mode (Default)
Clients receive a **`/32`** subnet mask (i.e., `255.255.255.255`). The server
injects a specific host route into the kernel for that client. This topology
prevents Layer 2 peer-to-peer communication entirely; clients cannot ARP for
neighbors, ensuring total isolation.

### 2. Micro-Segmentation (Compatibility Mode)
Some legacy devices (game consoles, older printers, simple IoT stacks)
malfunction when assigned a `/32` address.
* **The Solution:** `isodhcp` dynamically allocates a tiny **`/30`** subnet
  (4 IPs) for that specific device.
* It automatically adds a secondary alias IP to the router's interface to
  serve as the gateway for that micro-segment.
* The device sees a valid broadcast domain, but is effectively isolated in
  its own private network slice.

### 3. Playground Mode
For devices that require Layer 2 discovery protocols (e.g., Chromecast,
Apple TV) to function among a specific group of peers, `isodhcp` can reserve
a **Playground**—a contiguous block of IPs (e.g., a `/26`) that share a
standard subnet mask.

## Features

* **Topology Control:** Mix Isolated (`/32`), Legacy (`/30`), and Playground
  (`/26`) clients on the same physical interface.
* **Nftables Integration:** Automatically populates named sets (`nft_iso`,
  `nft_compat`, `nft_playground`) with client IPs as leases are granted or
  released, allowing for high-performance firewall rules.
* **DoS Protection:** Built-in ARP conflict detection and "quarantine" logic
  to prevent rogue devices from exhausting the address pool.
* **Masquerading:** Optional Source NAT (SNAT) support for clients that
  require traffic to appear as originating from the gateway.
* **Hook Scripts:** Triggers external scripts on lease changes with full
  context (IP, MAC, mode, gateway) via environment variables.

## Installation

The repository includes a helper script that sets up a Python virtual
environment, installs dependencies (`pyroute2`, `scapy`), and configures
`systemd` integration.

```bash
# Install (requires root)
sudo ./install.sh```

During installation, you will be prompted to choose an installation directory
(default: /usr/local/lib/isodhcp).

## Dependencies
* Python 3.6+
* scapy
* pyroute2
* Linux kernel with nftables support
* Systemd

## Configuration
isodhcp is configured entirely via command-line arguments passed to the
daemon. After installation, edit the `systemd` service file to match your
network topology:

```bash
sudo vi /usr/local/lib/isodhcp/isodhcp.service```

## Example Configuration:

```bash
/usr/local/bin/isodhcp \
    --interface guest0 \
    --pool 10.100.0.0/24 \
    --dns 1.1.1.1 \
    --playground-size 32 \
    --nft-set-isolated "inet filter client_iso" \
    --compat-oui "98:B6:E9"  # Nintendo Switch```

Once configured, start the service:

```bash
sudo systemctl start isodhcp```

## Documentation
For a complete reference of all command-line options, signal handling, and
hook script environment variables, please refer to the manual page:

[isodhcp(8)](isodhcp.8.md)

Or, after installation:

```bash
man isodhcp```

## Uninstalling
To remove the service, user, and files:

```bash
sudo ./uninstall.sh```
