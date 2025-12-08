# isodhcp(8) - Unnumbered DHCP Server with Client Isolation

Linux, December 2025

```
isodhcp [-d dns_server] [-f lease_file] [-i interface] [-p pool_cidr] [-s server_ip] [-t lease_time] [--compat-mac mac] [--compat-oui oui] [--compat-vendor string] [--static mac=ip{,hostname}]...
```

<a name="description"></a>

# Description

**isodhcp**
is a lightweight, specialized DHCP server designed for Linux routers hosting Guest, IoT, or untrusted networks.

Unlike standard DHCP servers, **isodhcp** utilizes an "Unnumbered
Interface" architecture. It assigns clients a **/32** subnet mask
(255.255.255.255), forcing all traffic - even traffic destined for
other devices on the same physical wire - to route through the gateway.

Simultaneously, **isodhcp** interacts directly with the Linux kernel using Netlink to inject explicit host routes for every connected client. This combination allows the administrator to implement strict Layer 3 Client Isolation and granular firewalling (via nftables) on the router, effectively treating a shared Ethernet segment as a collection of point-to-point links.

The daemon uses raw sockets (via Scapy) to handle DHCP traffic, bypassing standard UDP listeners. It includes built-in rate limiting to prevent DoS attacks and manages lease persistence via a JSON file.

While the server defaults to strict isolation (/32 masks), it includes a **Compatibility Mode** to dynamically provide standard netmasks (e.g., /24) to specific legacy clients identified by MAC address, OUI prefix, or Vendor ID.

<a name="options"></a>

# Options


* **-d**_ dns_**, --dns **_dns_  
  The DNS server IP address to offer clients. If omitted, the server parses _/etc/resolv.conf_ (and systemd-resolved upstream configurations) to find a valid IPv4 nameserver.
  
* **-f**_ path_**, --lease-file **_path_  
  Path to the JSON file where lease state is persisted. Defaults to _dhcp\_leases.json_ in the current working directory. The server writes to this file on allocation, release, and shutdown. To minimize disk wear, renewals are only written if the expiration time changes significantly.
  
* **-i**_ interface_**, --interface **_interface_  
  The network interface to listen on (e.g., _eth1_, _wlan0_). The server binds specifically to this interface to avoid conflicts with other DHCP servers on the host. Defaults to _guest_.
  
* **-p**_ pool_**, --pool **_pool_  
  The CIDR range of IPs to allocate (e.g., _10.100.0.0/24_). If omitted, the server attempts to auto-detect the subnet configured on the interface.
  
* **-s**_ server_ip_**, --server-ip **_server_ip_  
  The IP address of the router (gateway). If omitted, the server attempts to auto-detect the primary IP address assigned to the interface specified by **-i**.
  
* **-t**_ seconds_**, --lease-time **_seconds_  
  The duration of the DHCP lease in seconds. Defaults to _3600_ (1 hour).
* **--compat-mac**_ mac_  
  Treat the specified MAC address as a "legacy" client. Instead of receiving the standard strict **/32** netmask (client isolation), this device will receive the actual CIDR netmask of the pool (e.g., **255.255.255.0**).  
  Useful for older printers, embedded devices, or game consoles that refuse to accept a gateway outside of their own subnet mask.  
  Example: _--compat-mac 00:11:22:33:44:55_
  
* **--compat-oui**_ oui_  
  Treat any device whose MAC address starts with this 3-byte prefix (Organizationally Unique Identifier) as a legacy client.  
  The OUI format is _AA:BB:CC_. Case is insensitive.  
  Example: _--compat-oui B8:27:EB_ (Raspberry Pi Foundation)
  
* **--compat-vendor**_ string_  
  Treat any device sending a DHCP Vendor Class Identifier (option 60) containing this substring as a legacy client.  
  Useful for broad classes of devices or operating systems known to struggle with unnumbered interfaces.  
  Example: _--compat-vendor "MSFT 5.0"_
  
* **--static**_ mac=ip_  
  Maps a specific MAC address to a fixed IP. This option can be repeated multiple times.  
  Format: _aa:bb:cc:dd:ee:ff=192.168.1.50{,hostname}_.  
  Static IPs are removed from the dynamic pool at startup. If a conflict exists in the persistent lease file, the static mapping takes precedence.
  

<a name="signals"></a>

# Signals


* **SIGINT, SIGTERM**  
  The server catches these signals to perform an orderly shutdown. It flushes the current state of all leases to the JSON file before exiting.
  

<a name="examples"></a>

# Examples


**1. Auto-detected configuration (Standard Usage)**  
Start the server on _guest0_. The server IP and Pool are derived from the interface's system configuration:

* **isodhcp -i guest0**
  

**2. Manual Override with Static IPs**  
Manually specify the gateway and pool, and assign a static IP to a printer:

* **isodhcp -i eth1 -s 192.168.50.1 -p 192.168.50.0/24 --static 00:11:22:33:44:55=192.168.50.10,laserprinter**
  

**3. High-Turnover Guest Network**  
Set a short lease time (5 minutes) for a busy public Wi-Fi interface:

* **isodhcp -i wlan0 --lease-time 300**
  

**4. Systemd Service Definition**  
A typical _ExecStart_ line in a systemd unit file:

* **ExecStart=/usr/bin/python3 /opt/isodhcp/server.py --interface eth1 --lease-file /opt/isodhcp/leases.json**
  

**5. Handling Legacy Devices**  
Run the server while relaxing isolation for a specific printer, all Raspberry Pis, and old Windows clients:

* **isodhcp -i eth1 --compat-mac 00:11:22:33:44:55 --compat-oui B8:27:EB --compat-vendor MSFT 5.0**
  

<a name="files"></a>

# Files


* _./dhcp_leases.json_  
  The default location for lease persistence. Ensure the user running the daemon has write permissions to this file (or directory).
  

<a name="security-permissions"></a>

# Security & Permissions

To run **isodhcp** as an unprivileged user, the process requires the following Linux Capabilities:

* **CAP_NET_RAW**  
  Required to open raw sockets for sending/receiving DHCP packets via Scapy.
* **CAP_NET_ADMIN**  
  Required to modify the kernel routing table (adding/removing /32 routes via Netlink).
* **CAP_NET_BIND_SERVICE**  
  Required to bind to port 67 (optional, depending on implementation details, but recommended).
  

In a systemd unit file, these can be assigned via:  
_AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP\_NET\_BIND\_SERVICE_


<a name="avahi-mdns-interaction"></a>

# Avahi / Mdns Interaction

By default, this server disables **Promiscuous Mode** on the raw socket to prevent the OS from flagging a "Link Change" event. This prevents local mDNS daemons (like Avahi) from flushing their cache every time the server restarts.

To ensure proper mDNS reflection between the isolated network and a trusted network, ensure the router interface has a valid IP address within the pool range (e.g., _10.100.0.1/24_), even though clients are assigned _/32_ masks.


<a name="see-also"></a>

# See Also

**ip**(8),
**nftables**(8),
**avahi-daemon**(8)
