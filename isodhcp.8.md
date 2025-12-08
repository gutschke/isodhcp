# NAME

isodhcp - Unnumbered DHCP Server with Client Isolation

# SYNOPSIS

**isodhcp** \[**-d** *dns_server*\] \[**-f** *lease_file*\] \[**-i**
*interface*\] \[**-p** *pool_cidr*\] \[**-s** *server_ip*\] \[**-t**
*lease_time*\] \[**\--compat-mac** *mac*\] \[**\--compat-oui** *oui*\]
\[**\--compat-vendor** *string*\] \[**\--static**
*mac=ip{,hostname}*\]\...

# DESCRIPTION

**isodhcp** is a lightweight, specialized DHCP server designed for Linux
routers hosting Guest, IoT, or untrusted networks.

Unlike standard DHCP servers, **isodhcp** utilizes an \"Unnumbered
Interface\" architecture. It assigns clients a **/32** subnet mask
(255.255.255.255), forcing all traffic - even traffic destined for other
devices on the same physical wire - to route through the gateway.

Simultaneously, **isodhcp** interacts directly with the Linux kernel
using Netlink to inject explicit host routes for every connected client.
This combination allows the administrator to implement strict Layer 3
Client Isolation and granular firewalling (via nftables) on the router,
effectively treating a shared Ethernet segment as a collection of
point-to-point links.

The daemon uses raw sockets (via Scapy) to handle DHCP traffic,
bypassing standard UDP listeners. It includes built-in rate limiting to
prevent DoS attacks and manages lease persistence via a JSON file.

While the server defaults to strict isolation (/32 masks), it includes a
**Compatibility Mode** to dynamically provide standard netmasks (e.g.,
/24) to specific legacy clients identified by MAC address, OUI prefix,
or Vendor ID.

# OPTIONS

**-d*** dns***, \--dns ***dns*

:   The DNS server IP address to offer clients. If omitted, the server
    parses */etc/resolv.conf* (and systemd-resolved upstream
    configurations) to find a valid IPv4 nameserver.

**-f*** path***, \--lease-file ***path*

:   Path to the JSON file where lease state is persisted. Defaults to
    *dhcp_leases.json* in the current working directory. The server
    writes to this file on allocation, release, and shutdown. To
    minimize disk wear, renewals are only written if the expiration time
    changes significantly.

**-i*** interface***, \--interface ***interface*

:   The network interface to listen on (e.g., *eth1*, *wlan0*). The
    server binds specifically to this interface to avoid conflicts with
    other DHCP servers on the host. Defaults to *guest*.

**-p*** pool***, \--pool ***pool*

:   The CIDR range of IPs to allocate (e.g., *10.100.0.0/24*). If
    omitted, the server attempts to auto-detect the subnet configured on
    the interface.

**-s*** server_ip***, \--server-ip ***server_ip*

:   The IP address of the router (gateway). If omitted, the server
    attempts to auto-detect the primary IP address assigned to the
    interface specified by **-i**.

**-t*** seconds***, \--lease-time ***seconds*

:   The duration of the DHCP lease in seconds. Defaults to *3600* (1
    hour).

**\--compat-mac*** mac*

:   Treat the specified MAC address as a \"legacy\" client. Instead of
    receiving the standard strict **/32** netmask (client isolation),
    this device will receive the actual CIDR netmask of the pool (e.g.,
    **255.255.255.0**).\
    Useful for older printers, embedded devices, or game consoles that
    refuse to accept a gateway outside of their own subnet mask.\
    Example: *\--compat-mac 00:11:22:33:44:55*

**\--compat-oui*** oui*

:   Treat any device whose MAC address starts with this 3-byte prefix
    (Organizationally Unique Identifier) as a legacy client.\
    The OUI format is *AA:BB:CC*. Case is insensitive.\
    Example: *\--compat-oui B8:27:EB* (Raspberry Pi Foundation)

**\--compat-vendor*** string*

:   Treat any device sending a DHCP Vendor Class Identifier (option 60)
    containing this substring as a legacy client.\
    Useful for broad classes of devices or operating systems known to
    struggle with unnumbered interfaces.\
    Example: *\--compat-vendor \"MSFT 5.0\"*

**\--static*** mac=ip*

:   Maps a specific MAC address to a fixed IP. This option can be
    repeated multiple times.\
    Format: *aa:bb:cc:dd:ee:ff=192.168.1.50{,hostname}*.\
    Static IPs are removed from the dynamic pool at startup. If a
    conflict exists in the persistent lease file, the static mapping
    takes precedence.

# SIGNALS

**SIGINT, SIGTERM**

:   The server catches these signals to perform an orderly shutdown. It
    flushes the current state of all leases to the JSON file before
    exiting.

# EXAMPLES

**1. Auto-detected configuration (Standard Usage)**\
Start the server on *guest0*. The server IP and Pool are derived from
the interface\'s system configuration:

> **isodhcp -i guest0**

**2. Manual Override with Static IPs**\
Manually specify the gateway and pool, and assign a static IP to a
printer:

> **isodhcp -i eth1 -s 192.168.50.1 -p 192.168.50.0/24 \--static
> 00:11:22:33:44:55=192.168.50.10,laserprinter**

**3. High-Turnover Guest Network**\
Set a short lease time (5 minutes) for a busy public Wi-Fi interface:

> **isodhcp -i wlan0 \--lease-time 300**

**4. Systemd Service Definition**\
A typical *ExecStart* line in a systemd unit file:

> **ExecStart=/usr/bin/python3 /opt/isodhcp/server.py \--interface eth1
> \--lease-file /opt/isodhcp/leases.json**

**5. Handling Legacy Devices**\
Run the server while relaxing isolation for a specific printer, all
Raspberry Pis, and old Windows clients:

> **isodhcp -i eth1 \--compat-mac 00:11:22:33:44:55 \--compat-oui
> B8:27:EB \--compat-vendor MSFT 5.0**

# FILES

*./dhcp_leases.json*

:   The default location for lease persistence. Ensure the user running
    the daemon has write permissions to this file (or directory).

# SECURITY & PERMISSIONS

To run **isodhcp** as an unprivileged user, the process requires the
following Linux Capabilities:

**CAP_NET_RAW**

:   Required to open raw sockets for sending/receiving DHCP packets via
    Scapy.

**CAP_NET_ADMIN**

:   Required to modify the kernel routing table (adding/removing /32
    routes via Netlink).

**CAP_NET_BIND_SERVICE**

:   Required to bind to port 67 (optional, depending on implementation
    details, but recommended).

In a systemd unit file, these can be assigned via:\
*AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE*

# AVAHI / MDNS INTERACTION

By default, this server disables **Promiscuous Mode** on the raw socket
to prevent the OS from flagging a \"Link Change\" event. This prevents
local mDNS daemons (like Avahi) from flushing their cache every time the
server restarts.

To ensure proper mDNS reflection between the isolated network and a
trusted network, ensure the router interface has a valid IP address
within the pool range (e.g., *10.100.0.1/24*), even though clients are
assigned */32* masks.

# SEE ALSO

**ip**(8), **nftables**(8), **avahi-daemon**(8)
