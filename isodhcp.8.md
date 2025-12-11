# isodhcp(8) - Unnumbered DHCP Server with Client Isolation

Linux, December 2025

```
isodhcp [-i interface] [-s server_ip] [-p pool_cidr] [-d dns_server] [-t lease_time] [-f lease_file] [--static mac=ip[,hostname][,compat][,masquerade]]... [--compat-mac mac]... [--compat-oui prefix]... [--compat-vendor string]... [--masquerade-mac mac]... [--masquerade-oui prefix]... [--masquerade-vendor string]... [--nft-set-isolated set_name] [--nft-set-compat set_name] [--nft-set-gateway set_name] [--nft-set-network set_name] [--nft-set-broadcast set_name] [--nft-set-subnet set_name]... [--hook-file path] [--isolation {on,off,system}]
```

<a name="description"></a>

# Description

**isodhcp**
is a lightweight, specialized DHCP server designed for secure Linux
routers hosting Guest, IoT, or untrusted networks.


Unlike standard DHCP servers, **isodhcp** utilizes an "Unnumbered
Interface" architecture. It assigns clients a **/32** subnet mask
(255.255.255.255), forcing all traffic - even traffic destined for
other devices on the same physical wire - to route through the gateway.


Simultaneously, **isodhcp** interacts directly with the Linux kernel using
**netlink** to inject explicit host routes for every connected client.
This combination allows the administrator to implement strict layer 3 client
isolation and granular firewalling (via **NFTables**) on the router,
effectively treating a shared Ethernet segment as a collection of
point-to-point links.


For legacy clients that lack support for point-to-point **/32** netmasks,
**isodhcp** can operate in a micro-segmentation mode that helps
with compatibility problems. For these clients, **isodhcp** dynamically
carves a **/30** subnet (4 IPs) out of the main pool. It assigns a secondary
alias IP to the router interface to serve as the gateway for that specific
client. The client sees a standard broadcast domain, but is effectively
isolated in its own tiny subnet.


Furthermore **isodhcp** can utilize source NAT'ing to make all traffic that
is directed towards a client look as if it originated from the gateway address
assigned to that client. This can help with restricted network implementations.


The daemon uses raw sockets (via **scapy**) to handle DHCP traffic, bypassing
standard UDP listeners. It includes built-in rate limiting to prevent DoS
attacks and manages lease persistence via a JSON file.


<a name="options"></a>

# Options


* **-d** _dns_, **--dns** _dns_  
  The DNS server IP address to offer clients. If omitted, the server parses
  _/etc/resolv.conf_ (and systemd-resolved upstream configurations) to find a
  valid IPv4 nameserver.

* **-f** _path_, **--lease-file** _path_  
  Path to the JSON file where lease state is persisted. Defaults to
  _dhcp\_leases\_\{INTERFACE\}.json_ in the current working directory. The server writes to
  this file on allocation, release, and shutdown. To minimize disk wear, renewals
  are only written if the expiration time changes significantly.

* **-i** _interface_, **--interface** _interface_  
  The network interface to listen on (e.g., _eth1_, _wlan0_). The server
  binds specifically to this interface to avoid conflicts with other DHCP servers
  on the host. Defaults to _guest_.

* **-p** _pool_, **--pool** _pool_  
  The CIDR range of IPs to allocate (e.g., _10.100.0.0/24_). If omitted, the
  server attempts to auto-detect the subnet configured on the interface.

* **-s** _server\_ip_, **--server-ip** _server\_ip_  
  The IP address of the router (gateway). If omitted, the server attempts to
  auto-detect the primary IP address assigned to the interface specified
  by **-i**.

* **-t** _seconds_, **--lease-time** _seconds_  
  The duration of the DHCP lease in seconds. Defaults to _3600_ (1 hour).

* **--compat-mac** _mac_  
  Treat the specified MAC address as a "legacy" client. Instead of receiving the
  standard strict **/32** netmask (client isolation), this device will be
  assigned a **/30** micro-segment with a netmask of **255.255.255.252**).  
  Useful for older printers, embedded devices, or game consoles that refuse to
  accept a gateway outside of their own subnet mask.  
  Example: _--compat-mac 00:11:22:33:44:55_
  
* **--compat-oui** _oui_  
  Treat any device whose MAC address starts with this 3-byte prefix
  (Organizationally Unique Identifier) as a legacy client.  
  The OUI format is _AA:BB:CC_. Case is insensitive.  
  Example: _--compat-oui B8:27:EB_ (Raspberry Pi Foundation)
  
* **--compat-vendor** _string_  
  Treat any device sending a DHCP Vendor Class Identifier (option 60) containing
  this substring as a legacy client.  
  Useful for broad classes of devices or operating systems known to struggle with
  unnumbered interfaces.  
  Example: _--compat-vendor "MSFT 5.0"_
  
* **--masquerade-mac** _mac_  
  The device with this MAC will have their traffic source NAT'd (SNAT) by the
  router. Traffic destined for these clients will appear to originate from the
  gateway IP itself, rather than the original sender.
  
* **--masquerade-oui** _prefix_  
  Apply source NAT to any device whose MAC address starts with this
  3-byte prefix.
  
* **--masquerade-vendor** _prefix_  
  Apply source NAT to any device that matches this DHCP Vendor Class Identifier.
  
* **--nft-set-isolated** _name_  
  The daemon can populate named **NFTables** sets for integration with
  firewall rules. Each option can only be given once and specifies an
  optional name for a set (e.g., _"inet filter iso\_clients"_). The set will
  not be created if it doesn't already exist. **--nft-set-isolated** names
  the set for standard **/32** clients.
* **--nft-set-compat** _name_  
  Set for legacy **/30** clients.
* **--nft-set-gateway** _name_  
  Set for the dynamic gateway IPs created for **/30** blocks.
* **--nft-set-network** _name_  
  Set for the network addresses of **/30** blocks.
* **--nft-set-broadcast** _name_  
  Set for the broadcast addresses of **/30** blocks.
* **--nft-set-subnet** _name_  
  Set for the CIDR blocks of **/30** allocations. **Note:** This set must have
  the **interval** flag enabled in **NFTables**.
* **--static** _mac=ip[,hostname][,compat][,masquerade]_  
  Map a MAC to a specific IP. Can be repeated.  
  **hostname**: (Optional) string to log for this device.  
  **compat**: (Optional) flag to force this device into legacy or
  compatibility mode.  
  **masquerade**: (Optional) enable source NAT for this client.  
  **Note:**
  For _compat_ entries, the IP must be the ".2" offset of a valid
  **/30** block (e.g., .2, .6, .10). The server will reserve the entire 4-IP
  block immediately at startup.  
  Static entries are initialized immediately at startup. The server configures the
  interface, routes, and firewall rules before the client even connects. These
  addresses are permanently removed from the free pool.
* **--hook-file** _path_  
  Path to an executable script (e.g., shell or Python) that is invoked whenever a
  lease is added or released. See **HOOK SCRIPT** below for details.
* **--isolation** _{on,off,system}_  
  In the vast majority of cases, the job of **isodhcp** is done as soon as it
  sends all traffic through the level 3 router. Policy decisions are supposed to
  be enforced by a third-party firewall. But sometimes, the situation is easy
  enough that it only requires minimal firewall rules. In that case, the daemon
  can be configured to actively block ("on") or actively allow ("off")
  communication between clients. The default is "system", which leaves the
  firewall unconfigured.
  

<a name="hook-script"></a>

# Hook Script

If **--hook-file** is specified, the server executes the script
asynchronously on lease changes.

**Arguments:**  
$1 = **add** or **del**  
$2 = MAC Address  
$3 = IP Address  
$4 = Hostname (if available)


**Environment Variables:**

* **ISODHCP_PID**  
  Process ID of the server.
* **ISODHCP_INTERFACE**  
  The listening interface (e.g., _guest_).
* **ISODHCP_SERVER_IP**  
  The router's main IP address.
* **ISODHCP_POOL_CIDR**  
  The network used to allocate the dynamic pool of IP addresses.
* **ISODHCP_DNS**  
  The DNS server advertised by the DHCP server.
* **ISODHCP_LEASE_FILE**  
  The JSON file where the server persists its internal state.
* **ISODHCP_TOTAL_LEASES**  
  Current count of active leases.
* **ISODHCP_FREE_IPS**  
  Current unassigned IP addresses.
* **ISODHCP_ISOLATION**  
  Current isolation mode. Can be "on", "off" or "system".
* **ISODHCP_MASQ**  
  "1" if Masquerade is enabled for this client, else "0".
* **ISODHCP_COMPAT**  
  "1" if legacy/compat mode is enabled, else "0".
* **ISODHCP_GATEWAY**  
  The specific gateway IP assigned to this client (varies for /30 clients).
* **ISODHCP_NETMASK**  
  The specific netmask for this client. Either "255.255.255.255"
  or "255.255.255.252".
* **ISODHCP_SUBNET**  
  The specific subnet assigned to this /30 client.
  

<a name="signals"></a>

# Signals


* **SIGINT, SIGTERM, SIGHUP**  
  The server catches these signals to perform an orderly shutdown. It flushes the
  current state of all leases to the JSON file before exiting.
* **SIGUSR1**  
  Reload configuration state. The server will re-scan the in-memory leases and
  re-apply all external system state:
    * Refresh **NFTables** sets (add missing elements, but don't remove any
      extraneous ones if present).
    * Re-add missing IP aliases to the interface.
    * Sync kernel routing table (restore missing /32 routes).
  

<a name="examples"></a>

# Examples


**1. Auto-detected configuration (standard usage)**  
Start the server on _guest0_. The server IP and pool are derived from the
interface's system configuration:

* **isodhcp -i guest0**
  

**2. Manual override with static IPs**  
Manually specify the gateway and pool, and assign a static IP to a printer:

* **isodhcp -i eth1 -s 192.168.50.1 -p 192.168.50.0/24 --static 00:11:22:33:44:55=192.168.50.10,laserprinter**
  

**3. High-turnover guest network**  
Set a short lease time (5 minutes) for a busy public Wi-Fi interface:

* **isodhcp -i wlan0 --lease-time 300**
  

**4. Systemd service definition**  
A typical _ExecStart_ and _ExecReload_ line in a systemd unit file:

* **ExecStart=/usr/bin/python3 /opt/isodhcp/server.py --interface eth1 --lease-file /opt/isodhcp/leases.json**
* **ExecReload=/bin/kill -USR1 $MAINPID**
  

**5. Handling legacy devices**  
Run the server with micro-segmentation for a specific printer, all
Raspberry Pis, and old Windows clients:

* **isodhcp -i eth1 --compat-mac 00:11:22:33:44:55 --compat-oui B8:27:EB --compat-vendor MSFT 5.0**
  

**6. Masquerading a specific device**  
Force a device with a specific MAC to be masqueraded behind the gateway IP:

* **isodhcp --masquerade-mac aa:bb:cc:dd:ee:ff**
  

**7. Advanced hybrid configuration**  
Run on _guest0_. Treat Nintendo Switch (OUI _98:B6:E9_) and Windows XP
clients as legacy. Assign a static IP to a client that can't handle /32 routes.
Populate **NFTables** sets for firewalling:

* **isodhcp -i guest0 --compat-oui 98:B6:E9 --compat-vendor "MSFT 5.0" --static 00:11:22:33:44:55=192.168.2.6,compat,masquerade --nft-set-isolated "inet filter client_iso" --nft-set-compat "inet filter client_legacy" --nft-set-gateway "inet filter local_gateways"**


**2. Static legacy reservation**  
Assign a printer to 10.100.0.10. Force it to use a /30 subnet (occupying
10.100.0.8/30) because it doesn't support /32:

* **isodhcp --static 00:11:22:33:44:55=10.100.0.10,printer,compat**
  

<a name="files"></a>

# Files


* _./dhcp_leases_<INTERFACE>.json_  
  The default location for lease persistence. Ensure the user running the daemon
  has write permissions to this file (or directory).
  

<a name="security-permissions"></a>

# Security & Permissions

To run **isodhcp** as an unprivileged user, the process requires the
following Linux capabilities:

* **CAP_NET_RAW**  
  Required to open raw sockets for sending/receiving DHCP packets via Scapy.
* **CAP_NET_ADMIN**  
  Required to modify the kernel routing table (adding/removing /32 routes via
  **netlink**).
* **CAP_NET_BIND_SERVICE**  
  Required to bind to port 67 (optional, depending on implementation
  details, but recommended).
  

In a systemd unit file, these can be assigned via:  
_AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP\_NET\_BIND\_SERVICE_


<a name="nftables-configuration"></a>

# Nftables Configuration

To use the **--nft-set-subnet** feature, the target set must be capable
of storing intervals (CIDRs). Example configuration in _/etc/nftables.conf_:

    table inet filter {
        set iso_clients { type ipv4_addr; }
        set compat_subnets {
            type ipv4_addr
            flags interval
        }
    }


<a name="avahi-mdns-interaction"></a>

# Avahi / Mdns Interaction

By default, this server disables **Promiscuous Mode** on the raw socket to
prevent the OS from flagging a "link change" event. This prevents local mDNS
daemons (like Avahi) from flushing their cache every time the server restarts.

To ensure proper mDNS reflection between the isolated network and a trusted
network, ensure the router interface has a valid IP address within the pool
range (e.g., _10.100.0.1/24_), even though clients are assigned _/30_
and _/32_ masks.


<a name="see-also"></a>

# See Also

**ip**(8),
**nftables**(8),
**avahi-daemon**(8)
