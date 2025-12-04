import argparse
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
from scapy.all import *
from pyroute2 import IPRoute

INTERFACE = "guest"
LEASE_FILE = "dhcp_leases.json"
LEASE_TIME = 3600

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class LeaseManager:
    def __init__(self, pool_cidr, server_ip, lease_file, lease_time):
        self.network = ipaddress.IPv4Network(pool_cidr)
        self.server_ip = ipaddress.IPv4Address(server_ip)
        self.lease_file = lease_file
        self.lease_time = lease_time
        self.lock = threading.Lock()

        # In-memory storage
        self.leases = {}     # MAC -> {'ip': str, 'expires': float,
                             #         'hostname': str (opt) }
        self.ip_to_mac = {}  # IP -> MAC

        # Calculate Free IPs
        self.all_possible_ips = set()
        for ip in self.network.hosts():
            if ip != self.server_ip:
                self.all_possible_ips.add(str(ip))

        self.free_ips = self.all_possible_ips.copy()

        # Load from disk immediately
        self.load_leases()

    def load_leases(self):
        """Loads leases from disk and filters out expired ones."""
        if not os.path.exists(self.lease_file):
            return

        try:
            with open(self.lease_file, 'r') as f:
                saved_data = json.load(f)

            now = time.time()
            loaded_count = 0

            for mac, data in saved_data.items():
                ip = data['ip']
                expires = data['expires']

                # Only load if valid and valid IP
                if expires > now and ip in self.all_possible_ips:
                    self.leases[mac] = {'ip': ip, 'expires': expires}
                    if 'hostname' in data:
                        self.leases[mac]['hostname'] = data['hostname']
                    self.ip_to_mac[ip] = mac
                    if ip in self.free_ips:
                        self.free_ips.remove(ip)
                    loaded_count += 1

            logger.info(f"📁 Loaded {loaded_count} active leases from disk.")

        except Exception as e:
            logger.error(f"Failed to load lease file: {e}")

    def save_leases(self, force=False):
        """
        Persists leases to JSON.
        'force' overrides the optimization check.
        """
        try:
            # We dump the whole dictionary.
            # Ideally, atomic write: write to temp file, then rename.
            tmp_file = self.lease_file + ".tmp"
            with open(tmp_file, 'w') as f:
                json.dump(self.leases, f, indent=2)
            os.replace(tmp_file, self.lease_file)
        except Exception as e:
            logger.error(f"Failed to write lease file: {e}")

    def allocate_or_renew(self, mac, hostname=None):
        with self.lock:
            current_time = time.time()
            write_needed = False
            h = f'"{hostname}" ' if hostname else ''

            # RENEWAL
            if mac in self.leases:
                lease = self.leases[mac]
                old_expires = lease['expires']
                new_expires = current_time + self.lease_time

                lease['expires'] = new_expires

                if not h and 'hostname' in lease:
                    h = f'"{lease['hostname']}" '

                # DISK WEAR OPTIMIZATION:
                # Only write to disk if the extension is significant.
                # If we updated disk < 20% of lease time ago, skip writing.
                threshold = self.lease_time * 0.2
                if (new_expires - old_expires) > threshold:
                    write_needed = True
                    logger.info(f"♻️ Renewing lease for {h}{mac}, "
                                f"IPv4 {lease['ip']} (saving to disk)")
                else:
                    logger.debug(f"♻️ Renewing lease for {h}{mac}, "
                                 f"IPv4 {lease['ip']} (skipping "
                                 f"disk write)")

                if write_needed:
                    self.save_leases()
                return lease['ip']

            # NEW ALLOCATION
            if not self.free_ips:
                return None

            new_ip = self.free_ips.pop()
            self.leases[mac] = {
                'ip': new_ip,
                'expires': current_time + self.lease_time
            }
            if hostname:
                self.leases[mac]['hostname'] = hostname
            self.ip_to_mac[new_ip] = mac

            # Always save on new allocation
            logger.info(f"✨ Allocated {new_ip} to {h}{mac}")
            self.save_leases()
            return new_ip

    def release(self, mac):
        with self.lock:
            if mac in self.leases:
                ip = self.leases[mac]['ip']
                self.free_ips.add(ip)
                del self.ip_to_mac[ip]
                del self.leases[mac]
                # Always save on release
                self.save_leases()
                return ip
        return None

    def get_expired_leases(self):
        """Finds expired leases and cleans internal state"""
        expired_entries = [] # List of (mac, ip)
        with self.lock:
            now = time.time()
            # Identify
            for mac, data in list(self.leases.items()):
                if data['expires'] < now:
                    expired_entries.append((mac, data['ip']))

            # Cleanup
            for mac, ip in expired_entries:
                self.free_ips.add(ip)
                del self.ip_to_mac[ip]
                del self.leases[mac]

        return expired_entries

class RateLimiter:
    def __init__(self, rate=1.0, burst=5):
        self.rate = rate          # Tokens added per second
        self.burst = burst        # Maximum bucket size
        self.clients = {}         # MAC -> {tokens: float, last_update: float}
        self.lock = threading.Lock()

    def is_allowed(self, mac):
        now = time.time()

        with self.lock:
            # Initialize new client
            if mac not in self.clients:
                self.clients[mac] = {
                    'tokens': self.burst - 1,
                    'last_update': now
                }
                return True

            client = self.clients[mac]
            elapsed = now - client['last_update']
            client['last_update'] = now
            client['tokens'] = min(self.burst,
                                   client['tokens'] + (elapsed * self.rate))
            if client['tokens'] >= 1.0:
                client['tokens'] -= 1.0
                return True
            else:
                return False

    def cleanup(self):
        """Periodically remove old clients to save RAM"""
        now = time.time()
        with self.lock:
            # Remove clients we haven't seen in 1 hour
            stale_macs = [
                mac for mac,
                data in self.clients.items()
                if (now - data['last_update']) > 3600
            ]
            for mac in stale_macs:
                del self.clients[mac]
            if stale_macs:
                logging.debug(f"🧹 RateLimiter cleaned up {len(stale_macs)} "
                              f"stale MACs")

class UnnumberedDHCPServer:
    def __init__(self, interface, server_ip=None, pool_cidr=None,
                 dns_server=None, lease_time=LEASE_TIME,
                 lease_file=LEASE_FILE):
        self.iface = interface
        self.lease_time = lease_time
        self.lease_file = lease_file
        self.limiter = RateLimiter(rate=2.0, burst=5)

        # Detect IP/Pool
        if not server_ip or not pool_cidr:
            try:
                detected_ip, detected_cidr = \
                    self.get_interface_details(interface)
                self.server_ip = server_ip if server_ip else detected_ip
                self.pool_cidr = pool_cidr if pool_cidr else detected_cidr
                logger.info(f"🔎 Auto-detected: IP={self.server_ip}, "
                            f"Pool={self.pool_cidr}")
            except Exception as e:
                logger.critical(f"Auto-detect failed: {e}")
                exit(1)
        else:
            self.server_ip = server_ip
            self.pool_cidr = pool_cidr

        # Detect DNS
        if not dns_server:
            self.dns_server = self.get_system_dns()
            logger.info(f"🔎 Auto-detected DNS: {self.dns_server}")
        else:
            self.dns_server = dns_server

        self.server_mac = get_if_hwaddr(interface)
        self.ipr = IPRoute()
        self.if_index = self.ipr.link_lookup(ifname=self.iface)[0]

        # Pass configs to LeaseManager
        self.lease_mgr = LeaseManager(self.pool_cidr, self.server_ip,
                                      self.lease_file, self.lease_time)
        self.sync_kernel_routes()

        self.gc_thread = threading.Thread(target=self.garbage_collector,
                                          daemon=True)
        self.gc_thread.start()

    def sync_kernel_routes(self):
        """
        Reconciles the Linux Kernel Routing Table with the Lease Database.
        1. Adds routes for leases we loaded from disk but are missing in kernel.
        2. Deletes routes that exist in kernel but we have no lease for (Stale).
        """
        logger.info("⚙️ Syncing kernel routes with lease database...")

        # Get all routes currently on this interface
        # We filter for /32 routes (host routes) on our specific interface
        current_routes = self.ipr.get_routes(oif=self.if_index,
                                             family=2) # family 2 = IPv4

        active_kernel_ips = set()

        for r in current_routes:
            # Parse the destination attribute
            dst_attr = dict(r['attrs']).get('RTA_DST')
            dst_len = r['dst_len']

            # We only care about /32 routes that look like our pool
            # (ignoring multicast, broadcast, or the gateway itself)
            if dst_len == 32 and dst_attr:
                active_kernel_ips.add(dst_attr)

        # Get all IPs we THINK we have
        # (Since we just loaded from disk, this is our source of truth)
        valid_lease_ips = set(self.lease_mgr.ip_to_mac.keys())

        # Repair Missing Routes (Lease exists, Route missing)
        to_add = valid_lease_ips - active_kernel_ips
        for ip in to_add:
            logger.warning(f"🔧 Repairing missing route for {ip}")
            self.inject_host_route(ip)

        # Remove Stale Routes (Route exists, Lease missing)
        # Only delete IPs that fall within our managed POOL to be safe
        pool_net = ipaddress.IPv4Network(self.pool_cidr)

        for ip in active_kernel_ips:
            if ip not in valid_lease_ips:
                # Ensure we don't delete the server's own IP or unrelated
                # routes
                ip_obj = ipaddress.IPv4Address(ip)
                if (ip_obj in pool_net and
                    ip != self.server_ip and
                    ip_obj != pool_net.broadcast_address and
                    ip_obj != pool_net.network_address):
                    logger.warning(f"🧹 Removing stale route for {ip}")
                    self.delete_host_route(ip)

        logger.info("✅ Route Sync complete.")

    def inject_host_route(self, client_ip):
        try:
            # Check if route already exists to avoid log spam
            # (In production, pyroute2 raises specific errors, but this is
            # safe)
            self.ipr.route("replace",
                           dst=f"{client_ip}/32", oif=self.if_index)
            logger.debug(f"mapped {client_ip} -> {self.iface}")
        except Exception as e:
            logger.error(f"Route add failed: {e}")

    def delete_host_route(self, client_ip):
        try:
            self.ipr.route("del", dst=f"{client_ip}/32", oif=self.if_index)
            logger.info(f"🗑️ Route deleted: {client_ip}")
        except Exception as e:
            # It's okay if it's already gone
            pass

    def garbage_collector(self):
        """Background thread to clean up routes and leases"""
        while True:
            time.sleep(10) # Check every 10 seconds
            expired = self.lease_mgr.get_expired_leases()
            for mac, ip in expired:
                logger.info(f"⏳ Lease expired for {mac}, IPv4 {ip}. "
                            f"Cleaning up.")
                self.delete_host_route(ip)
            self.limiter.cleanup()

    def get_client_requested_ip(self, pkt):
        """Combined logic to find what IP the client is talking about"""
        if DHCP in pkt:
            dhcp_opts = {
                opt[0]: opt[1]
                for opt in pkt[DHCP].options if isinstance(opt, tuple)
            }
            if 'requested_addr' in dhcp_opts:
                return dhcp_opts['requested_addr']

        if BOOTP in pkt and pkt[BOOTP].ciaddr != "0.0.0.0":
            return pkt[BOOTP].ciaddr
        return None

    def get_hostname(self, dhcp_opts):
        """
        Safely extracts and decodes the hostname from DHCP options.
        Returns None if missing or malformed.
        """
        # Get the raw value (usually bytes, e.g., b'MyLaptop')
        raw_name = dhcp_opts.get('hostname')

        if not raw_name:
            return None

        # Decode Bytes -> String
        if isinstance(raw_name, bytes):
            try:
                # 'replace' inserts a  character for invalid bytes instead of
                # crashing
                hostname = raw_name.decode('utf-8', errors='replace')
            except Exception:
                # Fallback for extremely weird encodings
                hostname = raw_name.decode('latin-1', errors='replace')
        else:
            # Sometimes Scapy or other libs might auto-decode it
            hostname = str(raw_name)

        # Sanitize (Remove control characters like newlines or tabs)
        # This prevents a malicious client from breaking your log format
        clean_name = "".join(ch for ch in hostname if ch.isprintable()).strip()

        return clean_name if clean_name else None

    def handle_dhcp(self, pkt):
        try:
            if not (DHCP in pkt and pkt[DHCP].options):
                return

            # Uncomment to debug DHCP protocol.
            # logger.info(pkt.show(dump=True))

            dhcp_opts = {
                opt[0]: opt[1]
                for opt in pkt[DHCP].options if isinstance(opt, tuple)
            }
            msg_type = dhcp_opts.get("message-type")
            hostname = self.get_hostname(dhcp_opts)
            client_mac = pkt[Ether].src.lower()
            xid = pkt[BOOTP].xid

            if not re.match(r"[0-9a-f]{2}([:][0-9a-f]{2}){5}$", client_mac):
                logger.warning(f"⚠️ Ignoring packet with invalid MAC: "
                               f"{client_mac}")
                return

            # Rate limit traffic per MAC address
            if not self.limiter.is_allowed(client_mac):
                return

            # DISCOVER (Client needs an IP) ---
            if msg_type == 1:
                assigned_ip = self.lease_mgr.allocate_or_renew(client_mac,
                                                               hostname)
                if assigned_ip:
                    self.send_reply(pkt, "offer", assigned_ip, xid, client_mac)

            # REQUEST (Client accepts offer or renews) ---
            elif msg_type == 3:
                req_ip = self.get_client_requested_ip(pkt)

                # Security Check: Did we actually assign this IP to this MAC?
                # We peek into the lease manager without changing state yet
                current_owner_mac = self.lease_mgr.ip_to_mac.get(req_ip)

                # Case A: It's a valid request for an IP we reserved for them
                if current_owner_mac == client_mac:
                    # Confirm allocation (updates timestamp)
                    final_ip = self.lease_mgr.allocate_or_renew(client_mac,
                                                                hostname)

                    # Setup Networking
                    self.inject_host_route(final_ip)
                    self.send_reply(pkt, "ack", final_ip, xid, client_mac)

                # Case B: They are asking for an IP requesting someone else's
                # IP or garbage
                else:
                    logger.warning(f"NAK: {client_mac} requested {req_ip} but "
                                   f"it belongs to {current_owner_mac}")
                    self.send_reply(pkt, "nak", req_ip, xid, client_mac)

            # RELEASE (Client is shutting down politely) ---
            elif msg_type == 7:
                 req_ip = pkt[BOOTP].ciaddr
                 # Only allow release if the IP actually belongs to them
                 if self.lease_mgr.ip_to_mac.get(req_ip) == client_mac:
                     released_ip = self.lease_mgr.release(client_mac)
                     if released_ip:
                         self.delete_host_route(released_ip)
        except Exception as e:
            logger.error(f"⚠️ Malformed packet caused crash: {e}")
            return

    def build_option_121(self, gateway_ip):
        """
        Constructs the binary payload for Option 121.
        We want to tell the client:
        "The route to 0.0.0.0/0 is via <gateway_ip>"
        """
        # Convert string IP (e.g., "172.24.0.1") to 4 bytes
        gw_bytes = socket.inet_aton(gateway_ip)

        # Default Route (0.0.0.0/0)
        # Structure: [Mask=0] + [No Prefix] + [Gateway Bytes]
        default_route = b'\x00' + gw_bytes

        # OPTIONAL: Host route to the Gateway itself
        # Sometimes clients refuse to use a gateway that isn't in their
        # subnet. We can tell them:
        # "To reach 192.168.1.1/32, go to 0.0.0.0 (On-link)"
        # Note: In Option 121, "0.0.0.0" as a gateway means "On-link".
        return default_route

    def send_reply(self, old_pkt, msg_type, client_ip, xid, client_mac):
        op_code = 5 if msg_type == "ack" else 2 # Ack or Offer
        if msg_type == "nak": op_code = 6

        options = [
            ("message-type", op_code),
            ("server_id", self.server_ip),
        ]

        if msg_type != "nak":
            # Generate the raw bytes for Option 121
            opt_121_payload = self.build_option_121(self.server_ip)

            options.extend([
                ("lease_time", self.lease_time),
                ("subnet_mask", "255.255.255.255"), # /32 isolation

                # --- IMPORTANT: ROUTER OPTION LOGIC ---
                # RFC 3442 says: If Option 121 is present, clients MUST ignore
                # Option 3 (Router). So we must provide the default route
                # inside 121. We add Option 3 anyway for legacy clients that
                # don't understand 121.
                ("router", self.server_ip),

                # Option 121: Classless Static Route (Standard)
                (121, opt_121_payload),

                # Option 249: MS-Classless Static Route (Microsoft Legacy)
                # Older Windows versions (XP/2003) looked for option 249
                # with the exact same format. It's safe to send both.
                (249, opt_121_payload),

                ("name_server", self.dns_server)
            ])

        options.append("end")

        reply = (
            Ether(src=self.server_mac, dst=client_mac) /
            IP(src=self.server_ip, dst=client_ip) /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=client_ip if msg_type != "nak" else "0.0.0.0",
                  siaddr=self.server_ip, giaddr=0, chaddr=mac2str(client_mac),
                  xid=xid) /
            DHCP(options=options)
        )
        sendp(reply, iface=self.iface, verbose=False)

    def get_system_dns(self):
        """
        Determines the best DNS server to hand out to clients.
        Handles the systemd-resolved stub listener (127.0.0.53) edge case.
        """
        def is_ipv4(ip_str):
            try:
                return (type(ipaddress.ip_address(ip_str)) is
                        ipaddress.IPv4Address)
            except ValueError:
                return False

        # Try standard /etc/resolv.conf
        stub_resolver = False
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) > 1 and is_ipv4(parts[1]):
                            if parts[1].startswith("127."):
                                stub_resolver = True
                            else:
                                logger.info(f"✅ Found upstream DNS: "
                                            f"{parts[1]}")
                                return parts[1]
        except Exception as e:
            pass

        # If we found nothing, or we found the systemd stub (127.0.0.53),
        # we need to dig deeper.
        if stub_resolver:
            logger.info("⚠️  Detected local DNS stub (systemd-resolved). "
                        "Looking for upstream DNS...")

            # systemd-resolved keeps the "real" upstream servers in this
            # specific file
            upstream_resolv = "/run/systemd/resolve/resolv.conf"

            if os.path.exists(upstream_resolv):
                try:
                    with open(upstream_resolv, "r") as f:
                        for line in f:
                            if line.startswith("nameserver"):
                                parts = line.split()
                                if len(parts) > 1:
                                    # Ensure we don't grab a loopback again
                                    # by accident
                                    if not parts[1].startswith("127.") and \
                                       is_ipv4(parts[1]):
                                        logger.info(f"✅ Found upstream DNS: "
                                                    f"{parts[1]}")
                                        return parts[1]
                except Exception as e:
                    logger.warning(f"Could not read upstream DNS file: {e}")

        # Fallback if everything fails
        logger.warning("❌ No valid system DNS found. Defaulting to "
                       "Cloudflare (1.1.1.1).")
        return "1.1.1.1"

    def get_interface_details(self, iface_name):
        """
        Returns (ip_address, network_cidr) for a given interface.
        Example: ("192.168.1.1", "192.168.1.0/24")
        """
        ipr = IPRoute()
        try:
            # Find interface index
            idx = ipr.link_lookup(ifname=iface_name)[0]

            # Get IPv4 addresses (family 2)
            addrs = ipr.get_addr(index=idx, family=2)

            if not addrs:
                raise ValueError(f'No IPv4 address assigned to "{iface_name}"')

            # Use the first primary address found
            addr_info = addrs[0]
            local_ip = None
            prefix_len = addr_info['prefixlen']

            # Extract the actual IP string from attributes
            for attr, value in addr_info['attrs']:
                if attr == 'IFA_LOCAL':
                    local_ip = value
                    break

            if not local_ip:
                raise ValueError(f'Could not determine IP for "{iface_name}"')

            # Calculate Network CIDR using ipaddress library
            # Creates an interface object like "192.168.1.1/24"
            iface_obj = ipaddress.IPv4Interface(f"{local_ip}/{prefix_len}")
            network_cidr = str(iface_obj.network)

            return local_ip, network_cidr

        except IndexError:
            raise ValueError(f'Interface "{iface_name}" does not exist.')
        except Exception as e:
            raise RuntimeError(f"Error inspecting interface: {e}")
        finally:
            ipr.close()

    def start(self):
        logger.info(f'🚀 DHCP Server active on "{self.iface}"')
        logger.info(f"   IP: {self.server_ip} | Pool: {self.pool_cidr}")
        logger.info(f"   DNS: {self.dns_server} | Lease: {self.lease_time}s")
        sniff(iface=self.iface, filter="udp and (port 67 or port 68)",
              prn=self.handle_dhcp, store=0)

    def shutdown(self):
        """
        Cleanup tasks to run when the server stops.
        """
        logger.info("🛑 Server shutting down...")

        # Force save leases to disk (save_leases writes unconditionally
        # when called directly)
        self.lease_mgr.save_leases()
        logger.info("💾 Lease state flushed to disk.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Isolated DHCP Server for Point-To-Point Clients",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-i", "--interface",
        default=INTERFACE,
        help="Network interface to bind to"
    )

    parser.add_argument(
        "-s", "--server-ip",
        help="Static Server IP. If omitted, auto-detected from interface."
    )

    parser.add_argument(
        "-p", "--pool",
        help="IP Pool CIDR (e.g., 10.0.0.0/24). If omitted, " \
             "auto-detected from interface."
    )

    parser.add_argument(
        "-d", "--dns",
        help="DNS Server IP. If omitted, uses system /etc/resolv.conf."
    )

    parser.add_argument(
        "-t", "--lease-time",
        type=int,
        default=LEASE_TIME,
        help="DHCP Lease time in seconds."
    )

    parser.add_argument(
        "-f", "--lease-file",
        default=LEASE_FILE,
        help="Path to JSON file for persisting leases."
    )

    args = parser.parse_args()

    def graceful_exit(signum, frame):
        """
        Catches system signals (SIGINT/SIGTERM/SIGHUP) and raises SystemExit.
        This breaks the Scapy loop and triggers the 'finally' block.
        """
        sig_name = signal.Signals(signum).name
        logger.info(f"⚠️  Received signal: {sig_name}")
        sys.exit(0)

    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    signal.signal(signal.SIGHUP, graceful_exit)

    # Pass parsed arguments to the server constructor
    server = None
    try:
        server = UnnumberedDHCPServer(
            interface=args.interface,
            server_ip=args.server_ip,
            pool_cidr=args.pool,
            dns_server=args.dns,
            lease_time=args.lease_time,
            lease_file=args.lease_file
        )
        server.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        logger.critical(f"🔥 Unexpected Crash: {e}", exc_info=True)
    finally:
        if server:
            server.shutdown()
        logger.info("👋 Goodbye.")
