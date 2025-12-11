import argparse
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from scapy.all import *
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

INTERFACE = "guest"
LEASE_FILE = "dhcp_leases_{INTERFACE}.json"
LEASE_TIME = 3600

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Disable promiscuous mode to prevent Avahi flapping on interface changes
conf.sniff_promisc = 0

class SystemIntegrator:
    def __init__(self, interface, pool_cidr, isolation_mode='system',
                 nft_set_iso=None, nft_set_compat=None, nft_set_gw=None,
                 nft_set_net=None, nft_set_bcast=None, nft_set_subnet=None):
        self.iface = interface
        self.pool_cidr = pool_cidr
        self.isolation_mode = isolation_mode
        self.nft_iso = nft_set_iso       # e.g. 'inet filter isolated_ips'
        self.nft_compat = nft_set_compat # e.g. 'inet filter compat_ips'
        self.nft_gw = nft_set_gw
        self.nft_net = nft_set_net
        self.nft_bcast = nft_set_bcast
        self.nft_subnet = nft_set_subnet
        safe_iface = re.sub(r'[^a-zA-Z0-9]', '_', interface)
        self.table_name = f'isodhcp_{safe_iface}'
        self.init_firewall()

    def run_cmd(self, cmd):
        try:
            subprocess.run(cmd, shell=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass # Be resilient to errors (e.g. deleting non-existent entry)

    def update_snat(self, action, client_ip, gateway_ip):
        '''Adds or removes a source NAT rule. Deletion is handled by finding the
        rule handle first.'''
        if action == 'add':
            self.run_cmd(f'nft add rule ip "{self.table_name}" postrouting '
                         f'oifname "{self.iface}" ip daddr "{client_ip}" '
                         f'ip saddr != "{self.pool_cidr}" '
                         f'counter snat to "{gateway_ip}"')
        elif action == 'delete':
            try:
                # List the chain with handles (-a)
                result = subprocess.run(
                    ['nft', '-a', 'list', 'chain', 'ip', self.table_name,
                     'postrouting'], capture_output=True, text=True, check=True)
                pattern = re.compile(
                    rf'ip\s+daddr\s+{re.escape(client_ip)}\s+.*handle\s+(\d+)')

                match = pattern.search(result.stdout)
                if match:
                    handle = match.group(1)
                    # Delete by handle
                    del_cmd = (f'nft delete rule ip "{self.table_name}" '
                               f'postrouting handle "{handle}"')
                    self.run_cmd(del_cmd)
                else:
                    # Rule not found? That's fine, job done.
                    pass
            except:
                pass

    def add_alias_ip(self, ip, cidr):
        '''Adds a secondary IP to the interface (for /30 gateways)'''
        # cmd: ip addr add 10.100.0.5/30 dev eth1
        cmd = f'ip addr add "{ip}/{cidr}" dev "{self.iface}"'
        try:
            subprocess.run(cmd, shell=True, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            # Exit code 2 usually means "exists" in iproute2
            if e.returncode != 0:
                # We can verify existence if we really want, but for now
                # assuming it's fine
                pass

    def del_alias_ip(self, ip, cidr):
        self.run_cmd(f'ip addr del "{ip}/{cidr}" dev "{self.iface}"')

    def flush_nft_set(self, set_name):
        '''Empties an NFTables set completely.'''
        if set_name:
            self.run_cmd(f'nft "flush" element "{set_name}"')

    def update_nft(self, action, ip, is_compat):
        '''Updates the nftables named set'''
        # action is 'add' or 'delete'
        target_set = self.nft_compat if is_compat else self.nft_iso
        if target_set:
            # format: 'table family set_name' provided by user
            # We construct: nft add element inet filter my_set { 10.100.0.50 }
            self.run_cmd(f'nft "{action}" element "{target_set}" "{{ {ip} }}"')

    def update_compat_block(self, action, cidr, net_ip, gw_ip, bcast_ip):
        '''Updates all auxiliary sets for a /30 block.'''
        if self.nft_gw: self.run_cmd(
                f'nft "{action}" element "{self.nft_gw}" "{{ {gw_ip} }}"')
        if self.nft_net: self.run_cmd(
                f'nft "{action}" element "{self.nft_net}" "{{ {net_ip} }}"')
        if self.nft_bcast: self.run_cmd(
                f'nft "{action}" element "{self.nft_bcast}" "{{ {bcast_ip} }}"')
        if self.nft_subnet: self.run_cmd(
                f'nft "{action}" element "{self.nft_subnet}" "{{ {cidr} }}"')

    def init_firewall(self):
        '''Creates private table for source NAT and filter rules.'''
        self.run_cmd(f'nft add table ip "{self.table_name}"')
        self.run_cmd(f'nft add chain ip "{self.table_name}" postrouting "' '{ '
                     f'type nat hook postrouting priority srcnat; '
                      'policy accept; }"')
        self.run_cmd(f'nft flush chain ip "{self.table_name}" postrouting')
        self.run_cmd(f'nft add chain ip "{self.table_name}" forward "' '{ '
                     f'type filter hook forward priority filter; '
                      'policy accept; }"')
        self.run_cmd(f'nft flush chain ip "{self.table_name}" forward')
        self.apply_isolation_policy()

    def apply_isolation_policy(self):
        '''Applies client-to-client traffic rules based on mode.'''
        match = (f'iifname "{self.iface}" oifname "{self.iface}" '
                 f'ip saddr "{self.pool_cidr}" ip daddr "{self.pool_cidr}"')
        if self.isolation_mode == 'on':
            self.run_cmd(f'nft add rule ip "{self.table_name}" forward {match} '
                         f'counter drop')
        elif self.isolation_mode == 'off':
            self.run_cmd(f'nft add rule ip "{self.table_name}" forward {match} '
                         f'counter accept')
        else: pass # 'system' mode

    def flush_firewall(self):
        self.run_cmd(f'nft flush chain ip "{self.table_name}" postrouting')
        self.run_cmd(f'nft flush chain ip "{self.table_name}" forward')
        # Re-apply isolation immediately after flush
        self.apply_isolation_policy()

class RateLimiter:
    def __init__(self, rate=2.0, burst=5):
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
        '''Periodically remove old clients to save RAM'''
        now = time.time()
        with self.lock:
            # Remove clients we haven't seen in 1 hour
            stale_macs = [
                mac for mac,
                data in self.clients.items()
                if (now - data['last_update']) > 3600
            ]
            for mac in stale_macs:
                self.clients.pop(mac, None)
            if stale_macs:
                logging.debug(f'🧹 RateLimiter cleaned up {len(stale_macs)} '
                              f'stale MACs')

class LeaseManager:
    def __init__(self, pool_cidr, server_ip, lease_file, lease_time,
                 sys_integrator=None, static_map=None, compat_macs=None,
                 masq_macs=None, state_change_callback=None):
        self.network = ipaddress.IPv4Network(pool_cidr)
        self.server_ip = ipaddress.IPv4Address(server_ip)
        self.lease_file = lease_file
        self.lease_time = lease_time
        self.sys = sys_integrator
        self.lock = threading.RLock()
        self.cv = threading.Condition(self.lock)

        # Filter the map before we do anything else
        # {mac: (ip, hostname)}
        self.static_map = self.sanitize_static_map(static_map) \
            if static_map else {}
        self.compat_macs = compat_macs or set()
        self.masq_macs = masq_macs or set()
        self.state_change_callback = state_change_callback

        # In-memory storage
        self.subnet_leases = {} # Track /30 allocations:
                                # client_mac -> {gateway: ip, subnet: ip}
        self.leases = {}     # MAC -> {'ip': str, 'expires': float,
                             #         'hostname': str (opt) }
        self.quarantine = {}
        self.ip_to_mac = {}  # IP -> MAC

        # Calculate free IPs
        self.all_possible_ips = set()
        for ip in self.network.hosts():
            if ip != self.server_ip:
                self.all_possible_ips.add(str(ip))
        self.free_ips = self.all_possible_ips.copy()
        self.load_leases()
        self.reserve_static_ips()
        self.enforce_static_bindings()

    def sanitize_static_map(self, raw_map):
        '''
        Validates static IPs against the network topology.
        Returns a clean dictionary containing only valid mappings.
        '''
        valid_map = {}
        seen_ips = set()

        for mac, (ip_str, hostname) in raw_map.items():
            h = f'"{hostname}" ' if hostname else ''
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)

                # Is it actually in our subnet?
                if ip_obj not in self.network:
                    logger.error(f'❌ Static IP {ip_str} (for {h}{mac}) is '
                                 f'outside the pool {self.network}. Ignoring.')
                    continue

                # Is it the Gateway?
                if ip_obj == self.server_ip:
                    logger.error(f'❌ Static IP {ip_str} (for {h}{mac}) '
                                 f'conflicts with gateway/server IP. '
                                 f'Ignoring.')
                    continue

                # Is it Network or Broadcast address?
                # (Note: .hosts() usually excludes these, but manual checks
                # are safer)
                if ip_obj == self.network.network_address:
                    logger.error(f'❌ Static IP {ip_str} (for {h}{mac}) is '
                                 f'the network address. Ignoring.')
                    continue
                if ip_obj == self.network.broadcast_address:
                    logger.error(f'❌ Static IP {ip_str} (for {h}{mac}) is '
                                 f'the broadcast address. Ignoring.')
                    continue

                # Is this IP already assigned to another static MAC?
                # (User might have passed --static mac1=ipA --static mac2=ipA)
                if ip_str in seen_ips:
                    logger.error(f'❌ Static IP {ip_str} (for {h}{mac}) is '
                                 f'assigned to multiple MACs. Ignoring {mac}.')
                    continue

                # If we get here, it's valid.
                seen_ips.add(ip_str)
                valid_map[mac] = (ip_str, hostname)

            except ValueError:
                logger.error(f'❌ Invalid IP format in static map: {ip_str}')
            except Exception as e:
                logger.error(f'❌ Unexpected error validating {ip_str}: {e}')

        if len(valid_map) < len(raw_map):
            logger.warning(f'⚠️ Loaded {len(valid_map)} static mappings '
                           f'(dropped {len(raw_map) - len(valid_map)} '
                           f'invalid entries).')
        return valid_map

    def check_compat_alignment(self, ip_str):
        '''Returns (subnet_cidr, gateway_ip) if IP fits in a /30 as .2'''
        try:
            ip_int = int(ipaddress.IPv4Address(ip_str))
            if (ip_int - 2) % 4 != 0: return None, None
            net_int = ip_int - 2
            return f'{ipaddress.IPv4Address(net_int)}/30', \
                str(ipaddress.IPv4Address(net_int + 1))
        except: return None, None

    def reserve_static_ips(self):
        '''Populates the lease database with static entries immediately at
        startup, setting an infinte lease time.
        '''
        # Process explicit compat (reserve /30s)
        sorted_macs = sorted(self.static_map.keys())
        for mac in sorted_macs:
            ip, hostname = self.static_map[mac]
            is_compat = mac in self.compat_macs
            is_masq = mac in self.masq_macs
            if is_compat:
                subnet_cidr, gw = self.check_compat_alignment(ip)
                if not subnet_cidr:
                    logger.critical(f'⛔ FATAL: Static IP {ip} (MAC {mac}) '
                                    f'alignment error')
                    sys.exit(1) # Fail fast on config error

                # Calculate neighbors
                net = ipaddress.IPv4Network(subnet_cidr)
                block_ips = [str(x) for x in net]  # .0, .1, .2, .3

                for x in block_ips:
                    # If this IP is currently held by a dynamic lease from disk
                    # load, we must kill it to make room for the static
                    # infrastructure.
                    if x in self.ip_to_mac and self.ip_to_mac[x] != mac:
                        conflict_mac = self.ip_to_mac[x]
                        logger.warning(f'⚠️ Evicting dynamic lease {x} '
                                       f'({conflict_mac}) to make room for '
                                       f'static /30')
                        self.release(conflict_mac)
                    if x in self.free_ips: self.free_ips.remove(x)
                self.subnet_leases[mac] = {'gateway': gw, 'subnet': subnet_cidr}
            else:
                # Standard mode /32
                if ip in self.ip_to_mac and self.ip_to_mac[ip] != mac:
                    self.release(self.ip_to_mac[ip])
                if ip in self.free_ips: self.free_ips.remove(ip)
                self.subnet_leases.pop(mac, None)
            # Commit permanent lease
            self.leases[mac] = {
                'ip': ip, 'expires': float('inf'), 'masq': is_masq }
            if hostname: self.leases[mac]['hostname'] = hostname
            self.ip_to_mac[ip] = mac

            mode_str = 'compat/30' if is_compat else 'standard/32'
            logger.info(f'📌 Activated static {mode_str}: {ip} for {mac} '
                        f'(masq={is_masq})')

    def find_free_slash_30(self):
        '''
        Scans the pool for a block of 4 IPs (net, gateway, client, broadcast)
        Must be aligned to /30 boundaries (last octet 0, 4, 8, 12...)
        '''
        # Convert set of strings to sorted list of IP objects
        available_ips = sorted([ipaddress.IPv4Address(ip) \
                                for ip in self.free_ips])

        for ip in available_ips:
            if int(ip) % 4 != 0: continue
            try:
                candidate_net = ipaddress.IPv4Network(f'{ip}/30')
                # IPs: .0 (net), .1 (gateway), .2 (client), .3 (broadcast)
                ips_in_block = [str(x) for x in candidate_net]
                if all(x in self.free_ips for x in ips_in_block):
                    return candidate_net
            except: continue
        return None

    def load_leases(self):
        '''Loads leases from disk and filters out expired ones.'''
        if not os.path.exists(self.lease_file): return
        try:
            with open(self.lease_file, 'r') as f: saved_data = json.load(f)

            now = time.time()
            loaded_count = 0
            for mac, data in saved_data.get('leases', {}).items():
                ip = data['ip']

                if 'expires' not in data:
                    if mac in self.static_map:
                        expires = float('inf')
                    else:
                        expires = now + self.lease_time
                        logger.info(f'📉 Downgraded former static lease for '
                                    f'{mac} to dynamic (expires in '
                                    f'{self.lease_time} seconds)')
                else:
                    expires = data['expires']

                # Only load if valid and valid IP
                if (expires == float('inf') or expires > now) and \
                   ip in self.all_possible_ips:
                    self.leases[mac] = {
                        'ip': ip, 'expires': expires,
                        'masq': data.get('masq', False)}
                    if 'hostname' in data:
                        self.leases[mac]['hostname'] = data['hostname']
                    self.ip_to_mac[ip] = mac
                    if ip in self.free_ips: self.free_ips.remove(ip)
                    loaded_count += 1
            logger.info(f'📁 Loaded {loaded_count} active leases from disk.')

            loaded_subnets = 0
            for mac, data in saved_data.get('subnets', {}).items():
                if mac in self.leases:
                    try:
                        net = ipaddress.IPv4Network(data['subnet'])
                        for x in net:
                            if str(x) in self.free_ips:
                                self.free_ips.remove(str(x))
                        self.subnet_leases[mac] = data
                        loaded_subnets += 1
                    except: pass
            logger.info(f'📁 Loaded {loaded_subnets} active subnets from disk.')
        except Exception as e:
            logger.error(f'⚠️ Failed to load lease file: {e}')

    def save_leases(self, force=False):
        '''
        Persists leases to JSON.
        'force' overrides the optimization check.
        '''
        try:
            serializable_leases = {}
            for mac, data in self.leases.items():
                d = data.copy()
                if d['expires'] == float('inf'): d.pop('expires', None)
                serializable_leases[mac] = d
            out = {'leases': serializable_leases, 'subnets': self.subnet_leases}
            tmp_file = self.lease_file + '.tmp'
            with open(tmp_file, 'w') as f: json.dump(out, f, indent=2)
            os.replace(tmp_file, self.lease_file)
        except Exception as e:
            logger.error(f'Failed to write lease file: {e}')

    def enforce_static_bindings(self):
        '''
        Cleans up the loaded state to ensure static mappings take precedence.
        '''
        leases_to_purge = []

        for mac, data in self.leases.items():
            lease_ip = data['ip']

            # Conflict: This MAC is static, but has a different dynamic IP
            if mac in self.static_map:
                target_ip, hostname = self.static_map[mac]
                if lease_ip != target_ip:
                    h = f'"{hostname}" ' if hostname else ''
                    logger.warning(f'⚠️ Conflict: Static client {h}{mac} has '
                                   f'wrong dynamic IP {lease_ip}. Purging.')
                    leases_to_purge.append(mac)

            # Conflict: This IP is static (for someone else), but assigned
            # to this MAC. Check if lease_ip is a value in static_map (but
            # not for this mac)
            for static_mac, (static_ip, hostname) in self.static_map.items():
                h = f'"{hostname}" ' if hostname else ''
                if lease_ip == static_ip and mac != static_mac:
                    logger.warning(f'⚠️ Conflict: IP {lease_ip} is reserved '
                                   f'for {h}{static_mac} but held by {mac}. '
                                   f'Purging.')
                    leases_to_purge.append(mac)
                    break

        # Execute purge
        for mac in set(leases_to_purge): self.release(mac)

    def trigger_hook(self, action, mac, ip, hostname, extra_env=None):
        if self.state_change_callback:
            try:
                stats = {
                    'ISODHCP_TOTAL_LEASES': str(len(self.leases)),
                    'ISODHCP_FREE_IPS': str(len(self.free_ips)),
                    'ISODHCP_ISOLATION':
                    self.sys.isolation_mode if self.sys else 'unknown'
                }
                full_env = (extra_env or {}) | stats
                self.state_change_callback(action, mac, ip, hostname, full_env)
            except Exception as e:
                logger.error(f'Hook callback failed: {e}')

    def release(self, mac):
        with self.cv:
            if mac in self.leases:
                data = self.leases[mac]
                ip = data['ip']
                is_masq = data.get('masq', False)
                hostname = data.get('hostname', '')

                # Check if it was a compat /30 lease
                if mac in self.subnet_leases:
                    sub_data = self.subnet_leases.pop(mac, None)
                    subnet_cidr = sub_data['subnet']
                    gw_ip = sub_data['gateway']

                    # Tear down router alias
                    if self.sys:
                        self.sys.del_alias_ip(gw_ip, 30)
                        self.sys.update_nft('delete', ip, is_compat=True)
                        try:
                            net = ipaddress.IPv4Network(subnet_cidr)
                            blk = [str(x) for x in net]
                            self.sys.update_compat_block(
                                'delete', subnet_cidr, blk[0], blk[1], blk[3])
                        except: pass

                    # Return all 4 IPs to the pool
                    # (Re-calculate the block from the stored subnet CIDR)
                    net = ipaddress.IPv4Network(sub_data['subnet'])
                    for x in net:
                        self.free_ips.add(str(x))
                else:
                    # Standard /32 cleanup
                    if self.sys:
                        self.sys.update_nft('delete', ip, is_compat=False)
                    self.free_ips.add(ip)

                # Remove SRCNAT
                if is_masq and self.sys:
                    gw_ip = str(self.server_ip)
                    if mac in self.subnet_leases:
                        gw_ip = self.subnet_leases[mac]['gateway']
                    self.sys.update_snat('delete', ip, gw_ip)

                # Common clean-up
                self.ip_to_mac.pop(ip, None)
                self.leases.pop(mac, None)
                self.save_leases()

                # We trigger after cleanup so the state is consistent and the
                # lease is gone
                self.trigger_hook('del', mac, ip, hostname)

                # Inform the garbage collector
                self.cv.notify()
                return ip
        return None

    def get_next_expiration(self):
        '''Returns the timestamp of the soonest expiring lease (or None).'''
        # Lock is assumed to be held by caller (via with self.cv:)
        if not self.leases:
            return None
        # Find the minimum 'expires' float in the values
        return min(d['expires'] for d in self.leases.values())

    def is_ip_active_in_arp(self, ip_str):
        '''
        Checks if the kernel has a valid ARP entry for this IP.
        Returns True if the IP appears to be in use by a rogue device.
        '''
        try:
            with IPRoute() as ipr:
                # Get specific neighbor
                neighbors = ipr.get_neighbours(dst=ip_str, family=2)
                for n in neighbors:
                    state = n['state']
                    # States: 1=INCOMPLETE, 2=REACHABLE, 4=STALE, 8=DELAY,
                    # 16=PROBE, 32=FAILED, 64=NOARP, 128=PERMANENT
                    # We consider it 'Active' if it's Reachable, Stale, Delay, or Probe.
                    # We ignore Failed/Incomplete.
                    if state in (2, 4, 8, 16):
                        return True
        except: pass
        return False


    def process_quarantine_expiry(self):
        '''Lazy cleanup: Checks expired quarantine entries.
        If they are still active on wire, extends quarantine.
        If they are quiet, restores them to the free pool.'''
        now = time.time()

        expired_ips = [
            ip for ip, expiry in self.quarantine.items() if now > expiry]
        if not expired_ips:
            return

        active_on_wire = set()
        try:
            with IPRoute() as ipr:
                neighbors = ipr.get_neighbours(family=2)
                for n in neighbors:
                    # Check for active states (Reachable, Stale, Delay, Probe)
                    if n['state'] in (2, 4, 8, 16): 
                        for attr, val in n['attrs']:
                            if attr == 'NDA_DST':
                                active_on_wire.add(val)
        except: pass

        restored_count = 0
        for ip in expired_ips:
            if ip in active_on_wire:
                # Still active? Extend sentence by 5 mins
                self.quarantine[ip] = now + 300
            else:
                # Quiet? Release.
                del self.quarantine[ip]
                # Only add back if valid and not assigned static
                if ip in self.all_possible_ips and ip not in self.ip_to_mac:
                    self.free_ips.add(ip)
                    restored_count += 1

        if restored_count > 0:
            logger.info(f'♻️ Released {restored_count} IPs from quarantine.')

    def allocate_or_renew(self, mac, hostname=None, is_compat=False,
                          is_masq=False):
        with self.cv:
            if self.quarantine:
                self.process_quarantine_expiry()

            current_time = time.time()
            h = f'"{hostname}" ' if hostname else ''
            target_ip = None
            subnet_info = None
            nft_compat_flag = False
            force_save = True

            was_compat = (mac in self.subnet_leases) or \
                (mac in self.compat_macs)
            req_compat = is_compat

            new_expiry = current_time + self.lease_time
            if mac in self.static_map:
                new_expiry = float('inf')

            # Renewal attempt
            if mac in self.leases:
                lease = self.leases[mac]
                was_masq = lease.get('masq', False)

                if (was_compat != req_compat) or (was_masq != is_masq):
                    logger.info(f'♻️ Config change for {h}{mac} (compat: '
                                f'{was_compat}->{req_compat}, masq: '
                                f'{was_masq}->{is_masq}). Reallocating.')
                    self.release(mac)
                    # Cleared self.leases, and falls through to allocation
                else:
                    # Successful renewal
                    target_ip = lease['ip']

                    # Check optimization to avoid wearing out disk drives with
                    # excessive write operations
                    if (new_expiry == float('inf') or
                        current_time + self.lease_time - lease['expires']) < \
                       (self.lease_time * 0.2):
                        force_save = False

                    # Restore topology info for the commit phase
                    if was_compat:
                        sub_data = self.subnet_leases.get(mac)
                        if sub_data:
                            subnet_info = (
                                sub_data['gateway'], sub_data['subnet'])
                            nft_compat_flag = True
                    else:
                        nft_compat_flag = False

            # New allocation, if renewal failed or didn't happen
            if not target_ip:
                # Static allocation
                if mac in self.static_map:
                    static_ip, _ = self.static_map[mac]

                    # Explicitly requested compat mode for statically assigned
                    # and pre-reserved /30
                    if mac in self.compat_macs:
                        subnet_cidr, gw_ip = \
                            self.check_compat_alignment(static_ip)
                        target_ip = static_ip
                        subnet_info = (gw_ip, subnet_cidr)
                        nft_compat_flag = True

                    # Implicit compat mode (try to upgrade to /30)
                    elif is_compat:
                        subnet_cidr, gw_ip = \
                            self.check_compat_alignment(static_ip)

                        # Check neighbors
                        neighbors_free = False
                        if subnet_cidr:
                            block_ips = [
                                str(x) \
                                for x in ipaddress.IPv4Network(subnet_cidr)]
                            if all((ip == static_ip or ip in self.free_ips) \
                                   for ip in block_ips):
                                neighbors_free = True

                                # Claim neighbors now
                                for ip in block_ips:
                                    if ip in self.free_ips:
                                        self.free_ips.remove(ip)
                        if neighbors_free:
                            target_ip = static_ip
                            subnet_info = (gw_ip, subnet_cidr)
                            nft_compat_flag = True
                        else:
                            # Fallback to standard static
                            logger.info(f'♻️ Request failed for {h}{mac}. '
                                        f'Falling back to standard /32 '
                                        f'allocation')
                            target_ip = static_ip
                            nft_compat_flag = False
                    # Standard static
                    else:
                        target_ip = static_ip
                        nft_compat_flag = False

                # Dynamic allocation
                else:
                    # Dynamically allocate compat /30 address, because
                    # of matching "--compat-XXX=" flags
                    if is_compat:
                        subnet = self.find_free_slash_30()
                        if subnet:
                            blk = [str(x) for x in subnet]
                            target_ip = blk[2]
                            subnet_info = (blk[1], str(subnet))
                            nft_compat_flag = True

                            # Claim IPs
                            for ip in blk:
                                self.free_ips.remove(ip)

                    # Dynamically allocate standard IP address (/32)
                    else:
                        if self.free_ips:
                            for _ in range(5):
                                if not self.free_ips: break
                                # Minimize memory fragmentation by picking the
                                # highest available IP address, leaving the
                                # bottom pool open for aligned /30 blocks
                                candidate = max(self.free_ips,
                                                key=ipaddress.IPv4Address)
                                self.free_ips.remove(candidate)
                                if self.is_ip_active_in_arp(candidate):
                                    logger.warning(f'⚠️ IP {candidate} is free '
                                                   f'in DB but active on wire!')
                                    self.quarantine[candidate] = \
                                        current_time + 300
                                    continue
                                target_ip = candidate
                                nft_compat_flag = False
                                break
                            if not target_ip:
                                logger.error('❌ Pool exhausted (or all '
                                             'candidates busy on wire).')
                                return None

            # Commit the new state
            if not target_ip:
                logger.error(f'❌ Allocation failed for {h}{mac} (mode: '
                             f'compat={req_compat})')
                return None

            # Detect if this is a new allocation or just a renewal
            is_new_lease = not (mac in self.leases) or \
                self.leases[mac]['ip'] != target_ip

            # Update in-memory leases
            self.leases[mac] = {
                'ip': target_ip,
                'expires': new_expiry,
                'masq': is_masq
            }
            if hostname:
                self.leases[mac]['hostname'] = hostname
            self.ip_to_mac[target_ip] = mac
            if subnet_info:
                self.subnet_leases[mac] = {
                    'gateway': subnet_info[0],
                    'subnet': subnet_info[1]
                }

            # Update system state
            if subnet_info:
                gw_ip, subnet_cidr = subnet_info
                self.subnet_leases[mac] = {
                    'gateway': gw_ip, 'subnet': subnet_cidr}
                if self.sys:
                    self.sys.add_alias_ip(gw_ip, 30)
                    try:
                        blk = [
                            str(x) for x in ipaddress.IPv4Network(subnet_cidr)]
                        self.sys.update_compat_block(
                            'add', subnet_cidr, blk[0], blk[1], blk[3])
                    except: pass
            else:
                # Ensure we clean up any stale subnet info if switching back
                self.subnet_leases.pop(mac, None)
            if self.sys:
                self.sys.update_nft('add', target_ip, is_compat=nft_compat_flag)

            # Apply masquerading (source NAT)
            if is_masq and self.sys:
                self.sys.update_snat('add', target_ip,
                                     subnet_info[0] if subnet_info \
                                     else str(self.server_ip))

            # Trigger on new allocation or configuration changes, skip renewals.
            if is_new_lease:
                env = {
                    'ISODHCP_MASQ': '1' if is_masq else '0',
                    'ISODHCP_COMPAT': '1' if (mac in self.subnet_leases) else '0',
                }
                if mac in self.subnet_leases:
                    env['ISODHCP_GATEWAY'] = self.subnet_leases[mac]['gateway']
                    env['ISODHCP_SUBNET'] = self.subnet_leases[mac]['subnet']
                    env['ISODHCP_NETMASK'] = '255.255.255.252'
                else:
                    env['ISODHCP_GATEWAY'] = str(self.server_ip)
                    env['ISODHCP_NETMASK'] = '255.255.255.255'
                self.trigger_hook('add', mac, target_ip, hostname, env)

            # Persist to disk
            if force_save:
                self.save_leases()
                logger.info(f'✨ Lease committed: {target_ip} for {h}{mac} '
                            f'(compat={nft_compat_flag}, masquerade={is_masq})')

            # Recalculate when the next garbage collection cycle should run
            self.cv.notify()
            return target_ip

    def get_expired_leases(self):
        '''Finds expired leases and cleans internal state'''
        expired_entries = [] # List of (mac, ip)
        with self.cv:
            now = time.time()
            # Identify
            for mac, data in list(self.leases.items()):
                if data['expires'] < now:
                    expired_entries.append((mac, data['ip']))

            # Cleanup
            for mac, ip in expired_entries:
                self.release(mac)

        return expired_entries

    def reapply_system_state(self):
        '''When receiving SIGUSR1, forces a re-execution of all system
        integration'''
        if not self.sys: return

        with self.cv:
            # Flush all managed NFTables sets first. This ensures we don't leave
            # behind manually added entries or stale leases
            for s in [self.sys.nft_iso, self.sys.nft_compat, self.sys.nft_gw,
                      self.sys.nft_net, self.sys.nft_bcast,
                      self.sys.nft_subnet]:
                if s: self.sys.flush_nft_set(s)

            # Flush source NAT
            self.sys.flush_firewall()

            # Repopulate
            count = 0
            for mac, data in self.leases.items():
                ip = data['ip']

                # Check if it is a compat/legacy lease
                if mac in self.subnet_leases:
                    sub = self.subnet_leases[mac]
                    gw = sub['gateway']
                    cidr = sub['subnet']
                    self.sys.add_alias_ip(gw, 30)
                    self.sys.update_nft('add', ip, is_compat=True)
                    try:
                        net = ipaddress.IPv4Network(cidr)
                        blk = [str(x) for x in net]
                        self.sys.update_compat_block(
                            'add', cidr, blk[0], blk[1], blk[3])
                    except: pass
                # Standard lease
                else:
                    self.sys.update_nft('add', ip, is_compat=False)

                if data.get('masq', False):
                    gw = str(self.server_ip)
                    if mac in self.subnet_leases:
                        gw = self.subnet_leases[mac]['gateway']
                    self.sys.update_snat('add', data['ip'], gw)
                count += 1
            return count

class UnnumberedDHCPServer:
    def __init__(self, interface, server_ip=None, pool_cidr=None,
                 dns_server=None, lease_time=LEASE_TIME,
                 lease_file=LEASE_FILE, static_map=None,
                 compat_macs=None, compat_ouis=None, compat_vendors=None,
                 masq_macs=None, masq_ouis=None, masq_vendors=None,
                 nft_iso=None, nft_compat=None, nft_gw=None, nft_net=None,
                 nft_bcast=None, nft_subnet=None, hook_file=None,
                 isolation_mode='system'):
        self.iface = interface
        self.lease_time = lease_time
        self.lease_file = lease_file
        self.limiter = RateLimiter(rate=2.0, burst=5)

        # Compatibility configuration
        self.compat_macs = compat_macs or []
        self.compat_ouis = set(o.lower() for o in (compat_ouis or []))
        self.compat_vendors = set(v.lower() for v in (compat_vendors or []))

        # Masquerading configuration (source NAT)
        self.masq_macs = masq_macs or []
        self.masq_ouis = set(o.lower() for o in (masq_ouis or []))
        self.masq_vendors = set(v.lower() for v in (masq_vendors or []))

        # Detect IP/pool
        if not server_ip or not pool_cidr:
            try:
                detected_ip, detected_cidr = \
                    self.get_interface_details(interface)
                self.server_ip = server_ip or detected_ip
                self.pool_cidr = pool_cidr or detected_cidr
                logger.info(f'🔎 Auto-detected: IP={self.server_ip}, '
                            f'pool={self.pool_cidr}')
            except Exception as e:
                logger.critical(f'Auto-detect failed: {e}')
                sys.exit(1)
        else:
            self.server_ip = server_ip
            self.pool_cidr = pool_cidr

        # Detect DNS
        if not dns_server:
            self.dns_server = self.get_system_dns()
            logger.info(f'🔎 Auto-detected DNS: {self.dns_server}')
        else:
            self.dns_server = dns_server

        self.server_mac = get_if_hwaddr(interface)
        self.ipr = IPRoute()
        self.if_index = self.ipr.link_lookup(ifname=self.iface)[0]

        self.sys = SystemIntegrator(
            interface, self.pool_cidr, isolation_mode, nft_set_iso=nft_iso,
            nft_set_compat=nft_compat, nft_set_gw=nft_gw, nft_set_net=nft_net,
            nft_set_bcast=nft_bcast, nft_set_subnet=nft_subnet)

        # Pass configs to LeaseManager
        self.compat_macs = compat_macs or set()
        self.lease_mgr = LeaseManager(self.pool_cidr, self.server_ip,
                                      self.lease_file, self.lease_time,
                                      sys_integrator=self.sys,
                                      static_map=static_map,
                                      compat_macs=self.compat_macs,
                                      masq_macs=self.masq_macs,
                                      state_change_callback=self.execute_hook)

        # Pre-calculate the "wide" mask (e.g., '255.255.255.0')
        self.wide_netmask = str(self.lease_mgr.network.netmask)
        self.gc_thread = threading.Thread(target=self.garbage_collector,
                                          daemon=True)
        self.gc_thread.start()

        # Script file to notify of state change in leases allocations
        self.hook_file = hook_file
        self.base_env = os.environ.copy()
        self.base_env.update({
            'ISODHCP_PID': str(os.getpid()),
            'ISODHCP_LEASE_FILE': os.path.abspath(lease_file),
            'ISODHCP_SERVER_IP': str(self.server_ip),
            'ISODHCP_POOL_CIDR': str(self.pool_cidr),
            'ISODHCP_INTERFACE': self.iface,
            'ISODHCP_DNS': self.dns_server
        })

    def sync_kernel_routes(self):
        '''
        Reconciles the Linux kernel routing table with the lease database.
        Adds routes for leases we loaded from disk but are missing in kernel.
        And deletes stale routes that exist in kernel but we have no lease for
        '''
        logger.info('⚙️ Syncing kernel routes with lease database...')

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

        # Re-apply valid
        valid_ips = set(self.lease_mgr.ip_to_mac.keys())
        for ip in valid_ips:
            # Check legacy status via lease manager
            mac = self.lease_mgr.ip_to_mac[ip]
            is_legacy = mac in self.lease_mgr.subnet_leases
            self.ensure_route(ip, is_legacy)

        # Remove stale
        pool = ipaddress.IPv4Network(self.pool_cidr)
        for ip in active_kernel_ips:
            if ip not in valid_ips:
                obj = ipaddress.IPv4Address(ip)
                if (obj in pool and ip != self.server_ip and
                    obj != pool.network_address and
                    obj != pool.broadcast_address):
                    try:
                        self.ipr.route('del', dst=f'{ip}/32', oif=self.if_index)
                        logger.info(f'🗑️ Route deleted: {ip}')
                    except NetlinkError as e:
                        if e.code == 3: pass # ESRCH, no such process
                        else: logger.error(
                                f'⚠️ Failed to delete route {ip}: {e}')
                    except Exception as e:
                        logger.error(f'⚠️ Unexpected error deleting {ip}: {e}')
        logger.info('✅ Route sync complete.')

    def sync_interface_addresses(self):
        '''
        Removes stray IP aliases on the interface that belong to our pool
        but are not in our lease database.
        Respects IPs from other subnets (e.g. 192.168.1.x vs 192.168.2.x).
        '''
        logger.info('⚙️ Syncing interface IP aliases...')

        # Get all IPv4 addresses on this interface
        try:
            addrs = self.ipr.get_addr(index=self.if_index, family=2)
        except Exception as e:
            logger.error(f'⚠️ Failed to list addresses: {e}')
            return

        pool_net = ipaddress.IPv4Network(self.pool_cidr)

        # Build list of valid IPs (The Truth). Always keep the Server IP
        valid_ips = {ipaddress.IPv4Address(self.server_ip)}

        # Keep active /30 gateways
        for mac, sub_data in self.lease_mgr.subnet_leases.items():
            try:
                gw_ip = ipaddress.IPv4Address(sub_data['gateway'])
                valid_ips.add(gw_ip)
            except: pass

        # Scan and prune
        for addr in addrs:
            # Extract IP and prefix
            local_ip = None
            prefix = addr['prefixlen']
            for attr, value in addr['attrs']:
                if attr == 'IFA_LOCAL':
                    local_ip = value
                    break

            if not local_ip: continue

            try:
                ip_obj = ipaddress.IPv4Address(local_ip)

                # CRITICAL CHECK: Is this IP inside our managed pool?
                if ip_obj in pool_net:
                    # If it's in our pool, we own it; and if it's not in our
                    # valid list, destroy it.
                    if ip_obj not in valid_ips:
                        logger.info(f'🗑️ Removing stray alias: '
                                    f'{local_ip}/{prefix}')
                        self.sys.del_alias_ip(local_ip, prefix)
                else:
                    # It is outside our pool, leave it alone.
                    pass
            except Exception as e:
                logger.error(f'⚠️ Error checking alias {local_ip}: {e}')

    def execute_hook(self, action, mac, ip, hostname, extra_env):
        '''Runs the external shell script asynchronously.'''
        if not self.hook_file: return
        if not os.access(self.hook_file, os.X_OK):
            logger.error(f'🪝 Hook script "{self.hook_file}" is not executable.')
            return

        hook_env = self.base_env.copy()
        hook_env.update(extra_env)
        hook_env['ISODHCP_MAC'] = mac
        hook_env['ISODHCP_IP'] = ip
        if hostname: hook_env['ISODHCP_HOSTNAME'] = hostname
        args = [self.hook_file, action, mac, ip]
        if hostname: args.append(hostname)

        try:
            # Popen is non-blocking. We do NOT wait().
            # stdin/out/err to DEVNULL prevents broken pipes or buffer deadlocks
            subprocess.Popen(
                args,
                env=hook_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True
            )
            h = f' "{hostname}"' if hostname else ''
            logger.debug(f'🪝 Triggered hook: "{action}" "{mac}" "{ip}"{h}')
        except Exception as e:
            logger.error(f"Failed to trigger hook: {e}")

    def reload(self):
        '''Reloads state: Re-applies routes, aliases, and NFTables rules.'''
        logger.info("♻️  Reloading system state (SIGUSR1 received)...")
        self.sync_interface_addresses()
        count = self.lease_mgr.reapply_system_state()
        logger.info(f"   Refreshed system integrations for {count} leases.")
        self.sync_kernel_routes()
        logger.info("✅ Reload complete.")

    def ensure_route(self, client_ip, is_legacy):
        '''
        If compat route, checks if /30 route. If so, removes specific /32 to
        avoid redundancy. Otherwise if standard, ensures specific /32 exists.
        '''
        try:
            # Check for specific /32
            has_32 = False
            r32 = self.ipr.get_routes(dst=client_ip, dst_len=32, family=2)
            for r in r32:
                if r.get('oif') == self.if_index: has_32 = True; break

            if is_legacy:
                # We expect the kernel to have a /30 proto kernel route via the
                # alias. We should clean up the /32 if it exists.
                if has_32:
                    try:
                        self.ipr.route('del', dst=f"{client_ip}/32",
                                       oif=self.if_index)
                        logger.debug(f'🧹 Removed redundant /32 for compat client '
                                     f'{client_ip}')
                    except NetlinkError as e:
                        if e.code == 3: pass # ESRCH, no such process
                        else: raise e
            else:
                # We need the /32
                if not has_32:
                    self.ipr.route('replace', dst=f'{client_ip}/32',
                                   oif=self.if_index)
                    logger.debug(f'🔧 Added /32 host route for {client_ip}')
        except Exception as e: logger.error(f'⚠️ Route error {client_ip}: {e}')

    def garbage_collector(self):
        '''Background thread to clean up routes and leases'''
        while True:
            with self.lease_mgr.cv:
                next_event = self.lease_mgr.get_next_expiration()
                tmo = max(0.1, min(3600.0,
                                   (next_event or float('inf')) - time.time()))
                self.lease_mgr.cv.wait(timeout=tmo)
            expired = self.lease_mgr.get_expired_leases()
            for mac, ip in expired:
                logger.info(f'⏳ Lease expired for {mac}, IPv4 {ip}. '
                            f'Cleaning up.')
                try: self.ipr.route('del', dst=f'{ip}/32', oif=self.if_index)
                except NetlinkError as e:
                    if e.code == 3: pass # ESRCH, no such process
                    else: logger.error(
                            f'⚠️ Error garbage collecting routes: {e}')
                except: pass
            self.limiter.cleanup()

    def should_use_wide_mask(self, pkt, client_mac):
        '''
        Determines if a client requires compat treatment (wide subnet mask).
        '''
        if client_mac in self.compat_macs:
            logger.info(f'⚠️ Legacy Mode: MAC match for {client_mac}')
            return True

        # Check OUI (manufacturer prefix)
        # MAC is aa:bb:cc:dd:ee:ff. OUI is first 8 chars (aa:bb:cc)
        if len(client_mac) >= 8:
            oui = client_mac[:8]
            if oui in self.compat_ouis:
                logger.info(f'⚠️ Legacy Mode: OUI match for {client_mac} '
                            f'({oui})')
                return True

        # Check Vendor Class Identifier (option 60)
        # This allows detecting OS types (e.g., "MSFT 5.0", "Nintendo Switch")
        if DHCP in pkt and self.compat_vendors:
            dhcp_opts = {opt[0]: opt[1] \
                         for opt in pkt[DHCP].options \
                         if isinstance(opt, tuple)}
            vendor_id_bytes = dhcp_opts.get('vendor_class_id')

            if vendor_id_bytes:
                try:
                    if isinstance(vendor_id_bytes, bytes):
                        vendor_id = vendor_id_bytes.decode(
                            'utf-8', errors='ignore')
                    else:
                        vendor_id = str(vendor_id_bytes)

                    # Check partial matches
                    for pattern in self.compat_vendors:
                        if pattern.lower() in vendor_id.lower():
                            logger.info(f'⚠️ Legacy Mode: Vendor match '
                                        f'for {client_mac} ("{vendor_id}")')
                            return True
                except: pass

        return False

    def should_masquerade(self, pkt, mac):
        '''Checks if client requires source NAT.'''
        if mac in self.masq_macs: return True
        if len(mac) >= 8 and mac[:8] in self.masq_ouis: return True
        if DHCP in pkt and self.masq_vendors:
            dhcp_opts = {opt[0]: opt[1] \
                         for opt in pkt[DHCP].options \
                         if isinstance(opt, tuple)}
            vendor_id_bytes = dhcp_opts.get('vendor_class_id')

            if vendor_id_bytes:
                try:
                    if isinstance(vendor_id_bytes, bytes):
                        vendor_id = vendor_id_bytes.decode(
                            'utf-8', errors='ignore')
                    else:
                        vendor_id = str(vendor_id_bytes)

                    # Check partial matches
                    for pattern in self.masq_vendors:
                        if pattern.lower() in vendor_id.lower():
                            return True
                except: pass
        return False

    def get_hostname(self, dhcp_opts):
        '''
        Safely extracts and decodes the hostname from DHCP options.
        Returns None if missing or malformed.
        '''
        # Get the raw value (usually bytes, e.g., b'MyLaptop')
        raw_name = dhcp_opts.get('hostname')
        if not raw_name: return None

        # Decode Bytes -> String
        if isinstance(raw_name, bytes):
            try:
                hostname = raw_name.decode('utf-8', errors='replace')
            except:
                hostname = raw_name.decode('latin-1', errors='replace')
        else:
            hostname = str(raw_name)

        # Sanitize (Remove control characters like newlines or tabs)
        # This prevents a malicious client from breaking your log format
        clean_name = ''.join(
            ch for ch in hostname if ch.isprintable()).strip()

        return clean_name or None

    def get_client_requested_ip(self, pkt):
        '''Combined logic to find what IP the client is talking about'''
        if DHCP in pkt:
            dhcp_opts = {
                opt[0]: opt[1]
                for opt in pkt[DHCP].options if isinstance(opt, tuple)
            }
            if 'requested_addr' in dhcp_opts:
                return dhcp_opts['requested_addr']

        if BOOTP in pkt and pkt[BOOTP].ciaddr != '0.0.0.0':
            return pkt[BOOTP].ciaddr
        return None

    def handle_dhcp(self, pkt):
        try:
            if not (DHCP in pkt and pkt[DHCP].options): return
            client_mac = pkt[Ether].src.lower()
            if not re.match(r'[0-9a-f]{2}([:][0-9a-f]{2}){5}$', client_mac):
                logger.warning(f'⚠️ Ignoring packet with invalid MAC: '
                               f'{client_mac}')
                return

            # Rate limit traffic per MAC address
            if not self.limiter.is_allowed(client_mac):
                return

            # Uncomment to debug DHCP protocol.
            # logger.info(pkt.show(dump=True))

            # Or uncomment here, if all you want to see is the vendor class
            # if DHCP in pkt:
            #     opts = {opt[0]: opt[1] for opt in pkt[DHCP].options \
            #             if isinstance(opt, tuple)}
            #     if 'vendor_class_id' in opts:
            #         logger.info(f'Vendor ID for {pkt[Ether].src.lower()}: '
            #                     f'{opts['vendor_class_id']}')

            dhcp_opts = {
                o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple) }
            msg_type = dhcp_opts.get('message-type')
            hostname = self.get_hostname(dhcp_opts)
            xid = pkt[BOOTP].xid
            is_compat = self.should_use_wide_mask(pkt, client_mac)
            is_masq = self.should_masquerade(pkt, client_mac)

            # DISCOVER (Client needs an IP)
            if msg_type == 1:
                assigned_ip = self.lease_mgr.allocate_or_renew(
                    client_mac, hostname=hostname, is_compat=is_compat,
                    is_masq=is_masq)
                if assigned_ip:
                    self.send_reply(pkt, 'offer', assigned_ip, xid, client_mac)

            # REQUEST (Client accepts offer or renews)
            elif msg_type == 3:
                req_ip = self.get_client_requested_ip(pkt)

                # Security check: Did we actually assign this IP to this MAC?
                # We peek into the lease manager without changing state yet
                current_owner_mac = self.lease_mgr.ip_to_mac.get(req_ip)

                # It's a valid request for an IP we reserved for them
                if current_owner_mac == client_mac:
                    # Confirm allocation (updates timestamp)
                    final_ip = self.lease_mgr.allocate_or_renew(
                        client_mac, hostname=hostname, is_compat=is_compat,
                        is_masq=is_masq)

                    # Setup networking
                    self.ensure_route(final_ip, is_compat)
                    self.send_reply(pkt, 'ack', final_ip, xid, client_mac)

                # Or they are asking for an IP requesting someone else's
                # IP or garbage
                else:
                    h = f'"{self.lease_mgr.leases[current_owner_mac] \
                                                 ['hostname']}" ' \
                        if current_owner_mac in self.lease_mgr.leases and \
                           'hostname' in self.lease_mgr.leases[
                               current_owner_mac] \
                        else ''
                    logger.warning(f'NAK: {client_mac} requested {req_ip} but '
                                   f'it belongs to {h}{current_owner_mac}')
                    self.send_reply(pkt, 'nak', req_ip, xid, client_mac)

            # RELEASE (Client is shutting down politely)
            elif msg_type == 7:
                 req_ip = pkt[BOOTP].ciaddr
                 # Only allow release if the IP actually belongs to them
                 if self.lease_mgr.ip_to_mac.get(req_ip) == client_mac:
                     released_ip = self.lease_mgr.release(client_mac)
                     if released_ip:
                         try: self.ipr.route('del', dst=f'{released_ip}/32',
                                             oif=self.if_index)
                         except: pass
        except Exception as e:
            logger.error(f'⚠️ Malformed packet caused crash: {e}')

    def send_reply(self, old_pkt, msg_type, client_ip, xid, client_mac):
        op_code = 5 if msg_type == 'ack' else 2 # Ack or Offer
        if msg_type == 'nak': op_code = 6

        options = [
            ('message-type', op_code),
            ('server_id', self.server_ip),
        ]

        if msg_type != 'nak':
            router_ip = self.server_ip
            netmask_to_send = '255.255.255.255'
            compat = self.lease_mgr.subnet_leases.get(client_mac)
            if compat:
                router_ip = compat['gateway']
                netmask_to_send = '255.255.255.252'
            opt121 = b'\x00' + socket.inet_aton(router_ip)
            options.extend([
                ('lease_time', self.lease_time),
                ('subnet_mask', netmask_to_send), # /32 or /30 isolation
                ('name_server', self.dns_server),

                # --- IMPORTANT: ROUTER OPTION LOGIC ---
                # RFC 3442 says: If option 121 is present, clients MUST ignore
                # option 3 (Router). So we must provide the default route
                # inside 121. We add option 3 anyway for legacy clients that
                # don't understand 121.
                ('router', self.server_ip),

                # Option 121: Classless Static Route (Standard)
                (121, opt121),

                # Option 249: MS-Classless Static Route (Microsoft Legacy)
                # Older Windows versions (XP/2003) looked for option 249
                # with the exact same format. It's safe to send both.
                (249, opt121)
            ])
        options.append('end')

        reply = (
            Ether(src=self.server_mac, dst=client_mac) /
            IP(src=self.server_ip, dst=client_ip) /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=client_ip if msg_type != 'nak' else '0.0.0.0',
                  siaddr=self.server_ip, giaddr=0, chaddr=mac2str(client_mac),
                  xid=xid) /
            DHCP(options=options)
        )
        sendp(reply, iface=self.iface, verbose=False)

    def get_system_dns(self):
        '''
        Determines the best DNS server to hand out to clients.
        Handles the systemd-resolved stub listener (127.0.0.53) edge case.
        '''
        def is_ipv4(ip_str):
            try: return (type(ipaddress.ip_address(ip_str)) is
                         ipaddress.IPv4Address)
            except ValueError: return False

        # Try standard /etc/resolv.conf
        candidates = []
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) > 1 and is_ipv4(parts[1]):
                            if parts[1].startswith('127.'):
                                candidates.append(parts[1])
        except: pass

        # If we found nothing, or we found the systemd stub (127.0.0.53),
        # we need to dig deeper.
        if not candidates or (candidates and candidates[0].startswith('127.')):
            logger.info('⚠️  Detected local DNS stub (systemd-resolved). '
                        'Looking for upstream DNS...')

            # systemd-resolved keeps the "real" upstream servers in this
            # specific file
            upstream_resolv = '/run/systemd/resolve/resolv.conf'

            if os.path.exists(upstream_resolv):
                try:
                    with open(upstream_resolv, 'r') as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                parts = line.split()
                                if len(parts) > 1:
                                    # Ensure we don't grab a loopback again
                                    # by accident
                                    if not parts[1].startswith('127.') and \
                                       is_ipv4(parts[1]):
                                        logger.info(f'✅ Found upstream DNS: '
                                                    f'{parts[1]}')
                                        return parts[1]
                except Exception as e:
                    logger.warning(f'Could not read upstream DNS file: {e}')

        for ip in candidates:
            if not ip.startswith('127.'): return ip

        # Fallback if everything fails
        logger.warning('❌ No valid system DNS found. Defaulting to '
                       'Cloudflare (1.1.1.1).')
        return '1.1.1.1'

    def get_interface_details(self, iface_name):
        '''
        Returns (ip_address, network_cidr) for a given interface.
        Example: ('192.168.1.1', '192.168.1.0/24')
        '''
        ipr = IPRoute()
        try:
            # Find interface index
            idx = ipr.link_lookup(ifname=iface_name)[0]

            # Get IPv4 addresses (family 2)
            raw_addrs = ipr.get_addr(index=idx, family=2)

            if not raw_addrs:
                raise ValueError(f'No IPv4 address assigned to "{iface_name}"')

            # Sort by prefix length in ascending order. We want the smallest
            # prefix (e.g. 24) to win over larger ones (e.g. 30 or 32). This
            # ensures we pick the "main" network, not a stray /30 alias
            sorted_addrs = sorted(raw_addrs, key=lambda x: x['prefixlen'])

            # Use the first primary address found
            addr_info = sorted_addrs[0]
            local_ip = None
            prefix_len = addr_info['prefixlen']

            # Extract the actual IP string from attributes
            for attr, value in addr_info['attrs']:
                if attr == 'IFA_LOCAL':
                    local_ip = value
                    break

            if not local_ip:
                raise ValueError(f'Could not determine IP for "{iface_name}"')

            # Calculate network CIDR using ipaddress library
            # Creates an interface object like '192.168.1.1/24'
            iface_obj = ipaddress.IPv4Interface(f'{local_ip}/{prefix_len}')

            return local_ip, str(iface_obj.network)

        except IndexError:
            raise ValueError(f'Interface "{iface_name}" does not exist.')
        except Exception as e:
            raise RuntimeError(f'Error inspecting interface: {e}')
        finally:
            ipr.close()

    def shutdown(self):
        '''Cleanup tasks to run when the server stops.'''
        logger.info('🛑 Server shutting down...')

        # Force save leases to disk (save_leases writes unconditionally
        # when called directly)
        self.lease_mgr.save_leases()
        logger.info('💾 Lease state flushed to disk.')

    def start(self):
        logger.info(f'🚀 DHCP Server active on "{self.iface}"')
        logger.info(f'   IP: {self.server_ip} | Pool: {self.pool_cidr}')
        logger.info(f'   DNS: {self.dns_server} | Lease: {self.lease_time}s')

        # Ensure clean state on startup too!
        self.sync_interface_addresses()
        self.lease_mgr.reapply_system_state()
        self.sync_kernel_routes()
        sniff(iface=self.iface, filter='udp and (port 67 or port 68)',
              prn=self.handle_dhcp, store=0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Isolated DHCP Server for Point-To-Point Clients',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        '-d', '--dns',
        help='DNS Server IP. If omitted, uses system /etc/resolv.conf.'
    )

    parser.add_argument(
        '-f', '--lease-file',
        default=None,
        help=f'Path to JSON file. Defaults to "{LEASE_FILE}"'
    )

    parser.add_argument(
        '-i', '--interface',
        default=INTERFACE,
        help='Network interface to bind to'
    )

    parser.add_argument(
        '-p', '--pool',
        help='IP Pool CIDR (e.g., 10.0.0.0/24). If omitted, ' \
             'auto-detected from interface.'
    )

    parser.add_argument(
        '-s', '--server-ip',
        help='Static Server IP. If omitted, auto-detected from interface.'
    )

    parser.add_argument(
        '-t', '--lease-time',
        type=int,
        default=LEASE_TIME,
        help='DHCP Lease time in seconds.'
    )

    parser.add_argument(
        '--compat-mac',
        action='append',
        help='Treat this MAC as legacy (send wide netmask). Can be repeated.'
    )

    parser.add_argument(
        '--compat-oui',
        action='append',
        help='Treat this MAC prefix (e.g. "00:11:22") as legacy. Can be ' \
             'repeated.'
    )

    parser.add_argument(
        '--compat-vendor',
        action='append',
        help='Treat clients with this Vendor ID string (option 60) as ' \
             'legacy. e.g. "MSFT 5.0"'
    )

    parser.add_argument(
        '--masquerade-mac',
        action='append',
        help='Masquerade incoming traffic to originate from gateway IP. ' \
             'Can be repeated.'
    )

    parser.add_argument(
        '--masquerade-oui',
        action='append',
        help='Treat this MAC prefix (e.g. "00:11:22") as masqueraded. Can be ' \
             'repeated.'
    )

    parser.add_argument(
        '--masquerade-vendor',
        action='append',
        help='Treat clients with this Vendor ID string (option 60) as ' \
             'masqueraded. e.g. "MSFT 5.0"'
    )

    parser.add_argument(
        '--static',
        action='append',
        help='Map a MAC to an IP. Format: --static aa:bb:cc:dd:ee:ff=' \
             '10.100.0.50{,hostname}{,compat}{,masquerade}'
    )

    parser.add_argument('--nft-set-isolated',
                        help='NFTables set for isolated clients')

    parser.add_argument('--nft-set-compat',
                        help='NFTables set for legacy clients in '
                        'compatibility mode')

    parser.add_argument('--nft-set-gateway',
                        help='NFTables set for compatibility gateway IPs')

    parser.add_argument('--nft-set-network',
                        help='NFTables set for compatibility network IPs')

    parser.add_argument('--nft-set-broadcast',
                        help='NFTables set for compatibility broadcast IPs')

    parser.add_argument('--nft-set-subnet',
                        help='NFTables set for compatibility /30 subnets')

    parser.add_argument('--hook-file', help='Path to executable script '
                        'triggered on lease add/del')

    parser.add_argument('--isolation', choices=['on', 'off', 'system'],
                        default='system',
                        help='Enforce client-to-client isolation policy')

    args = parser.parse_args()

    try:
        # Try to set the correct process name, hiding the Python interpreter.
        # N.b. this does not change the command line, but only the "comm" name.
        libc = ctypes.cdll.LoadLibrary('libc.so.6')
        proc_name = f'isodhcp-{args.interface}'
        libc.prctl(15, proc_name.encode('utf-8')[:15], 0, 0, 0)
    except: pass

    if args.lease_file:
        lease_file = args.lease_file
    else:
        safe_iface = re.sub(r'[^a-zA-Z0-9]', '_', args.interface)
        lease_file = LEASE_FILE.replace('{INTERFACE}', safe_iface)

    def graceful_exit(signum, frame):
        '''
        Catches system signals (SIGINT/SIGTERM/SIGHUP) and raises SystemExit.
        This breaks the Scapy loop and triggers the 'finally' block.
        '''
        sig_name = signal.Signals(signum).name
        logger.info(f'⚠️  Received signal: {sig_name}')
        sys.exit(0)
    def handle_reload(signum, frame):
        '''Handles systemctl reload (SIGUSR1)'''
        if server: server.reload()
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    signal.signal(signal.SIGHUP, graceful_exit)
    signal.signal(signal.SIGUSR1, handle_reload)

    # Parse static maps
    static_map = {}
    compat_macs = set(m.lower() for m in (args.compat_mac or []))
    masq_macs = set(m.lower() for m in (args.masquerade_mac or []))

    static_map = {}
    if args.static:
        for item in args.static:
            try:
                parts = item.split('=')
                if len(parts) != 2:
                    raise ValueError('Format must be MAC=IP{,hostname}'
                                     '{,compat}{,masquerade}')
                mac = parts[0].strip().lower()
                val = parts[1].strip().split(',')
                ip = val[0].strip().lower()
                hostname = None
                for flag in val[1:]:
                    f = flag.strip().lower()
                    if f == 'compat': compat_macs.add(mac)
                    elif f == 'masquerade': masq_macs.add(mac)
                    elif f and not hostname: hostname = f
                    else: raise ValueError('Format must be MAC=IP{,hostname}'
                                           '{,compat}{,masquerade}')

                # Basic validation
                if not re.match(r'[0-9a-f]{2}([:][0-9a-f]{2}){5}$', mac):
                    logger.error(f'Invalid MAC in static map: {mac}')
                    sys.exit(1)
                ipaddress.IPv4Address(ip) # Check if valid IP
                static_map[mac] = (ip, hostname)
            except Exception as e:
                logger.critical(f'Failed to parse static map "{item}": {e}')
                sys.exit(1)

    # Pass parsed arguments to the server constructor
    server = None
    try:
        server = UnnumberedDHCPServer(
            interface=args.interface,
            server_ip=args.server_ip,
            pool_cidr=args.pool,
            dns_server=args.dns,
            lease_time=args.lease_time,
            lease_file=lease_file,
            static_map=static_map,
            compat_macs=compat_macs,
            compat_ouis=args.compat_oui,
            compat_vendors=args.compat_vendor,
            masq_macs=masq_macs,
            masq_ouis=args.masquerade_oui,
            masq_vendors=args.masquerade_vendor,
            nft_iso=args.nft_set_isolated,
            nft_compat=args.nft_set_compat,
            nft_gw=args.nft_set_gateway,
            nft_net=args.nft_set_network,
            nft_bcast=args.nft_set_broadcast,
            nft_subnet=args.nft_set_subnet,
            hook_file=args.hook_file,
            isolation_mode=args.isolation
        )
        server.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        logger.critical(f'🔥 Unexpected Crash: {e}', exc_info=True)
    finally:
        if server:
            server.shutdown()
        logger.info('👋 Goodbye.')
