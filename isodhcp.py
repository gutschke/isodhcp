import argparse
import ipaddress
import json
import logging
import os
import re
import shlex
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

INTERFACE = 'guest'
LEASE_FILE = 'dhcp_leases_{INTERFACE}.json'
SOCKET_FILE = 'isodhcp_{INTERFACE}.sock'
LEASE_TIME = 3600
VERSION = '1.0'

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Disable promiscuous mode to prevent Avahi flapping on interface changes
conf.sniff_promisc = 0

class SystemIntegrator:
    def __init__(self, interface, pool_cidr, isolation_mode='system',
                 nft_set_iso=None, nft_set_compat=None, nft_set_playground=None,
                 nft_set_playground_subnet=None, nft_set_gw=None,
                 nft_set_net=None, nft_set_bcast=None, nft_set_subnet=None):
        self.iface = interface
        self.pool_cidr = pool_cidr
        self.isolation_mode = isolation_mode
        self.nft_iso = nft_set_iso       # e.g. 'inet filter isolated_ips'
        self.nft_compat = nft_set_compat # e.g. 'inet filter compat_ips'
        self.nft_playground = nft_set_playground
        self.nft_playground_subnet = nft_set_playground_subnet
        self.nft_gw = nft_set_gw
        self.nft_net = nft_set_net
        self.nft_bcast = nft_set_bcast
        self.nft_subnet = nft_set_subnet
        safe_iface = re.sub(r'[^a-zA-Z0-9]', '_', interface)
        self.table_name = f'isodhcp_{safe_iface}'
        self.init_firewall()

    def run_cmd(self, cmd):
        # Tokenize with shlex and run WITHOUT a shell. The command strings quote
        # multi-word arguments (e.g. "inet filter isolated_ips" or "{ 10.0.0.1 }")
        # so shlex groups them exactly as the shell would have, and nft/ip re-lex
        # the reconstructed line. Dropping the shell removes any chance of a value
        # being interpreted as a metacharacter.
        try:
            argv = shlex.split(cmd)
            if not argv:
                return
            subprocess.run(argv, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            pass # Be resilient to errors (e.g. deleting non-existent entry)
        except ValueError as e:
            # shlex failed to tokenize (unbalanced quote). Never fall back to a
            # shell; just log and move on.
            logger.error(f'⚠️ Skipped malformed command: {e}')

    def update_snat(self, action, client_ip, gateway_ip):
        '''Adds or removes source NAT rules. Ensures no duplicate rules exist.'''
        # Always attempt to clean up existing rules for this client IP first.
        # Read the chain as JSON under a fixed C locale so rule matching never
        # depends on nft's (potentially localized) textual output — the handle
        # and the destination address come straight from structured data.
        try:
            result = subprocess.run(
                ['nft', '-j', '-a', 'list', 'chain', 'ip', self.table_name,
                 'postrouting'], capture_output=True, encoding='utf-8',
                env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'}, check=True)
            data = json.loads(result.stdout)
            for o in data.get('nftables', []):
                rule = o.get('rule')
                if not rule or 'handle' not in rule:
                    continue
                daddr = None
                for e in rule.get('expr', []):
                    if 'match' in e:
                        left = e['match'].get('left')
                        if isinstance(left, dict) and \
                           left.get('payload', {}).get('field') == 'daddr' \
                           and e['match'].get('op') == '==':
                            daddr = e['match'].get('right')
                if daddr == client_ip:
                    self.run_cmd(f'nft delete rule ip "{self.table_name}" '
                                 f'postrouting handle "{rule["handle"]}"')
        except Exception:
            pass

        if action == 'add':
            self.run_cmd(f'nft add rule ip "{self.table_name}" postrouting '
                         f'oifname "{self.iface}" ip daddr "{client_ip}" '
                         f'ip saddr != "{self.pool_cidr}" '
                         f'counter snat to "{gateway_ip}"')

    def add_alias_ip(self, ip, cidr):
        '''Adds a secondary IP to the interface (for /30 gateways)'''
        # cmd: ip addr add 10.100.0.5/30 dev eth1
        # run_cmd swallows the non-zero exit iproute2 returns when the alias
        # already exists, which is exactly the behaviour we want here.
        self.run_cmd(f'ip addr add "{ip}/{cidr}" dev "{self.iface}"')

    def del_alias_ip(self, ip, cidr):
        self.run_cmd(f'ip addr del "{ip}/{cidr}" dev "{self.iface}"')

    def flush_nft_set(self, set_name):
        '''Empties an NFTables set completely.'''
        if set_name:
            # 'flush set' empties a named set; 'flush element' is not valid nft
            # syntax and silently errored out, so stale entries used to survive
            # a SIGUSR1 reload instead of being reconciled away.
            self.run_cmd(f'nft "flush" set "{set_name}"')

    def update_client_nft(self, action, ip, mode):
        '''Updates the nftables named set based on client mode'''
        # action is 'add' or 'delete'
        target_set = None
        if mode == ClientClassifier.MODE_PLAYGROUND:
            target_set = self.nft_playground
        elif mode == ClientClassifier.MODE_COMPAT:
            target_set = self.nft_compat
        elif mode == ClientClassifier.MODE_STANDARD:
            target_set = self.nft_iso
        if target_set:
            # format: 'table family set_name' provided by user
            # We construct: nft add element inet filter my_set { 10.100.0.50 }
            self.run_cmd(f'nft "{action}" element "{target_set}" "{{ {ip} }}"')

    def update_playground_subnet(self, action, cidr):
        '''Updates the playground subnet set'''
        if self.nft_playground_subnet:
            self.run_cmd(
                f'nft "{action}" element "{self.nft_playground_subnet}" "{{ '
                f'{cidr} }}"')

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

    def apply_isolation_policy(self, playground_cidr=None):
        '''Applies client-to-client traffic rules based on mode.'''
        self.run_cmd(f'nft flush chain ip "{self.table_name}" forward')
        if playground_cidr:
            match = (f'iifname "{self.iface}" oifname "{self.iface}" '
                     f'ip saddr "{playground_cidr}" '
                     f'ip daddr "{playground_cidr}"')
            self.run_cmd(f'nft add rule ip "{self.table_name}" forward '
                         f'{match} counter accept')
        match = (f'iifname "{self.iface}" oifname "{self.iface}" '
                 f'ip saddr "{self.pool_cidr}" ip daddr "{self.pool_cidr}"')

        if self.isolation_mode == 'on':
            self.run_cmd(f'nft add rule ip "{self.table_name}" forward '
                         f'{match} counter drop')
        elif self.isolation_mode == 'off':
            self.run_cmd(f'nft add rule ip "{self.table_name}" forward '
                         f'{match} counter accept')
        # else: system default (usually accept, or handled by other chains)

    def flush_firewall(self, playground_cidr=None):
        self.run_cmd(f'nft flush chain ip "{self.table_name}" postrouting')
        # Re-apply isolation immediately after flush
        self.apply_isolation_policy(playground_cidr)

class ClientClassifier:
    '''
    Centralizes logic for determining client mode (standard, compat, playground)
    and attributes (masquerade).
    Precedence: static > MAC > OUI > vendor.
    Tie-break: compat > playground.
    '''
    MODE_PLAYGROUND = 'playground'
    MODE_STANDARD = 'standard'
    MODE_COMPAT = 'compat'

    def __init__(self, pg_macs=None, pg_ouis=None, pg_vendors=None,
                 compat_macs=None, compat_ouis=None, compat_vendors=None,
                 masq_macs=None, masq_ouis=None, masq_vendors=None,
                 static_profiles=None):
        self.pg_macs = pg_macs or set()
        self.pg_ouis = pg_ouis or set()
        self.pg_vendors = pg_vendors or set() # Special: '' matches all

        self.compat_macs = compat_macs or set()
        self.compat_ouis = compat_ouis or set()
        self.compat_vendors = compat_vendors or set()

        self.masq_macs = masq_macs or set()
        self.masq_ouis = masq_ouis or set()
        self.masq_vendors = masq_vendors or set()

        # Static overrides: mac -> {'mode': ..., 'masq': ...}
        self.static_profiles = static_profiles or {}

    def get_profile(self, mac, pkt):
        '''Returns a dict: {'mode': MODE_*, 'masq': bool}'''
        # Static configuration (highest precedence)
        if mac in self.static_profiles:
            return self.static_profiles[mac]

        # Dynamic classification
        is_playground = self.check_match(mac, pkt, self.pg_macs,
                                          self.pg_ouis, self.pg_vendors)

        is_compat = self.check_match(mac, pkt, self.compat_macs,
                                     self.compat_ouis, self.compat_vendors)

        is_masq = self.check_match(mac, pkt, self.masq_macs,
                                   self.masq_ouis, self.masq_vendors)

        # Conflict resolution (compat > playground)
        mode = self.MODE_STANDARD
        if is_compat:
            mode = self.MODE_COMPAT
        elif is_playground:
            mode = self.MODE_PLAYGROUND

        return {'mode': mode, 'masq': is_masq}

    def check_match(self, mac, pkt, mac_set, oui_set, vendor_set):
        if mac in mac_set: return True
        if len(mac) >= 8 and mac[:8] in oui_set: return True
        if vendor_set:
            # If we have an empty string rule, it matches everything
            if '' in vendor_set: return True

            # Otherwise check packet options
            if DHCP in pkt:
                opts = {o[0]: o[1] \
                        for o in pkt[DHCP].options if isinstance(o, tuple)}
                vci_bytes = opts.get('vendor_class_id')
                if vci_bytes:
                    vci = str(vci_bytes).lower()
                    # Check partial matches
                    for pattern in vendor_set:
                        if pattern and pattern.lower() in vci:
                            return True
        return False

def classify_lease_mode(mac, data, subnet_leases):
    '''Single source of truth for a lease's category (standard/compat/
    playground) used for nft-set membership and reply topology. Deriving it the
    same way everywhere keeps startup, SIGUSR1 reload, release, the DHCP reply
    and diagnostics in agreement — a client cannot be filed into one set on add
    and a different one on delete.

    Compat is /30-block membership (subnet_leases) — authoritative and always
    available. Otherwise the lease's stored 'mode' is used; it is written by
    live allocation and preserved across restarts by load_leases. A lease with
    no stored mode (only a static reservation before its first DHCP exchange)
    defaults to STANDARD, the most-isolated / fail-closed category. It is NOT
    guessed from the address: a playground block is chosen before leases load,
    so an isolated client's address can fall inside it, and guessing would file
    that client into the permissive playground set — an isolation downgrade.'''
    if mac in subnet_leases:
        return ClientClassifier.MODE_COMPAT
    return data.get('mode') or ClientClassifier.MODE_STANDARD

class RateLimiter:
    def __init__(self, rate=2.0, burst=5, max_clients=65536):
        self.rate = rate          # Tokens added per second
        self.burst = burst        # Maximum bucket size
        # Hard cap on tracked MACs. A guest spoofing a flood of random source
        # MACs would otherwise grow this dict without bound (one entry per MAC)
        # long before the hourly cleanup runs, so cap it and fail closed.
        self.max_clients = max_clients
        self.clients = {}         # MAC -> {tokens: float, last_update: float}
        self.lock = threading.Lock()
        self._full_alerted = False  # one-shot alert when the table saturates
        self._last_prune = 0.0      # throttles the inline prune when saturated

    def _prune(self, now):
        '''Drop clients idle for over an hour. Caller must hold self.lock.'''
        self._last_prune = now
        stale_macs = [
            mac for mac,
            data in self.clients.items()
            if (now - data['last_update']) > 3600
        ]
        for mac in stale_macs:
            self.clients.pop(mac, None)
        if stale_macs:
            logger.debug(f'🧹 RateLimiter cleaned up {len(stale_macs)} '
                         f'stale MACs')
        return len(stale_macs)

    def is_allowed(self, mac):
        now = time.time()

        with self.lock:
            # Initialize new client
            if mac not in self.clients:
                # Bound memory: if the table is full, try an inline prune of
                # idle entries first; if it is still full it is saturated with
                # active abusers, so drop this packet rather than risk an OOM.
                if len(self.clients) >= self.max_clients:
                    # Throttle the scan. Under a sustained new-MAC flood every
                    # entry is fresh, so a prune frees nothing; rescanning the
                    # whole table on every packet would just turn the averted
                    # memory DoS into a CPU one. Rescan at most once a second and
                    # otherwise fail closed immediately.
                    if now - self._last_prune >= 1.0:
                        self._prune(now)
                    if len(self.clients) >= self.max_clients:
                        if not self._full_alerted:
                            logger.error(
                                f'🚨 RateLimiter table full '
                                f'({self.max_clients} MACs). Dropping packets '
                                f'from new MACs — possible source-MAC flood.')
                            self._full_alerted = True
                        return False
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
            self._prune(now)
            # Re-arm the saturation alert once the table has real headroom, so a
            # future flood alerts again without spamming while one is ongoing.
            if self._full_alerted and len(self.clients) < self.max_clients * 0.9:
                self._full_alerted = False

class LeaseManager:
    def __init__(self, pool_cidr, server_ip, lease_file, lease_time,
                 sys_integrator=None, static_map=None, compat_macs=None,
                 masq_macs=None, state_change_callback=None,
                 playground_size=0):
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

        # Set up a subset of the pool for a playground area
        self.playground_size = playground_size
        self.playground_subnet = None
        self.playground_gateway = None
        self.playground_free_ips = set()

        # In-memory storage
        self.subnet_leases = {} # Track /30 allocations:
                                # client_mac -> {gateway: ip, subnet: ip}
        self.leases = {}     # MAC -> {'ip': str, 'expires': float,
                             #         'hostname': str (opt) }
        self.quarantine = {}
        self._quarantine_alerted = False  # one-shot alert when the cap is reached
        self.ip_to_mac = {}  # IP -> MAC

        # Calculate free IPs
        self.all_possible_ips = set()
        for ip in self.network.hosts():
            if ip != self.server_ip:
                self.all_possible_ips.add(str(ip))
        self.free_ips = self.all_possible_ips.copy()
        # Bound the quarantine so a device that DECLINE-floods or ARP-claims many pool IPs
        # cannot pin the whole pool out of service. At least half the pool is always kept
        # allocatable; reaching the cap raises a loud one-shot alert.
        self.quarantine_cap = max(16, len(self.all_possible_ips) // 2)

        # Carve out playground
        if self.playground_size > 0:
            self.init_playground()

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

    def init_playground(self):
        '''
        Finds a contiguous aligned block for the playground, removing it from
        the main free_ips pool.
        '''
        # Calculate required prefix (e.g., size 64 -> /26)
        # 32 - log2(64) = 26
        import math
        prefix_bits = math.ceil(math.log2(self.playground_size))
        needed_prefix = 32 - prefix_bits

        # Get candidates (if size=pool, this returns just the pool itself)
        # We try to allocate from the top of the pool to avoid fragmenting the
        # bottom (where /30s live). We iterate subnets of the main pool.
        if needed_prefix < self.network.prefixlen:
            logger.critical(f'⛔ Playground size {self.playground_size} is '
                            f'larger than the pool.')
            sys.exit(1)
        try:
            candidate_subnets = \
                list(self.network.subnets(new_prefix=needed_prefix))
        except ValueError:
            logger.critical(f'⛔ Cannot allocate playground of size '
                            f'{self.playground_size} from {self.network}.')
            sys.exit(1)
        candidate_subnets.reverse()
        found = None
        for subnet in candidate_subnets:
            # Valid IPs are those that are free or are the server itself,
            # which is fine to encompass. We strictly check that we aren't
            # stomping on existing leases.
            # First, check for conflicts with active leases (standard/compat)
            # that might have loaded from disk
            subnet_set = set(str(ip) for ip in subnet.hosts())

            has_conflict = False
            for ip in subnet_set:
                if ip in self.ip_to_mac and ip != str(self.server_ip):
                    has_conflict = True
                    break
            if not has_conflict:
                found = subnet
                break

        if not found:
            logger.critical(f'⛔ Not enough contiguous space for playground '
                            f'of size {self.playground_size}.')
            sys.exit(1)
        self.playground_subnet = found

        # Assign playground gateway (first IP of the block)
        if self.server_ip in found:
            self.playground_gateway = str(self.server_ip)
        else:
            self.playground_gateway = str(list(found.hosts())[0])

        # Initialize playground free pool
        for ip_obj in found.hosts():
            s_ip = str(ip_obj)
            if s_ip == self.playground_gateway:
                if s_ip in self.free_ips: self.free_ips.remove(s_ip)
                continue
            if s_ip in self.free_ips:
                self.free_ips.remove(s_ip)
                self.playground_free_ips.add(s_ip)

        logger.info(f'🎡 Initialized playground: {found} (gw: '
                    f'{self.playground_gateway})')

        # Add Interface Alias immediately
        if self.sys:
            self.sys.add_alias_ip(self.playground_gateway, needed_prefix)
            self.sys.apply_isolation_policy(str(self.playground_subnet))
            self.sys.update_playground_subnet(
                'add', str(self.playground_subnet))

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
                    # Preserve the authoritative category across restarts.
                    # Without this the reloaded lease is mode-less and would be
                    # re-derived (defaulting to standard), so a playground or
                    # compat client could be re-filed into the wrong nft set on
                    # startup and needlessly reallocated on its first renewal.
                    if 'mode' in data:
                        self.leases[mac]['mode'] = data['mode']
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

    def _effective_mode(self, mac, data):
        '''Category for nft-set membership, resilient to leases (static or
        disk-reloaded) that carry no 'mode' field. See classify_lease_mode.'''
        return classify_lease_mode(mac, data, self.subnet_leases)

    def release(self, mac):
        with self.cv:
            if mac in self.leases:
                data = self.leases[mac]
                ip = data['ip']
                mode = self._effective_mode(mac, data)
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
                        self.sys.update_client_nft('delete', ip, mode)
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
                        self.sys.update_client_nft('delete', ip, mode)
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

    def _quarantine(self, ip, until):
        '''Quarantine `ip` until `until`, capped so a misbehaving or hostile device cannot
        pin the whole pool out of service (a DECLINE flood, or ARP-claiming pool IPs). An
        already-quarantined IP is always updatable (extending its sentence costs nothing);
        a NEW entry is refused once the cap is reached, and the operator is alerted once.
        Caller must hold self.lock. Returns True if `ip` is (now) quarantined, else False.'''
        if ip in self.quarantine:
            self.quarantine[ip] = until
            return True
        if len(self.quarantine) >= self.quarantine_cap:
            if not self._quarantine_alerted:
                logger.error(f'🚨 Quarantine cap reached ({self.quarantine_cap} of '
                             f'{len(self.all_possible_ips)} pool IPs). Refusing to pin '
                             f'more — possible DECLINE flood or ARP spoofing on the '
                             f'segment. The pool stays allocatable; investigate.')
                self._quarantine_alerted = True
            return False
        self.quarantine[ip] = until
        return True

    def decline_ip(self, mac, ip):
        '''Handles DHCPDECLINE. Revokes lease and quarantines IP.'''
        with self.lock:
            # Prevent a rogue client from declining someone else's IP.
            current_owner = self.ip_to_mac.get(ip)
            if current_owner and current_owner != mac:
                logger.warning(f'⚠️ Security: Ignored spoofed DECLINE for {ip} '
                               f'from {mac} (owned by {current_owner})')
                return
            if current_owner == mac:
                self.release(mac)
            if self._quarantine(ip, time.time() + 600):
                self.free_ips.discard(ip)
                logger.warning(f'⚠️ Received DECLINE for {ip} from {mac}. '
                               f'Quarantining for 10 min.')

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
                # Still active? Extend sentence by 5 mins (already counted, never capped).
                self._quarantine(ip, now + 300)
            else:
                # Quiet? Release.
                del self.quarantine[ip]
                # Only add back if valid and not assigned static
                if ip in self.all_possible_ips and ip not in self.ip_to_mac:
                    self.free_ips.add(ip)
                    restored_count += 1

        # Re-arm the cap alert once the quarantine has drained back under the cap.
        if self._quarantine_alerted and len(self.quarantine) < self.quarantine_cap:
            self._quarantine_alerted = False

        if restored_count > 0:
            logger.info(f'♻️ Released {restored_count} IPs from quarantine.')

    def allocate_or_renew(self, mac, hostname=None, client_profile=None):
        '''
        Main logic to determine which IP a client gets. Handles renewals, static
        mappings, and dynamic allocation strategies.
        '''
        if not client_profile: client_profile = {}
        mode = client_profile.get('mode', ClientClassifier.MODE_STANDARD)
        is_masq = client_profile.get('masq', False)

        with self.cv:
            if self.quarantine:
                self.process_quarantine_expiry()

            current_time = time.time()
            h = f'"{hostname}" ' if hostname else ''
            target_ip = None
            subnet_info = None
            nft_compat_flag = False
            force_save = True
            is_new_lease = True

            new_expiry = current_time + self.lease_time
            if mac in self.static_map:
                new_expiry = float('inf')

            # Renewal attempt
            if mac in self.leases:
                lease = self.leases[mac]
                old_mode = self._effective_mode(mac, lease)
                was_masq = lease.get('masq', False)

                if (old_mode != mode) or (was_masq != is_masq):
                    logger.info(f'♻️ Config change for {h}{mac} (mode: '
                                f'{old_mode}->{mode}, masq: {was_masq}->'
                                f'{is_masq}). Reallocating.')
                    self.release(mac)
                    # Cleared self.leases, and falls through to allocation
                else:
                    # Successful renewal
                    target_ip = lease['ip']
                    is_new_lease = False

                    # Check optimization to avoid wearing out disk drives with
                    # excessive write operations
                    if new_expiry == float('inf') and \
                       lease['expires'] == float('inf'):
                        force_save = False
                    elif new_expiry != float('inf') and \
                         lease['expires'] != float('inf'):
                        remaining = lease['expires'] - current_time
                        if remaining > (self.lease_time * 0.2):
                            force_save = False

                    # Restore topology info for the commit phase
                    if mode == ClientClassifier.MODE_COMPAT:
                        sub_data = self.subnet_leases.get(mac)
                        if sub_data:
                            subnet_info = (
                                sub_data['gateway'], sub_data['subnet'])
                            nft_compat_flag = True
                    elif mode == ClientClassifier.MODE_PLAYGROUND:
                        nft_compat_flag = False
                    else:
                        nft_compat_flag = False

            # New allocation, if renewal failed or didn't happen
            if not target_ip:
                # Static allocation
                if mac in self.static_map:
                    static_ip, _ = self.static_map[mac]

                    if mode == ClientClassifier.MODE_PLAYGROUND:
                        if self.playground_subnet and \
                           ipaddress.IPv4Address(static_ip) in \
                           self.playground_subnet:
                            target_ip = static_ip
                            nft_compat_flag = False
                        else:
                            logger.error(f'❌ Static IP {static_ip} for {mac} '
                                         f'is not in the playground subnet.')
                            return None
                    elif mode == ClientClassifier.MODE_COMPAT:
                        # Validate alignment for /30
                        subnet_cidr, gw_ip = \
                            self.check_compat_alignment(static_ip)
                        if subnet_cidr:
                            target_ip = static_ip
                            subnet_info = (gw_ip, subnet_cidr)
                            nft_compat_flag = True
                        else:
                            logger.error(f'❌ Static IP {static_ip} for {mac} '
                                         f'is not aligned for compat mode.')
                            return None
                    else:  # Standard
                        target_ip = static_ip
                        nft_compat_flag = False
                else:
                    # Playground /24../29
                    if mode == ClientClassifier.MODE_PLAYGROUND:
                        if not self.playground_subnet:
                            logger.error(f'❌ Playground requested by {mac} '
                                         f'but not configured.')
                            return None
                        if self.playground_free_ips:
                            # Pick any free IP from the playground pool
                            target_ip = self.playground_free_ips.pop()
                            nft_compat_flag = False
                        else:
                            logger.error(f'❌ Playground pool exhausted.')
                            return None
                    # Compat /30
                    elif mode == ClientClassifier.MODE_COMPAT:
                        subnet = self.find_free_slash_30()
                        if subnet:
                            block = [str(x) for x in subnet]
                            # block=[net, gw, client, bcast]
                            target_ip = block[2]
                            subnet_info = (block[1], str(subnet))
                            nft_compat_flag = True

                            # Claim IPs
                            for ip in block:
                                if ip in self.free_ips:
                                    self.free_ips.remove(ip)
                        else:
                            logger.error(f'❌ No /30 subnets available for '
                                         f'compat client {mac}.')
                            return None
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
                                    if not self._quarantine(candidate,
                                                            current_time + 300):
                                        # Cap hit: don't leak it, return to the pool.
                                        self.free_ips.add(candidate)
                                    continue
                                target_ip = candidate
                                nft_compat_flag = False
                                break
                        if not target_ip:
                            logger.error('❌ Pool exhausted (or all '
                                         'candidates busy on wire).')
                            return None

            # Commit the new state
            if not target_ip: return None

            # Update in-memory leases
            self.leases[mac] = {
                'ip': target_ip,
                'expires': new_expiry,
                'mode': mode,
                'masq': is_masq
            }
            if hostname:
                self.leases[mac]['hostname'] = hostname
            self.ip_to_mac[target_ip] = mac
            if subnet_info:
                # In compat mode we need to store and create the /30 structure
                self.subnet_leases[mac] = {
                    'gateway': subnet_info[0],
                    'subnet': subnet_info[1]
                }

                if self.sys:
                    self.sys.add_alias_ip(subnet_info[0], 30)
                    try:
                        net = ipaddress.IPv4Network(subnet_info[1])
                        blk = [str(x) for x in net]
                        self.sys.update_compat_block(
                            'add', subnet_info[1], blk[0], blk[1], blk[3])
                    except: pass
                else:
                    # Clean up is switching away from compat mode
                    self.subnet_leases.pop(mac, None)
            if self.sys:
                self.sys.update_client_nft('add', target_ip, mode)

            # Apply masquerading (source NAT)
            if is_masq and self.sys:
                gw_ip = str(self.server_ip)
                if mode == ClientClassifier.MODE_COMPAT and subnet_info:
                    gw_ip = subnet_info[0]
                elif mode == ClientClassifier.MODE_PLAYGROUND and \
                     self.playground_gateway:
                    gw_ip = self.playground_gateway
                self.sys.update_snat('add', target_ip, gw_ip)

            # Trigger on new allocation or configuration changes, skip renewals.
            if is_new_lease:
                env = {
                    'ISODHCP_MODE': mode,
                    'ISODHCP_MASQ': '1' if is_masq else '0',
                    'ISODHCP_EXPIRY': str(new_expiry)
                }
                if mode == ClientClassifier.MODE_COMPAT and subnet_info:
                    env['ISODHCP_GATEWAY'] = subnet_info[0]
                    env['ISODHCP_SUBNET'] = subnet_info[1]
                    env['ISODHCP_NETMASK'] = '255.255.255.252'
                elif mode == ClientClassifier.MODE_PLAYGROUND:
                    env['ISODHCP_GATEWAY'] = self.playground_gateway
                    env['ISODHCP_SUBNET'] = str(self.playground_subnet)
                    env['ISODHCP_NETMASK'] = str(self.playground_subnet.netmask)
                else:
                    env['ISODHCP_GATEWAY'] = str(self.server_ip)
                    env['ISODHCP_NETMASK'] = '255.255.255.255'
                self.trigger_hook('add', mac, target_ip, hostname, env)

            # Persist to disk
            if force_save:
                self.save_leases()
                logger.info(f'✨ Lease committed: {target_ip} for {h}{mac} '
                            f'(mode={mode}, masquerade={is_masq}, exp='
                            f'{new_expiry})')

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
                      self.sys.nft_net, self.sys.nft_bcast, self.sys.nft_subnet,
                      self.sys.nft_playground, self.sys.nft_playground_subnet]:
                if s: self.sys.flush_nft_set(s)

            # Flush source NAT
            pg_cidr = str(self.playground_subnet) \
                if self.playground_subnet else None
            self.sys.flush_firewall(playground_cidr=pg_cidr)

            # Repopulate
            if self.playground_subnet:
                self.sys.update_playground_subnet(
                    'add', str(self.playground_subnet))
            count = 0
            for mac, data in self.leases.items():
                ip = data['ip']
                # Resolve the category from authoritative state, not the raw
                # 'mode' field: static and disk-reloaded leases lack it, and
                # defaulting them to standard used to file compat clients into
                # the isolated set on every startup and reload.
                mode = self._effective_mode(mac, data)

                # Check if it is a compat/legacy lease
                if mac in self.subnet_leases:
                    sub = self.subnet_leases[mac]
                    gw = sub['gateway']
                    cidr = sub['subnet']
                    self.sys.add_alias_ip(gw, 30)
                    try:
                        net = ipaddress.IPv4Network(cidr)
                        blk = [str(x) for x in net]
                        self.sys.update_compat_block(
                            'add', cidr, blk[0], blk[1], blk[3])
                    except: pass
                self.sys.update_client_nft('add', ip, mode)

                if data.get('masq', False):
                    gw = str(self.server_ip)
                    if mac in self.subnet_leases:
                        gw = self.subnet_leases[mac]['gateway']
                    self.sys.update_snat('add', data['ip'], gw)
                count += 1
            return count

def resolve_socket_path(iface, explicit=None, for_daemon=False):
    '''Locate the diagnostics Unix socket for `iface`.

    The daemon and the (same-binary) client must agree on a path without the
    operator having to think about it. We probe a small ordered list of
    well-known directories: systemd's $STATE_DIRECTORY (set for units with
    StateDirectory=), the conventional /var/lib/isodhcp, and finally the cwd.
    The daemon picks the first writable directory; the client picks the first
    where the socket already exists (falling back to the daemon's choice for a
    useful "not running" message). --socket overrides all of this.'''
    if explicit:
        return explicit
    name = SOCKET_FILE.replace('{INTERFACE}', re.sub(r'[^a-zA-Z0-9]', '_', iface))
    dirs = []
    sd = os.environ.get('STATE_DIRECTORY')
    if sd:
        dirs.append(sd.split(':')[0])
    dirs.append('/var/lib/isodhcp')
    dirs.append(os.getcwd())
    seen = set()
    cands = []
    for d in dirs:
        if d and d not in seen:
            seen.add(d)
            cands.append(os.path.join(d, name))
    if for_daemon:
        for c in cands:
            parent = os.path.dirname(c)
            if os.path.isdir(parent) and os.access(parent, os.W_OK):
                return c
    else:
        for c in cands:
            if os.path.exists(c):
                return c
    return cands[0]

class DiagnosticsServer:
    '''Read-only introspection endpoint served over a Unix domain socket.

    isodhcp ships as a single binary that runs as a capability-holding systemd
    service. Rather than make operators reproduce those privileges (or read
    kernel/nftables state that could race the daemon), the running daemon
    answers status/config/dump/show/verify queries here, and the same binary
    invoked in client mode just formats the reply. The socket is 0600 and, via
    SO_PEERCRED, only serves the daemon's own uid or root. Every handler is
    wrapped so a diagnostics fault can never take down DHCP service.'''

    def __init__(self, server, socket_path):
        self.server = server
        self.socket_path = socket_path
        self.running = True
        self._sock = None
        self.allowed_uids = {os.getuid(), 0}

    def _peer_allowed(self, conn):
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                  struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', raw)
            return uid in self.allowed_uids
        except Exception:
            return False

    def handle_client(self, conn):
        try:
            conn.settimeout(5.0)
            data = b''
            while b'\n' not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not data:
                return
            if not self._peer_allowed(conn):
                self._send(conn, {'status': 'error',
                                  'message': 'permission denied: run the '
                                  'client as the isodhcp service user or root'})
                return
            try:
                request = json.loads(data.decode('utf-8'))
            except Exception:
                self._send(conn, {'status': 'error',
                                  'message': 'malformed request'})
                return
            cmd = request.get('cmd')
            handlers = {
                'status': self.server.diag_status,
                'config': self.server.diag_config,
                'dump': self.server.diag_dump,
                'show': self.server.diag_show,
                'verify': self.server.diag_verify,
            }
            handler = handlers.get(cmd)
            if not handler:
                self._send(conn, {'status': 'error',
                                  'message': f'unknown command: {cmd}'})
                return
            try:
                resp = handler(request)
            except Exception as e:
                logger.error(f'Diagnostics handler "{cmd}" failed: {e}')
                resp = {'status': 'error', 'message': f'internal error: {e}'}
            self._send(conn, resp)
        except Exception as e:
            logger.debug(f'Diagnostics client error: {e}')
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _send(self, conn, obj):
        try:
            conn.sendall((json.dumps(obj) + '\n').encode('utf-8'))
        except Exception:
            pass

    def run(self):
        try:
            if os.path.exists(self.socket_path):
                os.remove(self.socket_path)
        except OSError as e:
            logger.error(f'Diagnostics: cannot clear stale socket '
                         f'{self.socket_path}: {e} (introspection disabled)')
            return
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(self.socket_path)
            s.listen(4)
            os.chmod(self.socket_path, 0o600)
        except Exception as e:
            logger.error(f'Diagnostics: failed to bind {self.socket_path}: '
                         f'{e} (introspection disabled)')
            return
        self._sock = s
        logger.info(f'🔌 Diagnostics socket ready: {self.socket_path}')
        while self.running:
            try:
                conn, _ = s.accept()
            except OSError:
                break
            t = threading.Thread(target=self.handle_client, args=(conn,),
                                 daemon=True)
            t.start()
        try:
            s.close()
        except Exception:
            pass

    def stop(self):
        self.running = False
        try:
            # Unblock accept() with a throwaway self-connection.
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                c.connect(self.socket_path)
            except Exception:
                pass
            c.close()
        except Exception:
            pass
        try:
            if os.path.exists(self.socket_path):
                os.remove(self.socket_path)
        except Exception:
            pass

class UnnumberedDHCPServer:
    def __init__(self, interface, server_ip=None, pool_cidr=None,
                 dns_server=None, lease_time=LEASE_TIME,
                 lease_file=LEASE_FILE, static_map=None, playground_size=0,
                 pg_macs=None, pg_ouis=None, pg_vendors=None,
                 compat_macs=None, compat_ouis=None, compat_vendors=None,
                 masq_macs=None, masq_ouis=None, masq_vendors=None,
                 nft_iso=None, nft_compat=None, nft_set_playground=None,
                 nft_set_playground_subnet=None, nft_gw=None, nft_net=None,
                 nft_bcast=None, nft_subnet=None, hook_file=None,
                 isolation_mode='system', custom_options=None,
                 socket_path=None):
        self.iface = interface
        self.lease_time = lease_time
        self.lease_file = lease_file
        self.start_time = time.time()
        self.limiter = RateLimiter(rate=2.0, burst=5)

        self.pg_macs = pg_macs or set()
        self.pg_ouis = pg_ouis or set()
        self.pg_vendors = pg_vendors or set()

        self.compat_macs = compat_macs or set()
        self.compat_ouis = compat_ouis or set()
        self.compat_vendors = compat_vendors or set()

        self.masq_macs = masq_macs or set()
        self.masq_ouis = masq_ouis or set()
        self.masq_vendors = masq_vendors or set()

        self.custom_options = custom_options or []

        static_profiles = {}
        for mac in (static_map or {}):
            mode = ClientClassifier.MODE_STANDARD
            if mac in self.compat_macs:
                mode = ClientClassifier.MODE_COMPAT
            elif mac in self.pg_macs:
                mode = ClientClassifier.MODE_PLAYGROUND
            static_profiles[mac] = {
                'mode': mode,
                'masq': (mac in self.masq_macs)
            }

        self.classifier = ClientClassifier(
            # Playground
            pg_macs=self.pg_macs,
            pg_ouis=self.pg_ouis,
            pg_vendors=self.pg_vendors,

            # Compatibility configuration
            compat_macs=self.compat_macs,
            compat_ouis=self.compat_ouis,
            compat_vendors=self.compat_vendors,

            # Masquerading configuration (source NAT)
            masq_macs=self.masq_macs,
            masq_ouis=self.masq_ouis,
            masq_vendors=self.masq_vendors,

            # Static profiles
            static_profiles=static_profiles
        )

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
            nft_set_compat=nft_compat, nft_set_playground=nft_set_playground,
            nft_set_playground_subnet=nft_set_playground_subnet,
            nft_set_gw=nft_gw, nft_set_net=nft_net, nft_set_bcast=nft_bcast,
            nft_set_subnet=nft_subnet)

        # Pass configs to LeaseManager
        self.lease_mgr = LeaseManager(self.pool_cidr, self.server_ip,
                                      self.lease_file, self.lease_time,
                                      sys_integrator=self.sys,
                                      static_map=static_map,
                                      compat_macs=self.compat_macs,
                                      masq_macs=self.masq_macs,
                                      state_change_callback=self.execute_hook,
                                      playground_size=playground_size)

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

        # Read-only diagnostics endpoint (single-binary client mode talks here).
        self.socket_path = resolve_socket_path(
            self.iface, explicit=socket_path, for_daemon=True)
        self.diag = DiagnosticsServer(self, self.socket_path)
        self.diag_thread = threading.Thread(target=self.diag.run, daemon=True)

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
            profile = self.classifier.get_profile(client_mac, pkt)
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

            # DHCPDISCOVER (Client needs an IP)
            if msg_type == 1:
                assigned_ip = self.lease_mgr.allocate_or_renew(
                    client_mac, hostname=hostname, client_profile=profile)
                if assigned_ip:
                    self.send_reply(pkt, 'offer', assigned_ip, xid, client_mac)

            # DHCPREQUEST (Client accepts offer or renews)
            elif msg_type == 3:
                req_ip = self.get_client_requested_ip(pkt)

                # Security check: Did we actually assign this IP to this MAC?
                # We peek into the lease manager without changing state yet
                current_owner_mac = self.lease_mgr.ip_to_mac.get(req_ip)

                # It's a valid request for an IP we reserved for them
                if current_owner_mac == client_mac:
                    # Confirm allocation (updates timestamp)
                    final_ip = self.lease_mgr.allocate_or_renew(
                        client_mac, hostname=hostname, client_profile=profile)

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

            # DHCPDECLINE (Client suspects IP address of being used by a rogue)
            elif msg_type == 4:
                req_ip = self.get_client_requested_ip(pkt)
                if req_ip:
                    logger.info(f'📩 Received DECLINE from {client_mac} for '
                                f'{req_ip}')
                    self.lease_mgr.decline_ip(client_mac, req_ip)

            # DHCPRELEASE (Client is shutting down politely)
            elif msg_type == 7:
                 req_ip = pkt[BOOTP].ciaddr
                 # Only allow release if the IP actually belongs to them
                 if self.lease_mgr.ip_to_mac.get(req_ip) == client_mac:
                     released_ip = self.lease_mgr.release(client_mac)
                     if released_ip:
                         try: self.ipr.route('del', dst=f'{released_ip}/32',
                                             oif=self.if_index)
                         except: pass

            # DHCPINFORM (Client has static IP, but needs other data)
            elif msg_type == 8:
                client_ip = pkt[BOOTP].ciaddr
                if client_ip == '0.0.0.0': return
                # Only answer for an address inside our managed pool. This keeps
                # the server from being coaxed into emitting a unicast reply
                # aimed at an arbitrary off-pool ciaddr.
                try:
                    in_pool = ipaddress.IPv4Address(client_ip) in \
                        self.lease_mgr.network
                except ValueError:
                    in_pool = False
                if not in_pool:
                    logger.warning(f'⚠️ Ignoring INFORM from {client_mac} for '
                                   f'out-of-pool IP {client_ip}')
                    return
                logger.info(f'ℹ️ Received INFORM from {client_ip} '
                            f'({client_mac})')
                self.send_reply(pkt, 'ack', client_ip, xid, client_mac,
                                is_inform=True)
        except Exception as e:
            logger.error(f'⚠️ Malformed packet caused crash: {e}')

    def send_reply(self, old_pkt, msg_type, client_ip, xid, client_mac,
                   is_inform=False):
        op_code = 5 if msg_type == 'ack' else 2 # Ack or Offer
        if msg_type == 'nak': op_code = 6

        options = [
            ('message-type', op_code),
            ('server_id', self.server_ip),
        ]

        if msg_type != 'nak':
            # Read a consistent (mode, gateway, netmask) snapshot under the lease
            # lock; the garbage-collector thread can release a lease and tear down
            # its subnet_leases entry concurrently, and we don't want to build a
            # reply from half-updated state. sendp() stays outside the lock.
            router_ip = self.server_ip
            netmask_to_send = '255.255.255.255'
            with self.lease_mgr.lock:
                lease = self.lease_mgr.leases.get(client_mac)
                # Same shared classifier used by reapply/release/diagnostics, so
                # a mode-less lease (static reservation, or a DHCPINFORM handled
                # without going through allocation) still yields the right
                # gateway and netmask instead of falling back to /32.
                mode = classify_lease_mode(
                    client_mac, lease or {}, self.lease_mgr.subnet_leases)

                if mode == ClientClassifier.MODE_PLAYGROUND and \
                   self.lease_mgr.playground_subnet:
                    router_ip = self.lease_mgr.playground_gateway
                    netmask_to_send = \
                        str(self.lease_mgr.playground_subnet.netmask)
                elif mode == ClientClassifier.MODE_COMPAT:
                    # Use THIS client's /30 gateway. (Previously referenced a bare
                    # `mac` that resolved to a stale module-global, so every
                    # compat client was handed the last static client's gateway.)
                    # Guard the lookup so a missing entry falls back to the server
                    # route instead of crashing the reply path.
                    sub = self.lease_mgr.subnet_leases.get(client_mac)
                    if sub:
                        router_ip = sub['gateway']
                        netmask_to_send = '255.255.255.252'

            opt121 = b'\x00' + socket.inet_aton(router_ip)

            if not is_inform:
                options.append(('lease_time', self.lease_time))

            options.extend([
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
                (249, opt121),
            ])

            # Inject custom options
            if self.custom_options:
                options.extend(self.custom_options)

        options.append('end')

        yiaddr_val = '0.0.0.0' if msg_type == 'nak' or is_inform else client_ip
        reply = (
            Ether(src=self.server_mac, dst=client_mac) /
            IP(src=self.server_ip, dst=client_ip) /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=yiaddr_val, siaddr=self.server_ip, giaddr=0,
                  chaddr=mac2str(client_mac), xid=xid,
                  ciaddr=client_ip if is_inform else '0.0.0.0') /
            DHCP(options=options)
        )
        sendp(reply, iface=self.iface, verbose=False)
        log_type = 'INFORM_ACK' if is_inform else msg_type.upper()
        logger.info(f'📤 Sent {log_type} to {client_ip} ({client_mac})')

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
            logger.info('⚠️ Detected local DNS stub (systemd-resolved). '
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
                raise ValueError(f'⚠️ No IPv4 address assigned to '
                                 f'"{iface_name}"')

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
                raise ValueError(f'⚠️ Could not determine IP for '
                                 f'"{iface_name}"')

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

    # ----- Diagnostics (answered on the Unix socket for client mode) -----
    #
    # These run on the diagnostics thread. They read live in-memory state under
    # lease_mgr.lock but NEVER hold that lock across a kernel/nft read (which
    # can be slow and would stall the DHCP path). Everything is scoped to
    # isodhcp's OWN footprint: its private table, the sets it was configured to
    # populate, in-pool interface aliases, and in-pool /32 routes. It never
    # inspects or flags foreign tables/rules/addresses — isodhcp is only one of
    # several things that may be managing this host's firewall.

    def _resolve_mode(self, mac, data, subnet_leases):
        '''Diagnostics view of a lease's category. Uses the same shared
        classifier as the daemon's own reapply/release paths, on a consistent
        snapshot of subnet_leases, so what --verify expects matches what the
        daemon actually applies.'''
        return classify_lease_mode(mac, data, subnet_leases)

    def _compress_ranges(self, ip_objs_sorted):
        '''Collapse a sorted list of IPv4Address into compact range strings
        ("a-b" for a run, "a" for a singleton). Keeps output bounded even on a
        /16 pool, where listing every free address would be unusable.'''
        ranges = []
        start = prev = None
        for ip in ip_objs_sorted:
            if start is None:
                start = prev = ip
            elif int(ip) == int(prev) + 1:
                prev = ip
            else:
                ranges.append(str(start) if start == prev
                              else f'{start}-{prev}')
                start = prev = ip
        if start is not None:
            ranges.append(str(start) if start == prev else f'{start}-{prev}')
        return ranges

    def _count_free_slash30(self, free_ips):
        '''Number of aligned, fully-free /30 blocks (compat capacity). A
        fragmented pool can hold thousands of free IPs yet zero /30s.'''
        n = 0
        for ip in free_ips:
            if int(ipaddress.IPv4Address(ip)) % 4:
                continue
            net = ipaddress.IPv4Network(f'{ip}/30')
            if all(str(x) in free_ips for x in net):
                n += 1
        return n

    def _connected_nets(self, aliases):
        '''Networks the interface is directly connected to, derived from its
        addresses. A client covered by one is reachable without a /32 host
        route (numbered deployment), so its missing /32 is not a fault.'''
        nets = []
        for aip, apfx in aliases.items():
            try:
                nets.append(ipaddress.IPv4Interface(f'{aip}/{apfx}').network)
            except ValueError:
                pass
        return nets

    def _nft_json(self, argv):
        '''Run an `nft -j` read command. Returns (parsed, error_or_None).
        Forces the C locale and explicit UTF-8 decoding so neither the JSON nor
        any error text depends on the caller's locale.'''
        try:
            r = subprocess.run(
                ['nft', '-j'] + argv, capture_output=True, encoding='utf-8',
                env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
        except FileNotFoundError:
            return None, 'nft not installed'
        except Exception as e:
            return None, str(e)
        if r.returncode != 0:
            return None, (r.stderr.strip().splitlines()[0]
                          if r.stderr.strip() else 'nft returned non-zero')
        try:
            return json.loads(r.stdout), None
        except Exception as e:
            return None, f'unparseable nft output: {e}'

    def _nft_elem_to_str(self, e):
        '''Normalise one nft -j set element to a string. Handles every form:
        a bare "1.2.3.4"; an interval {"prefix":{"addr","len"}}; and the
        {"elem":{"val": ...}} wrapper nft emits for sets with flags
        timeout/dynamic or per-element counters (whose val may itself be a
        prefix). Returns None for anything unrecognised.'''
        if isinstance(e, str):
            return e
        if isinstance(e, dict):
            if 'elem' in e and isinstance(e['elem'], dict):
                return self._nft_elem_to_str(e['elem'].get('val'))
            if 'prefix' in e:
                p = e['prefix']
                return f"{p['addr']}/{p['len']}"
        return None

    def _read_set_elements(self, setspec):
        '''Elements of a configured named set. Returns (set_of_strings,
        error_or_None). A malformed element is skipped, not fatal.'''
        data, err = self._nft_json(['list', 'set'] + setspec.split())
        if err:
            return None, err
        elems = set()
        for o in data.get('nftables', []):
            s = o.get('set')
            if not s:
                continue
            for e in s.get('elem', []):
                try:
                    v = self._nft_elem_to_str(e)
                except Exception:
                    v = None
                if v is not None:
                    elems.add(v)
        return elems, None

    def _read_snat_rules(self):
        '''Map daddr -> [snat targets] from OUR private postrouting chain.'''
        data, err = self._nft_json(
            ['list', 'chain', 'ip', self.sys.table_name, 'postrouting'])
        if err:
            return None, err
        rules = {}
        for o in data.get('nftables', []):
            rule = o.get('rule')
            if not rule:
                continue
            try:
                daddr = snat = None
                for e in rule.get('expr', []):
                    if 'match' in e:
                        left = e['match'].get('left')
                        if isinstance(left, dict) and \
                           left.get('payload', {}).get('field') == 'daddr' and \
                           e['match'].get('op') == '==':
                            daddr = e['match'].get('right')
                    if 'snat' in e and isinstance(e['snat'], dict):
                        snat = e['snat'].get('addr')
                if daddr and snat:
                    rules.setdefault(daddr, []).append(snat)
            except Exception:
                continue
        return rules, None

    def _read_kernel_l3(self):
        '''Live /32 routes and interface addresses on our interface. Uses a
        fresh IPRoute() — self.ipr belongs to the sniff/GC threads.'''
        routes32, aliases = set(), {}
        try:
            with IPRoute() as ipr:
                for r in ipr.get_routes(oif=self.if_index, family=2):
                    a = dict(r['attrs'])
                    # Only OUR host routes: /32, main table (254), unicast (1).
                    # get_routes(oif=...) also returns the kernel's automatic
                    # local/broadcast /32s from the local table (255) — those
                    # are not isodhcp routes and must not be mistaken for drift.
                    # On policy-routing boxes the table id can arrive via
                    # RTA_TABLE rather than the compat 'table' field, so prefer
                    # the attribute. isodhcp only ever writes the main table.
                    tbl = a.get('RTA_TABLE', r.get('table'))
                    if r.get('dst_len') == 32 and tbl == 254 and \
                       r.get('type') == 1:
                        dst = a.get('RTA_DST')
                        if dst:
                            routes32.add(dst)
                for a in ipr.get_addr(index=self.if_index, family=2):
                    local = dict(a['attrs']).get('IFA_LOCAL')
                    if local:
                        aliases[local] = a['prefixlen']
        except Exception as e:
            logger.error(f'Diagnostics: kernel L3 read failed: {e}')
        return routes32, aliases

    def _read_routes_raw(self):
        '''Every route on our interface with its table/type/proto exposed, so
        an operator can extract unfiltered ground truth (no interpretation).'''
        rows = []
        try:
            with IPRoute() as ipr:
                for r in ipr.get_routes(oif=self.if_index, family=2):
                    a = dict(r['attrs'])
                    rows.append({
                        'dst': a.get('RTA_DST') or 'default',
                        'dst_len': r.get('dst_len'),
                        'table': a.get('RTA_TABLE', r.get('table')),
                        'type': r.get('type'),
                        'proto': r.get('proto'),
                        'scope': r.get('scope'),
                    })
        except Exception as e:
            logger.error(f'Diagnostics: raw route read failed: {e}')
        return rows

    def diag_firewall(self, request):
        '''Raw ACTUAL kernel/nftables state as the daemon sees it — the
        ground truth to compare against --dump leases and --verify. Reads live
        state; holds no lock.'''
        routes32, aliases = self._read_kernel_l3()
        snat, snat_err = self._read_snat_rules()
        sets_out = {}
        managed = [
            ('isolated', self.sys.nft_iso), ('compat', self.sys.nft_compat),
            ('playground', self.sys.nft_playground),
            ('playground_subnet', self.sys.nft_playground_subnet),
            ('gateway', self.sys.nft_gw), ('network', self.sys.nft_net),
            ('broadcast', self.sys.nft_bcast), ('subnet', self.sys.nft_subnet),
        ]
        for label, spec in managed:
            if not spec:
                continue
            elems, err = self._read_set_elements(spec)
            sets_out[label] = {'spec': spec, 'error': err,
                               'elements': (sorted(elems) if elems else [])}
        return {
            'status': 'ok', 'version': VERSION,
            'iface': self.iface, 'private_table': self.sys.table_name,
            'host_routes_32': sorted(routes32, key=ipaddress.IPv4Address),
            'routes_raw': self._read_routes_raw(),
            'interface_aliases': dict(sorted(
                aliases.items(), key=lambda kv: ipaddress.IPv4Address(kv[0]))),
            'snat_rules': ('UNREADABLE: ' + snat_err) if snat_err else snat,
            'nft_sets': sets_out,
        }

    def diag_status(self, request):
        lm = self.lease_mgr
        now = time.time()
        with lm.lock:
            leases = {m: dict(d) for m, d in lm.leases.items()}
            subnet_leases = {m: dict(d) for m, d in lm.subnet_leases.items()}
            free_ips = set(lm.free_ips)
            pool_total = len(lm.all_possible_ips)
            quarantine = dict(lm.quarantine)
            q_cap = lm.quarantine_cap
            pg_subnet = str(lm.playground_subnet) if lm.playground_subnet \
                else None
            pg_gw = lm.playground_gateway
            pg_free = len(lm.playground_free_ips)
            next_exp = lm.get_next_expiration()
        with self.limiter.lock:
            rl_tracked = len(self.limiter.clients)
            rl_max = self.limiter.max_clients
            rl_sat = self.limiter._full_alerted
        standard = compat = playground = 0
        for m, d in leases.items():
            mode = self._resolve_mode(m, d, subnet_leases)
            if mode == ClientClassifier.MODE_COMPAT:
                compat += 1
            elif mode == ClientClassifier.MODE_PLAYGROUND:
                playground += 1
            else:
                standard += 1
        free = len(free_ips)
        util = round(100.0 * (pool_total - free) / pool_total, 1) \
            if pool_total else 0.0
        return {
            'status': 'ok', 'version': VERSION, 'pid': os.getpid(),
            'iface': self.iface, 'server_ip': str(self.server_ip),
            'pool_cidr': str(self.pool_cidr),
            'isolation_mode': self.sys.isolation_mode if self.sys else 'unknown',
            'uptime_seconds': round(now - self.start_time, 1),
            'pool': {
                'total': pool_total, 'leased': len(leases), 'free': free,
                'quarantined': len(quarantine), 'utilization_pct': util,
                'free_slash30_blocks': self._count_free_slash30(free_ips),
            },
            'clients': {'standard': standard, 'compat': compat,
                        'playground': playground},
            'quarantine': {'count': len(quarantine), 'cap': q_cap,
                           'at_cap': len(quarantine) >= q_cap},
            'ratelimit': {'tracked': rl_tracked, 'max': rl_max,
                          'saturated': bool(rl_sat)},
            'playground': ({'subnet': pg_subnet, 'gateway': pg_gw,
                            'free': pg_free, 'used': playground}
                           if pg_subnet else None),
            'next_expiry_epoch': (None if next_exp in (None, float('inf'))
                                  else round(next_exp, 1)),
            'lease_file': os.path.abspath(self.lease_file),
            'socket': self.socket_path,
        }

    def diag_config(self, request):
        lm = self.lease_mgr
        srt = lambda s: sorted(s) if s else []
        return {
            'status': 'ok', 'version': VERSION, 'iface': self.iface,
            'server_ip': str(self.server_ip), 'pool_cidr': str(self.pool_cidr),
            'dns_server': self.dns_server, 'lease_time': self.lease_time,
            'lease_file': os.path.abspath(self.lease_file),
            'socket': self.socket_path,
            'isolation_mode': self.sys.isolation_mode if self.sys else 'unknown',
            'private_table': self.sys.table_name,
            'playground': ({'subnet': str(lm.playground_subnet),
                            'gateway': lm.playground_gateway}
                           if lm.playground_subnet else None),
            'classifier': {
                'compat_macs': srt(self.compat_macs),
                'compat_ouis': srt(self.compat_ouis),
                'compat_vendors': srt(self.compat_vendors),
                'playground_macs': srt(self.pg_macs),
                'playground_ouis': srt(self.pg_ouis),
                'playground_vendors': srt(self.pg_vendors),
                'masquerade_macs': srt(self.masq_macs),
                'masquerade_ouis': srt(self.masq_ouis),
                'masquerade_vendors': srt(self.masq_vendors),
            },
            'nft_sets': {
                'isolated': self.sys.nft_iso, 'compat': self.sys.nft_compat,
                'playground': self.sys.nft_playground,
                'playground_subnet': self.sys.nft_playground_subnet,
                'gateway': self.sys.nft_gw, 'network': self.sys.nft_net,
                'broadcast': self.sys.nft_bcast, 'subnet': self.sys.nft_subnet,
            },
            'static_count': len(lm.static_map),
            'custom_option_codes': [c for c, _ in self.custom_options],
        }

    def diag_dump(self, request):
        sections = request.get('sections') or ['leases', 'subnets']
        lm = self.lease_mgr
        now = time.time()
        out = {'status': 'ok', 'version': VERSION, 'sections': {}}
        with lm.lock:
            leases = {m: dict(d) for m, d in lm.leases.items()}
            subnet_leases = {m: dict(d) for m, d in lm.subnet_leases.items()}
            quarantine = dict(lm.quarantine)
            pool_total = len(lm.all_possible_ips)
            free_set = set(lm.free_ips) if 'pool' in sections else set()
        if 'leases' in sections:
            rows = []
            for m, d in sorted(leases.items()):
                exp = d.get('expires')
                rows.append({
                    'mac': m, 'ip': d.get('ip'), 'hostname': d.get('hostname'),
                    'mode': self._resolve_mode(m, d, subnet_leases),
                    'masq': bool(d.get('masq')),
                    'static': exp == float('inf'),
                    'expires_epoch': None if exp == float('inf') else exp,
                })
            out['sections']['leases'] = rows
        if 'subnets' in sections:
            out['sections']['subnets'] = [
                {'mac': m, 'gateway': d['gateway'], 'subnet': d['subnet']}
                for m, d in sorted(subnet_leases.items())]
        if 'quarantine' in sections:
            out['sections']['quarantine'] = [
                {'ip': ip, 'release_epoch': round(exp, 1),
                 'release_in': round(exp - now, 1)}
                for ip, exp in sorted(
                    quarantine.items(),
                    key=lambda kv: ipaddress.IPv4Address(kv[0]))]
        if 'ratelimit' in sections:
            with self.limiter.lock:
                out['sections']['ratelimit'] = {
                    'tracked': len(self.limiter.clients),
                    'max': self.limiter.max_clients,
                    'saturated': bool(self.limiter._full_alerted)}
        if 'pool' in sections:
            free_objs = sorted(ipaddress.IPv4Address(x) for x in free_set)
            out['sections']['pool'] = {
                'total': pool_total, 'free_count': len(free_objs),
                'free_slash30_blocks': self._count_free_slash30(free_set),
                # Ranges, not a full IP list: a /16 would otherwise dump 65k
                # entries. Gaps in the ranges are the in-use/reserved IPs.
                'free_ranges': self._compress_ranges(free_objs)}
        if 'config' in sections:
            out['sections']['config'] = self.diag_config(request)
        if 'firewall' in sections:
            out['sections']['firewall'] = self.diag_firewall(request)
        return out

    def diag_show(self, request):
        key = (request.get('key') or '').strip().lower()
        lm = self.lease_mgr
        with lm.lock:
            leases = {m: dict(d) for m, d in lm.leases.items()}
            subnet_leases = {m: dict(d) for m, d in lm.subnet_leases.items()}
        found = None
        if key in leases:
            found = key
        else:
            for m, d in leases.items():
                if d.get('ip') == key or \
                   (d.get('hostname') or '').lower() == key:
                    found = m
                    break
        if not found:
            return {'status': 'error', 'message': f'no lease matching "{key}"'}
        d = leases[found]
        ip = d.get('ip')
        is_compat = found in subnet_leases
        mode = self._resolve_mode(found, d, subnet_leases)
        exp = d.get('expires')
        info = {
            'status': 'ok', 'mac': found, 'ip': ip,
            'hostname': d.get('hostname'), 'mode': mode,
            'masq': bool(d.get('masq')), 'static': exp == float('inf'),
            'expires_epoch': None if exp == float('inf') else exp,
        }
        if is_compat:
            info['gateway'] = subnet_leases[found]['gateway']
            info['subnet'] = subnet_leases[found]['subnet']
        # Scoped resource checklist (live reads).
        routes32, aliases = self._read_kernel_l3()
        checks = []
        if is_compat:
            gw = subnet_leases[found]['gateway']
            checks.append({'resource': 'gateway_alias',
                           'detail': f'{gw}/30 on {self.iface}',
                           'present': gw in aliases})
        else:
            # Present if a /32 host route exists OR a connected route on the
            # interface already reaches it (numbered deployment).
            has32 = ip in routes32
            try:
                obj = ipaddress.IPv4Address(ip)
                covered = any(obj in n
                              for n in self._connected_nets(aliases))
            except ValueError:
                covered = False
            if has32:
                detail = f'{ip}/32 host route'
            elif covered:
                detail = f'{ip} (reachable via connected route)'
            else:
                detail = f'{ip}/32 host route'
            checks.append({'resource': 'route', 'detail': detail,
                           'present': has32 or covered})
        if is_compat:
            setspec = self.sys.nft_compat
        elif mode == ClientClassifier.MODE_PLAYGROUND:
            setspec = self.sys.nft_playground
        else:
            setspec = self.sys.nft_iso
        if setspec:
            elems, err = self._read_set_elements(setspec)
            checks.append({'resource': 'nft_set', 'detail': setspec,
                           'present': None if err else (ip in elems),
                           'error': err})
        if d.get('masq'):
            rules, err = self._read_snat_rules()
            checks.append({'resource': 'snat', 'detail': f'daddr {ip}',
                           'present': None if err else (ip in rules),
                           'error': err})
        info['checks'] = checks
        return info

    def diag_verify(self, request):
        lm = self.lease_mgr
        pool = ipaddress.IPv4Network(self.pool_cidr)
        server_ip = str(self.server_ip)
        # 1. Cheap snapshot under the lock; release before any kernel read.
        with lm.lock:
            leases = {m: dict(d) for m, d in lm.leases.items()}
            subnet_leases = {m: dict(d) for m, d in lm.subnet_leases.items()}
            ip_to_mac = dict(lm.ip_to_mac)
            free_ips = set(lm.free_ips)
            quarantine = set(lm.quarantine.keys())
            pg_subnet = str(lm.playground_subnet) if lm.playground_subnet \
                else None
            pg_gw = lm.playground_gateway
        snap1 = {m: (d.get('ip'), d.get('expires')) for m, d in leases.items()}

        disc = []

        def add(sev, resource, kind, detail, mac=None, ip=None):
            disc.append({'severity': sev, 'resource': resource, 'kind': kind,
                         'detail': detail, 'mac': mac, 'ip': ip,
                         'transient': False})

        # 2. Derive INTENDED state from the snapshot (isodhcp's footprint only).
        intended_routes = {ip for ip, m in ip_to_mac.items()
                           if m not in subnet_leases}
        iso_ips, compat_ips, pg_ips = set(), set(), set()
        gw_ips, net_ips, bcast_ips, subnet_cidrs = set(), set(), set(), set()
        intended_masq = {}
        intended_aliases = {server_ip}
        if pg_gw:
            intended_aliases.add(pg_gw)
        for m, d in leases.items():
            ip = d.get('ip')
            if not ip:
                continue
            mode = self._resolve_mode(m, d, subnet_leases)
            if mode == ClientClassifier.MODE_COMPAT:
                compat_ips.add(ip)
            elif mode == ClientClassifier.MODE_PLAYGROUND:
                pg_ips.add(ip)
            else:
                iso_ips.add(ip)
            if d.get('masq'):
                if mode == ClientClassifier.MODE_COMPAT and m in subnet_leases:
                    acceptable = {subnet_leases[m]['gateway']}
                elif mode == ClientClassifier.MODE_PLAYGROUND:
                    # A fresh allocation SNATs a playground client to the
                    # playground gateway; a SIGUSR1 reapply SNATs it to the
                    # server IP. Both states occur on a running daemon, so
                    # accept either rather than emit a false wrong-target.
                    acceptable = {server_ip}
                    if pg_gw:
                        acceptable.add(pg_gw)
                else:
                    acceptable = {server_ip}
                intended_masq[ip] = acceptable
        for m, sub in subnet_leases.items():
            try:
                net = ipaddress.IPv4Network(sub['subnet'])
                blk = [str(x) for x in net]
                net_ips.add(blk[0])
                gw_ips.add(blk[1])
                bcast_ips.add(blk[3])
                subnet_cidrs.add(str(net))
                intended_aliases.add(sub['gateway'])
            except Exception:
                pass

        # 3. Read ACTUAL kernel/nft state (lock released).
        routes32, aliases = self._read_kernel_l3()
        snat_actual, snat_err = self._read_snat_rules()

        # A. /32 host routes.
        # A per-client /32 is only REQUIRED when the interface is unnumbered
        # (no connected route covers the client). On a numbered deployment the
        # server holds e.g. 10.0.0.1/24 on the interface, so the connected route
        # already reaches every client and the /32 is redundant — the daemon
        # deliberately skips it there. So only alarm when a client is reachable
        # by NEITHER a /32 NOR a connected route on this interface. Isolation
        # itself is enforced by the /32 netmask handed to the client, not by
        # these router-side routes.
        connected_nets = self._connected_nets(aliases)

        def _covered(ip):
            try:
                obj = ipaddress.IPv4Address(ip)
            except ValueError:
                return False
            return any(obj in n for n in connected_nets)

        for ip in intended_routes:
            if ip not in routes32 and not _covered(ip):
                add('alarming', 'route', 'missing',
                    f'{ip} has no /32 host route and is not covered by a '
                    f'connected route on {self.iface}',
                    mac=ip_to_mac.get(ip), ip=ip)
        for ip in routes32:
            try:
                obj = ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            if obj not in pool or ip == server_ip or \
               obj == pool.network_address or obj == pool.broadcast_address:
                continue
            if ip in intended_routes:
                continue
            if ip in compat_ips:
                add('low', 'route', 'compat_redundant_32',
                    f'redundant /32 route for compat client {ip}', ip=ip)
            else:
                add('moderate', 'route', 'orphan',
                    f'/32 route {ip} on {self.iface} with no matching lease '
                    f'(stale, or added by other software)', ip=ip)

        # B. Interface aliases (in-pool only; foreign addresses are ignored)
        if server_ip not in aliases:
            add('alarming', 'alias', 'missing',
                f'server IP {server_ip} not present on {self.iface}',
                ip=server_ip)
        for ip in intended_aliases:
            if ip != server_ip and ip not in aliases:
                add('alarming', 'alias', 'missing',
                    f'gateway alias {ip} missing from {self.iface}', ip=ip)
        for ip, pfx in aliases.items():
            try:
                if ipaddress.IPv4Address(ip) not in pool:
                    continue
            except ValueError:
                continue
            if ip not in intended_aliases:
                add('moderate', 'alias', 'orphan',
                    f'stale in-pool alias {ip}/{pfx} on {self.iface}', ip=ip)
            elif ip in gw_ips and pfx != 30:
                add('moderate', 'alias', 'wrong_prefix',
                    f'gateway {ip} has /{pfx}, expected /30', ip=ip)

        # C. SNAT rules in our private table
        if snat_err:
            add('unknown', 'snat', 'unreadable',
                f'cannot read SNAT chain: {snat_err}')
        else:
            for ip, acceptable in intended_masq.items():
                targets = snat_actual.get(ip)
                if not targets:
                    add('alarming', 'snat', 'missing',
                        f'SNAT rule for {ip} missing', ip=ip)
                elif not (set(targets) & acceptable):
                    add('alarming', 'snat', 'wrong_target',
                        f'SNAT for {ip} targets {targets}, expected one of '
                        f'{sorted(acceptable)}', ip=ip)
                elif len(targets) > 1:
                    add('low', 'snat', 'duplicate',
                        f'{len(targets)} SNAT rules for {ip}', ip=ip)
            for ip in snat_actual:
                if ip not in intended_masq:
                    add('moderate', 'snat', 'orphan',
                        f'stale SNAT rule for {ip} (no masquerade lease)', ip=ip)

        # D. Configured named sets (element-level; only sets we manage)
        managed_sets = [
            (self.sys.nft_iso, iso_ips, 'nft_isolated'),
            (self.sys.nft_compat, compat_ips, 'nft_compat'),
            (self.sys.nft_playground, pg_ips, 'nft_playground'),
            (self.sys.nft_gw, gw_ips, 'nft_gateway'),
            (self.sys.nft_net, net_ips, 'nft_network'),
            (self.sys.nft_bcast, bcast_ips, 'nft_broadcast'),
            (self.sys.nft_subnet, subnet_cidrs, 'nft_subnet'),
            (self.sys.nft_playground_subnet,
             ({pg_subnet} if pg_subnet else set()), 'nft_playground_subnet'),
        ]
        for setspec, intended_elems, label in managed_sets:
            if not setspec:
                continue
            actual, err = self._read_set_elements(setspec)
            if err:
                add('unknown', label, 'unreadable',
                    f'set "{setspec}" unreadable: {err}')
                continue
            for el in intended_elems:
                if el not in actual:
                    add('alarming', label, 'missing_element',
                        f'{el} missing from set "{setspec}"', ip=el)
            for el in actual:
                if el not in intended_elems:
                    # Low, not moderate: these named sets can legitimately be
                    # co-managed by other firewall software on this host, so an
                    # element we don't recognise is not necessarily our stale
                    # entry and must not chronically fail a monitoring check.
                    add('low', label, 'extra_element',
                        f'{el} in set "{setspec}" without a lease '
                        f'(stale, or managed by other software)', ip=el)

        # E. In-memory invariants (no kernel reads; always run)
        for ip in (free_ips & set(ip_to_mac.keys())):
            add('alarming', 'internal', 'double_alloc',
                f'{ip} is simultaneously free and leased', ip=ip)
        for ip, m in ip_to_mac.items():
            if m not in leases:
                add('alarming', 'internal', 'index_desync',
                    f'{ip} indexed to {m} but {m} has no lease', mac=m, ip=ip)
        for m in subnet_leases:
            if m not in leases:
                add('alarming', 'internal', 'subnet_orphan',
                    f'subnet lease for {m} with no base lease', mac=m)
        for ip in (quarantine & free_ips):
            add('low', 'internal', 'quarantine_overlap',
                f'{ip} is both quarantined and free', ip=ip)

        # 4. Tag discrepancies for leases that changed during the read as
        # transient (racy snapshot, not real drift).
        with lm.lock:
            snap2 = {m: (d.get('ip'), d.get('expires'))
                     for m, d in lm.leases.items()}
        for x in disc:
            m = x.get('mac')
            if not m and x.get('ip'):
                m = ip_to_mac.get(x['ip'])
            if m and snap1.get(m) != snap2.get(m):
                x['transient'] = True

        alarming = sum(1 for x in disc
                       if x['severity'] == 'alarming' and not x['transient'])
        moderate = sum(1 for x in disc
                       if x['severity'] == 'moderate' and not x['transient'])
        low = sum(1 for x in disc
                  if x['severity'] == 'low' and not x['transient'])
        unknown = sum(1 for x in disc if x['severity'] == 'unknown')
        transient = sum(1 for x in disc if x['transient'])
        return {
            'status': 'ok',
            'ok': (alarming == 0 and moderate == 0 and unknown == 0),
            'summary': {'alarming': alarming, 'moderate': moderate, 'low': low,
                        'unknown': unknown, 'transient': transient,
                        'total': len(disc)},
            'discrepancies': disc,
        }

    def shutdown(self):
        '''Cleanup tasks to run when the server stops.'''
        logger.info('🛑 Server shutting down...')

        try:
            self.diag.stop()
        except Exception:
            pass

        # Force save leases to disk (save_leases writes unconditionally
        # when called directly)
        self.lease_mgr.save_leases()
        logger.info('💾 Lease state flushed to disk.')

    def start(self):
        logger.info(f'🚀 DHCP Server active on "{self.iface}"')
        logger.info(f'   IP: {self.server_ip} | Pool: {self.pool_cidr}')
        logger.info(f'   DNS: {self.dns_server} | Lease: {self.lease_time}s')

        # Bring up the diagnostics socket before we block in sniff().
        self.diag_thread.start()

        # Ensure clean state on startup too!
        self.sync_interface_addresses()
        self.lease_mgr.reapply_system_state()
        self.sync_kernel_routes()
        sniff(iface=self.iface, filter='udp and (port 67 or port 68)',
              prn=self.handle_dhcp, store=0)

def parse_custom_options(raw_options):
    '''Parses CLI options into Scapy-compatible (code, value_bytes) tuples.'''
    parsed = []
    if not raw_options: return parsed

    for opt in raw_options:
        try:
            parts = opt.split(',', 2)
            if len(parts) != 3:
                raise ValueError('Format must be CODE,TYPE,VALUE')

            code = int(parts[0])
            dtype = parts[1].lower()
            val = parts[2]

            encoded_val = b''

            if dtype == 'ip':
                encoded_val = socket.inet_aton(val)
            elif dtype == 'ips':
                # Comma-separated list of IPs
                for ip in val.split(','):
                    encoded_val += socket.inet_aton(ip.strip())
            elif dtype == 'str':
                encoded_val = val.encode('utf-8')
            elif dtype == 'int8':
                encoded_val = struct.pack('!B', int(val))
            elif dtype == 'int16':
                encoded_val = struct.pack('!H', int(val))
            elif dtype == 'int32':
                encoded_val = struct.pack('!I', int(val))
            elif dtype == 'hex':
                # Allows raw payload construction (useful for Option 43)
                encoded_val = bytes.fromhex(val.replace(':', ''). \
                                            replace(' ', ''))
            else:
                raise ValueError(f'Unknown type "{dtype}"')

            parsed.append((code, encoded_val))
        except Exception as e:
            logger.critical(f'⛔ Invalid custom option "{opt}": {e}')
            sys.exit(1)
    return parsed

# ----- Client mode (same binary, --status/--verify/--dump/--show/--config) ---

def diag_query(payload, socket_path):
    '''Send one request to the daemon's socket; return (response, error).'''
    if not os.path.exists(socket_path):
        return None, f'daemon not running (no socket at {socket_path})'
    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.settimeout(15.0)
        c.connect(socket_path)
    except (ConnectionRefusedError, FileNotFoundError):
        return None, (f'daemon not running (stale socket at {socket_path})')
    except Exception as e:
        return None, str(e)
    try:
        c.sendall((json.dumps(payload) + '\n').encode('utf-8'))
        buf = b''
        while b'\n' not in buf:
            chunk = c.recv(65536)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return None, 'empty response from daemon'
        return json.loads(buf.decode('utf-8')), None
    except Exception as e:
        return None, str(e)
    finally:
        c.close()

def _fmt_epoch(e):
    if e is None:
        return '-'
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e))

_MAC_RE = re.compile(r'\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b')

def _redact_mac(mac):
    parts = mac.split(':')
    return ':'.join(parts[:3] + ['xx', 'xx', 'xx']) if len(parts) == 6 else mac

def _redact_obj(o):
    if isinstance(o, dict):
        r = {}
        for k, v in o.items():
            if k == 'hostname':
                r[k] = None
            elif k == 'mac' and isinstance(v, str):
                r[k] = _redact_mac(v)
            elif k in ('compat_macs', 'playground_macs',
                       'masquerade_macs') and isinstance(v, list):
                r[k] = [_redact_mac(x) for x in v]
            elif isinstance(v, str):
                # Scrub any MAC embedded in free-text (e.g. verify 'detail').
                r[k] = _MAC_RE.sub(lambda mm: _redact_mac(mm.group(0)), v)
            else:
                r[k] = _redact_obj(v)
        return r
    if isinstance(o, list):
        return [_redact_obj(x) for x in o]
    return o

def _diag_exit_code(cmd, resp):
    '''Nagios-style: 0 ok, 1 warning, 2 critical, 3 unknown.'''
    if cmd != 'verify':
        return 0
    s = resp.get('summary', {})
    if s.get('alarming', 0) > 0:
        return 2
    if s.get('moderate', 0) > 0:
        return 1
    if s.get('unknown', 0) > 0:
        return 3
    return 0

def render_status(r, args):
    print(f"✅ isodhcp {r['version']} on \"{r['iface']}\" "
          f"(pid {r['pid']}, up {r['uptime_seconds']}s)")
    print(f"   Server {r['server_ip']}  Pool {r['pool_cidr']}  "
          f"Isolation: {r['isolation_mode']}")
    p = r['pool']
    print(f"   Pool: {p['leased']}/{p['total']} leased "
          f"({p['utilization_pct']}%), {p['free']} free, "
          f"{p['free_slash30_blocks']} free /30 blocks, "
          f"{p['quarantined']} quarantined")
    c = r['clients']
    print(f"   Clients: {c['standard']} standard, {c['compat']} compat, "
          f"{c['playground']} playground")
    q = r['quarantine']
    print(f"   Quarantine: {q['count']}/{q['cap']}"
          f"{'  ⚠️ AT CAP' if q['at_cap'] else ''}")
    rl = r['ratelimit']
    print(f"   Rate limiter: {rl['tracked']}/{rl['max']} MACs"
          f"{'  ⚠️ SATURATED' if rl['saturated'] else ''}")
    if r.get('playground'):
        pg = r['playground']
        print(f"   Playground: {pg['subnet']} gw {pg['gateway']} — "
              f"{pg['used']} used, {pg['free']} free")
    print(f"   Socket: {r['socket']}")

def render_config(r, args):
    print(f"isodhcp {r['version']} configuration ({r['iface']}):")
    for k in ('server_ip', 'pool_cidr', 'dns_server', 'lease_time',
              'isolation_mode', 'lease_file', 'socket', 'private_table',
              'static_count'):
        print(f"  {k:<15} {r.get(k)}")
    if r.get('playground'):
        print(f"  {'playground':<15} {r['playground']['subnet']} "
              f"(gw {r['playground']['gateway']})")
    sets = {k: v for k, v in r['nft_sets'].items() if v}
    if sets:
        print("  nft sets:")
        for k, v in sets.items():
            print(f"    {k:<18} {v}")
    cls = {k: v for k, v in r['classifier'].items() if v}
    if cls:
        print("  classifier rules:")
        for k, v in cls.items():
            print(f"    {k:<20} {', '.join(v)}")

def render_dump(r, args):
    secs = r.get('sections', {})
    if 'leases' in secs:
        rows = secs['leases']
        print(f"LEASES ({len(rows)}):")
        print(f"  {'MAC':<18} {'IP':<15} {'MODE':<10} {'MASQ':<4} "
              f"{'EXPIRES':<20} HOSTNAME")
        for x in rows:
            exp = 'static' if x['static'] else _fmt_epoch(x['expires_epoch'])
            print(f"  {x['mac']:<18} {str(x['ip']):<15} {x['mode']:<10} "
                  f"{'yes' if x['masq'] else 'no':<4} {exp:<20} "
                  f"{x.get('hostname') or ''}")
    if 'subnets' in secs:
        rows = secs['subnets']
        print(f"\nCOMPAT /30 SUBNETS ({len(rows)}):")
        for x in rows:
            print(f"  {x['mac']:<18} gw {x['gateway']:<15} {x['subnet']}")
    if 'quarantine' in secs:
        rows = secs['quarantine']
        print(f"\nQUARANTINE ({len(rows)}):")
        for x in rows:
            print(f"  {x['ip']:<15} releases in {x['release_in']}s")
    if 'ratelimit' in secs:
        rl = secs['ratelimit']
        print(f"\nRATE LIMITER: {rl['tracked']}/{rl['max']} tracked, "
              f"saturated={rl['saturated']}")
    if 'pool' in secs:
        p = secs['pool']
        print(f"\nPOOL: {p['free_count']} free of {p['total']} "
              f"({p['free_slash30_blocks']} free /30 blocks). Free ranges "
              f"(gaps are in use/reserved):")
        for r in p['free_ranges']:
            print(f"  {r}")
    if 'config' in secs:
        print()
        render_config(secs['config'], args)
    if 'firewall' in secs:
        print()
        render_firewall(secs['firewall'], args)

_RTYPE = {1: 'unicast', 2: 'local', 3: 'broadcast', 4: 'anycast',
          5: 'multicast', 6: 'blackhole'}

def render_firewall(f, args):
    print(f"ACTUAL FIREWALL/KERNEL STATE (ground truth) for {f['iface']}:")
    print(f"  private table: {f['private_table']}")
    hr = f['host_routes_32']
    print(f"  /32 host routes (main table, unicast): {len(hr)}")
    if hr:
        print('    ' + ', '.join(hr))
    print("  all IPv4 routes on interface (raw):")
    for r in f['routes_raw']:
        dst = r['dst'] if r['dst_len'] is None else f"{r['dst']}/{r['dst_len']}"
        print(f"    {dst:<22} table={r['table']:<4} "
              f"type={_RTYPE.get(r['type'], r['type'])} proto={r['proto']}")
    print("  interface IPv4 addresses:")
    for ip, pfx in f['interface_aliases'].items():
        print(f"    {ip}/{pfx}")
    print("  SNAT rules (private table):")
    snat = f['snat_rules']
    if isinstance(snat, str):
        print(f"    {snat}")
    elif not snat:
        print("    (none)")
    else:
        for daddr, targets in sorted(snat.items()):
            print(f"    daddr {daddr:<16} -> snat {', '.join(targets)}")
    print("  configured nft sets (actual elements):")
    if not f['nft_sets']:
        print("    (none configured)")
    for label, s in f['nft_sets'].items():
        if s.get('error'):
            print(f"    {label:<18} {s['spec']}: ERROR {s['error']}")
        else:
            els = ', '.join(s['elements']) if s['elements'] else '(empty)'
            print(f"    {label:<18} {s['spec']}: {els}")

def render_show(r, args):
    print(f"Client {r['mac']}  →  {r['ip']}")
    if r.get('hostname'):
        print(f"  hostname   {r['hostname']}")
    print(f"  mode       {r['mode']}")
    print(f"  masquerade {'yes' if r['masq'] else 'no'}")
    print(f"  lease      "
          f"{'static' if r['static'] else _fmt_epoch(r['expires_epoch'])}")
    if 'gateway' in r:
        print(f"  gateway    {r['gateway']}  subnet {r['subnet']}")
    print("  resources:")
    for c in r.get('checks', []):
        if c.get('error'):
            mark = f"? ({c['error']})"
        else:
            mark = '✅ present' if c['present'] else '❌ MISSING'
        print(f"    {c['resource']:<14} {c['detail']:<30} {mark}")

def render_verify(r, args):
    s = r['summary']
    order = {'alarming': 0, 'unknown': 1, 'moderate': 2, 'low': 3}
    icons = {'alarming': '🔴', 'unknown': '❓', 'moderate': '🟡', 'low': '⚪'}
    shown = [d for d in r['discrepancies']
             if getattr(args, 'all', False) or not d['transient']]
    shown.sort(key=lambda d: order.get(d['severity'], 9))
    if not shown:
        print(f"✅ No drift detected "
              f"({s['transient']} transient discrepancies ignored).")
    else:
        for d in shown:
            t = ' [transient]' if d['transient'] else ''
            print(f"  {icons.get(d['severity'], '•')} "
                  f"{d['severity'].upper():<9} {d['resource']}/{d['kind']}: "
                  f"{d['detail']}{t}")
    print(f"\nRESULT: {s['alarming']} alarming, {s['moderate']} moderate, "
          f"{s['low']} low, {s['unknown']} unknown, {s['transient']} transient")
    if s['alarming'] or s['moderate']:
        print("Hint: 'systemctl reload isodhcp' (SIGUSR1) reconciles routes, "
              "aliases and set membership; then re-run --verify.")

def run_client(cmd, args):
    socket_path = resolve_socket_path(args.interface, explicit=args.socket)
    payload = {'cmd': cmd}
    if cmd == 'dump':
        secs = [s.strip() for s in (args.dump or '').split(',') if s.strip()]
        if secs:
            payload['sections'] = secs
    elif cmd == 'show':
        payload['key'] = args.show
    resp, err = diag_query(payload, socket_path)
    if err:
        if args.json:
            print(json.dumps({'status': 'error', 'running': False,
                              'message': err}))
        else:
            print(f'❌ {err}')
        return 3
    if resp.get('status') == 'error':
        if args.json:
            print(json.dumps(resp, indent=2))
        else:
            print(f"❌ {resp.get('message')}")
        return 3
    if args.redact:
        resp = _redact_obj(resp)
    if args.json:
        print(json.dumps(resp, indent=2))
    else:
        {'status': render_status, 'config': render_config, 'dump': render_dump,
         'show': render_show, 'verify': render_verify}[cmd](resp, args)
    return _diag_exit_code(cmd, resp)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Isolated DHCP Server for Point-To-Point Clients',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '-d', '--dns',
        help='DNS Server IP. If omitted, uses system /etc/resolv.conf.')
    parser.add_argument(
        '-f', '--lease-file',
        default=None,
        help=f'Path to JSON file. Defaults to "{LEASE_FILE}"')
    parser.add_argument(
        '-i', '--interface',
        default=INTERFACE,
        help='Network interface to bind to.')
    parser.add_argument(
        '-p', '--pool',
        help='IP Pool CIDR (e.g., 10.0.0.0/24). If omitted, ' \
             'auto-detected from interface.')
    parser.add_argument(
        '-s', '--server-ip',
        help='Static Server IP. If omitted, auto-detected from interface.')
    parser.add_argument(
        '-t', '--lease-time', type=int, default=LEASE_TIME,
        help='DHCP Lease time in seconds.')
    parser.add_argument(
        '--playground-size', type=int, default=0, help='Size of shared pool. '
        'Behaves like a traditional DHCP server without layer 3 isolation.')
    parser.add_argument(
        '--playground-mac', action='append',
        help='Treat this MAC as part of the playground. Can be repeated.')
    parser.add_argument(
        '--playground-oui', action='append', help='Treat this MAC prefix (e.g. '
        '"00:11:22") as part of the playground. Can be repeated.')
    parser.add_argument(
        '--playground-vendor', action='append', help='Treat clients with this '
        'Vendor ID string (option 60) as part of the playground. An empty '
        'argument is treated as a wild-card matching every client. Can be '
        'repeated.')
    parser.add_argument(
        '--compat-mac', action='append', help='Treat this MAC as legacy (send '
        'wide /30 netmask). Can be repeated.')
    parser.add_argument(
        '--compat-oui', action='append', help='Treat this MAC prefix (e.g. '
        '"00:11:22") as legacy. Can be repeated.')
    parser.add_argument(
        '--compat-vendor', action='append', help='Treat clients with this '
        'Vendor ID string (option 60) as legacy. e.g. "MSFT 5.0". An empty '
        'argument is treated as a wild-card matching every client. Can be '
        'repeated.')
    parser.add_argument(
        '--masquerade-mac', action='append', help='Masquerade incoming traffic '
        'to originate from gateway IP. Can be repeated.')
    parser.add_argument(
        '--masquerade-oui', action='append', help='Treat this MAC prefix (e.g. '
        '"00:11:22") as masqueraded. Can be repeated.')
    parser.add_argument(
        '--masquerade-vendor', action='append', help='Treat clients with this '
        'Vendor ID string (option 60) as masqueraded. e.g. "MSFT 5.0". An '
        'empty argument is treated as a wild-card matching every client. Can '
        'be repeated.')
    parser.add_argument(
        '--static', action='append', help='Map a MAC to an IP. Format: '
        '--static aa:bb:cc:dd:ee:ff=10.100.0.50{,hostname}{,compat}'
        '{,masquerade}{,playground}')
    parser.add_argument('--nft-set-isolated',
                        help='NFTables set for isolated clients')
    parser.add_argument('--nft-set-compat',
                        help='NFTables set for legacy clients in '
                        'compatibility mode')
    parser.add_argument('--nft-set-playground',
                        help='NFTables set for playground clients')
    parser.add_argument('--nft-set-playground-subnet',
                        help='NFTables set for the playground subnet CIDR')
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
    parser.add_argument(
        '--dhcp-option', action='append', help='Add custom DHCP option. '
        'Format: CODE,TYPE,VALUE. Types: ip, ips, str, int8, int16, int32, '
        'hex. Example: --dhcp-option "42,ip,192.168.1.1"')

    diag = parser.add_argument_group(
        'Diagnostics (client mode: query a running daemon and exit)')
    diag.add_argument('--status', action='store_true',
                      help='Print a health summary of the running daemon.')
    diag.add_argument('--verify', '--check', dest='verify',
                      action='store_true',
                      help='Cross-check the daemon\'s in-memory state against '
                      'the live kernel routes, interface aliases and nftables '
                      'sets/SNAT rules it manages, and report any drift. Exit '
                      'code: 0 clean, 1 warning, 2 critical, 3 unknown.')
    diag.add_argument('--dump', nargs='?', const='', metavar='SECTIONS',
                      help='Dump state tables. Optional comma-separated list: '
                      'leases,subnets,quarantine,ratelimit,pool,config '
                      '(default: leases,subnets).')
    diag.add_argument('--show', metavar='MAC|IP|HOSTNAME',
                      help='Show one client and whether each resource it '
                      'should own (route/alias/set/SNAT) is actually present.')
    diag.add_argument('--config', dest='show_config', action='store_true',
                      help='Print the effective running configuration.')
    diag.add_argument('--json', action='store_true',
                      help='Emit diagnostic output as JSON.')
    diag.add_argument('--redact', action='store_true',
                      help='Mask MAC addresses and hostnames in diagnostic '
                      'output.')
    diag.add_argument('--all', action='store_true',
                      help='With --verify, also list transient discrepancies.')
    diag.add_argument('--socket',
                      help='Path to the diagnostics Unix socket (default: '
                      'auto-detected in the state directory).')

    args = parser.parse_args()

    # Client mode: if a diagnostic action was requested, talk to the running
    # daemon over its socket and exit. This is the same binary in a different
    # role, so no privileges or interface access are needed here.
    client_cmd = None
    if args.status:
        client_cmd = 'status'
    elif args.verify:
        client_cmd = 'verify'
    elif args.dump is not None:
        client_cmd = 'dump'
    elif args.show:
        client_cmd = 'show'
    elif args.show_config:
        client_cmd = 'config'
    if client_cmd:
        sys.exit(run_client(client_cmd, args))

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
        logger.info(f'⚠️ Received signal: {sig_name}')
        sys.exit(0)
    def handle_reload(signum, frame):
        '''Handles systemctl reload (SIGUSR1)'''
        if server: server.reload()
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    signal.signal(signal.SIGHUP, graceful_exit)
    signal.signal(signal.SIGUSR1, handle_reload)

    def clean_set(items):
        if not items: return set()
        return set(str(i).strip().lower() for i in items)

    # Normalize command line list
    pg_macs = clean_set(args.playground_mac)
    pg_ouis = clean_set(args.playground_oui)
    pg_vendors = clean_set(args.playground_vendor)

    compat_macs = clean_set(args.compat_mac)
    compat_ouis = clean_set(args.compat_oui)
    compat_vendors = clean_set(args.compat_vendor)

    masq_macs = clean_set(args.masquerade_mac)
    masq_ouis = clean_set(args.masquerade_oui)
    masq_vendors = clean_set(args.masquerade_vendor)

    static_map = {}
    if args.static:
        for item in args.static:
            try:
                parts = item.split('=')
                if len(parts) != 2:
                    raise ValueError('Format must be MAC=IP{,hostname}'
                                     '{,compat}{,masquerade}{,playground}')
                mac = parts[0].strip().lower()
                val = parts[1].strip().split(',')
                ip = val[0].strip().lower()
                hostname = None
                for flag in val[1:]:
                    f = flag.strip().lower()
                    if f == 'playground': pg_macs.add(mac)
                    elif f == 'compat': compat_macs.add(mac)
                    elif f == 'masquerade': masq_macs.add(mac)
                    elif f and not hostname: hostname = f
                    else: raise ValueError('Format must be MAC=IP{,hostname}'
                                           '{,compat}{,masquerade}')

                # Basic validation
                if not re.match(r'[0-9a-f]{2}([:][0-9a-f]{2}){5}$', mac):
                    raise ValueError(f'⚠️ Invalid MAC in static map: {mac}')
                ipaddress.IPv4Address(ip) # Check if valid IP
                if (mac in pg_macs) and (mac in compat_macs):
                    raise ValueError(f'MAC {mac} cannot be both "compat" and '
                                     f'"playground".')
                static_map[mac] = (ip, hostname)
            except Exception as e:
                logger.critical(f'⚠️ Failed to parse static map "{item}": {e}')
                sys.exit(1)

    # Validate playground size
    if args.playground_size > 0:
        if args.playground_size <= 5:
             logger.critical(f'⚠️ Playground size must be > 5 for a minimum '
                             f'allocation of 8 IPs.')
             sys.exit(1)

    # Parse custom DHCP options
    custom_options = parse_custom_options(args.dhcp_option)

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
            playground_size=args.playground_size,
            pg_macs=pg_macs,
            pg_ouis=pg_ouis,
            pg_vendors=pg_vendors,
            compat_macs=compat_macs,
            compat_ouis=compat_ouis,
            compat_vendors=compat_vendors,
            masq_macs=masq_macs,
            masq_ouis=masq_ouis,
            masq_vendors=masq_vendors,
            nft_iso=args.nft_set_isolated,
            nft_compat=args.nft_set_compat,
            nft_set_playground=args.nft_set_playground,
            nft_set_playground_subnet=args.nft_set_playground_subnet,
            nft_gw=args.nft_set_gateway,
            nft_net=args.nft_set_network,
            nft_bcast=args.nft_set_broadcast,
            nft_subnet=args.nft_set_subnet,
            hook_file=args.hook_file,
            isolation_mode=args.isolation,
            custom_options=custom_options,
            socket_path=args.socket
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
