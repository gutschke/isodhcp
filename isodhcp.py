import argparse
import heapq
import ipaddress
import json
import logging
import os
import random
import re
import select
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

MAC_RE = re.compile(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}$')

def unicast_mac(m):
    '''True if `m` is a canonical MAC string naming one station: not a
    group (broadcast or multicast) address, and not all zeroes.'''
    return isinstance(m, str) and bool(MAC_RE.fullmatch(m)) and \
        not int(m[:2], 16) & 1 and m != '00:00:00:00:00:00'

def _finite_time(v):
    '''`v` if it is a plausible epoch timestamp from our own lease file,
    else None. JSON accepts NaN and Infinity, and bool is an int.'''
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if not 0 <= v <= time.time() + 86400:
        return None
    return float(v)

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
        self._limit_logged = 0.0    # throttles the "rate limiting" line...
        self._limit_unlogged = 0    # ...counting what it did not say

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
            # Dropping is otherwise silent, which makes a client we dropped
            # look exactly like one that never asked. Say so once per episode.
            # The episode only ends when the bucket has refilled completely,
            # i.e. the client went quiet; re-arming on the next single token
            # would log at the refill rate for as long as a flood lasts.
            if client['tokens'] >= self.burst:
                client.pop('limited', None)
            if client['tokens'] >= 1.0:
                client['tokens'] -= 1.0
                return True
            else:
                if not client.get('limited'):
                    client['limited'] = True
                    # Per MAC, but at most one line a second overall, so a
                    # flood of fresh MACs cannot turn into a flood of log.
                    if now - self._limit_logged >= 1.0:
                        more = (f' ({self._limit_unlogged} more MACs limited '
                                f'since the last report)'
                                if self._limit_unlogged else '')
                        logger.warning(f'⚠️ Rate limiting {mac}: dropping its '
                                       f'DHCP packets until it slows down.'
                                       f'{more}')
                        self._limit_logged = now
                        self._limit_unlogged = 0
                    else:
                        self._limit_unlogged += 1
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
        # When each address last went back to a pool (epoch seconds), so that
        # allocation does not hand a just-freed address straight back out; see
        # _pick_dynamic. Never-used addresses count as freed at time zero.
        # Persisted, because a restart is exactly when a whole set of leases
        # tends to have lapsed together.
        self.last_freed = {}
        # Who last held each freed address, and whether its lease ran out
        # rather than being released. A device that carries on using an
        # expired lease is the usual silent squatter, and if it does come back
        # through DHCP it should get the same address again (RFC 2131 4.3.1).
        self.former = {}  # ip -> {'mac': str, 'expired': bool, 'block': cidr}
        # Unleased addresses the ARP sweep heard a device answer for: ip ->
        # (mac, when). Allocation avoids them while the answer is recent; see
        # _busy. In memory only, and empty without a sweep: everything that
        # goes wrong with it lets the entries age out, which leaves
        # allocation as it would be without one.
        self.heard = {}
        self.heard_for = 0      # how long an answer counts; set by the sweep
        self._skip_logged = set()
        self._override_logged = {}
        self._crowd = []
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

        # Startup has just reconciled the lease table against the
        # configuration, but nothing above persists the result: load_leases
        # writes before the static labels are applied, and neither
        # reserve_static_ips nor enforce_static_bindings writes at all. The
        # file, not this process's memory, is what downstream consumers read.
        # So an operator who renames a host and restarts would see the daemon
        # report the new name while the file still served the old one, until
        # some unrelated dynamic client happened to trigger a write -- which on
        # an all-static network never comes. One write here keeps the file and
        # the running state in agreement from the first moment.
        self.save_leases()

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

            # A lease reloaded from disk may still sit on an address this MAC
            # has since been re-pointed away from. Committing the reservation
            # on top of it silently strands the old one: it stays indexed to
            # this MAC, stays out of the free pool, and keeps whatever /30 it
            # came with -- for good, because enforce_static_bindings() only
            # purges a lease whose address disagrees with the reservation, and
            # by then this one agrees. Let go of the old address first; the
            # reservation is rebuilt from the operator's configuration below.
            old = self.leases.get(mac)
            if old and old['ip'] != ip:
                logger.info(f'♻️ Releasing {old["ip"]} held by {mac} before '
                            f'reserving {ip}')
                self.release(mac)

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
                        h = f'"{hostname}" ' if hostname else ''
                        logger.warning(f'⚠️ Evicting dynamic lease {x} '
                                       f'({conflict_mac}) to make room for '
                                       f'static /30 of {h}{mac}')
                        self.release(conflict_mac)
                    if x in self.free_ips: self.free_ips.remove(x)
                self.subnet_leases[mac] = {'gateway': gw, 'subnet': subnet_cidr}
            else:
                # Standard mode /32
                if ip in self.ip_to_mac and self.ip_to_mac[ip] != mac:
                    conflict_mac = self.ip_to_mac[ip]
                    h = f'"{hostname}" ' if hostname else ''
                    logger.warning(f'⚠️ Evicting dynamic lease {ip} '
                                   f'({conflict_mac}) to make room for '
                                   f'static {h}{mac}')
                    self.release(conflict_mac)
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

        # Initialize playground free pool. Iterate the whole block, not just
        # its hosts: the network and broadcast addresses are ordinary members
        # of the surrounding pool and would otherwise be left behind in it,
        # allocatable to an isolated client who would then be sitting inside
        # the permissive playground CIDR. They belong to neither pool.
        for ip_obj in found:
            s_ip = str(ip_obj)
            if s_ip == self.playground_gateway or \
               ip_obj == found.network_address or \
               ip_obj == found.broadcast_address:
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

    def return_to_pool(self, ip):
        '''Hands an address back to the pool it was drawn from.

        The playground is carved out of free_ips at startup and kept apart
        ever since, so the two pools stay disjoint only for as long as every
        release puts an address back where it came from. A playground address
        dropped into the main pool shrinks the playground by one and then gets
        offered to an isolated client -- and the forward chain accepts
        client-to-client traffic on both sides of the playground CIDR, so that
        client is silently un-isolated. Infrastructure addresses (the
        playground's own gateway, network and broadcast) belong to no pool and
        are simply not handed back.'''
        addr = ipaddress.IPv4Address(ip)
        # Never hand out what the server uses itself, whichever path brought
        # the address here: its own address, the pool's network and
        # broadcast, or any address of a live /30 block.
        if ip not in self.all_possible_ips or any(
                addr in ipaddress.IPv4Network(d['subnet'])
                for d in self.subnet_leases.values()):
            return
        self.last_freed[ip] = time.time()
        if self.playground_subnet and addr in self.playground_subnet:
            if ip != self.playground_gateway and \
               addr != self.playground_subnet.network_address and \
               addr != self.playground_subnet.broadcast_address:
                self.playground_free_ips.add(ip)
        else:
            self.free_ips.add(ip)

    # How many of the highest free addresses allocation chooses among. See
    # _pick_dynamic.
    REUSE_WINDOW = 4

    def _window_order(self, pool, n, avoid=()):
        '''The first `n` addresses _pick_dynamic would hand out from `pool`,
        in order, if nothing else changed in between, leaving out `avoid`.'''
        taken = set()

        def opens_block(ip):
            # Would taking ip break up an aligned /30 that is still whole?
            base = int(ipaddress.IPv4Address(ip)) & ~3
            return all(str(ipaddress.IPv4Address(base + i)) in pool and
                       str(ipaddress.IPv4Address(base + i)) not in taken
                       for i in range(4))

        key = lambda ip: (opens_block(ip), self.last_freed.get(ip, 0.0),
                          -int(ipaddress.IPv4Address(ip)))
        top = heapq.nlargest(n + self.REUSE_WINDOW - 1,
                             (ip for ip in pool if ip not in avoid),
                             key=ipaddress.IPv4Address)
        out = []
        while top and len(out) < n:
            pick = min(top[:self.REUSE_WINDOW], key=key)
            top.remove(pick)
            taken.add(pick)
            out.append(pick)
        return out

    def _pick_dynamic(self, pool):
        '''The address to hand out next from `pool`, or None.

        Highest first, because that keeps the pool compact: /32 clients fill
        it from the top while aligned /30 blocks are taken from the bottom,
        and every address that leaves a hole in between can break up a block
        a compat client, or a larger mini-subnet, will need later. On a /24
        that is not a theoretical concern.

        Strictly highest-first has one bad habit, though: whatever was
        released last is offered again first. That is precisely wrong for a
        device that never renews and simply keeps using its old address after
        the lease has lapsed -- its address is the next one given to somebody
        else, and the two then both answer for it. So the choice is made
        among the REUSE_WINDOW highest free addresses, taking the one that has
        been free the longest (never used counts as longest) -- but never one
        that would break up a /30 block that is still whole, if another in the
        window would not. A just-freed address is thus not handed out while an
        address free for longer is in the window -- which on a full pool may
        be only a few allocations. The window is kept small so that
        allocation stays close to strict highest-first.

        Addresses the ARP sweep has recently heard a device answer for are
        skipped, at most SKIP_MAX of them, and only while something else is
        left; see _busy.'''
        pick, busy, avoid = self._next_dynamic(pool)
        if pick is None:
            return None
        # Said once per address and device, for as long as it answers.
        self._skip_logged = {k for k in self._skip_logged
                             if busy.get(k[0]) == k[1]}
        a = ipaddress.IPv4Address(pick)
        for ip in avoid:
            if ipaddress.IPv4Address(ip) > a and \
               (ip, busy[ip]) not in self._skip_logged:
                self._skip_logged.add((ip, busy[ip]))
                logger.warning(f'⚠️ Not offering {ip}: {busy[ip]} answered '
                               f'ARP for it {self._heard_ago(ip)}.')
        if pick in busy:
            self._override('pick', f'Handing out {pick} although '
                           f'{busy[pick]} answered ARP for it '
                           f'{self._heard_ago(pick)}: nothing else was left '
                           f'to skip to.')
        if self._crowd:
            self._override('crowd', f'Not avoiding the addresses '
                           f'{", ".join(self._crowd)} answer ARP for: no '
                           f'device answers for that many without being a '
                           f'proxy-ARP host or forging replies.')
        return pick

    def _next_dynamic(self, pool, fallback=True):
        '''What _pick_dynamic would hand out, without saying anything:
        (address or None, busy, avoided). Without `fallback`, never a busy
        address.'''
        busy = self._busy()
        avoid = self._avoid(pool, busy)
        if not fallback:
            avoid = {ip for ip in busy if ip in pool}
        order = self._window_order(pool, 1, avoid) or \
            (self._window_order(pool, 1) if fallback else [])
        return (order[0] if order else None), busy, avoid

    # Busy addresses allocation skips per pick, and how many busy addresses
    # one MAC may account for before it looks like proxy ARP or forgery and
    # is not believed at all.
    SKIP_MAX = 8
    HEARD_PER_MAC = 2
    HEARD_MAX = 64

    def note_heard(self, ip, mac, when):
        '''The sweep heard `mac` answer ARP for the unleased address `ip`.
        A MAC already answering for more than it is believed for gets no
        more room: a proxy must not push real answers out. Caller holds
        the lock.'''
        self.heard = {i: (m, t) for i, (m, t) in self.heard.items()
                      if 0 <= when - t < self.heard_for and i != ip}
        if sum(m == mac for m, _ in self.heard.values()) > \
           self.HEARD_PER_MAC:
            return
        self.heard[ip] = (mac, when)
        while len(self.heard) > self.HEARD_MAX:
            del self.heard[min(self.heard, key=lambda x: self.heard[x][1])]

    def _busy(self):
        '''ip -> MAC for every address a device answered for within
        heard_for, unless that MAC answers for more than HEARD_PER_MAC of
        them. An answer is never cleared by silence, which on a wireless
        segment proves little; it only ages out. Caller holds the lock.'''
        now = time.time()
        # An answer dated in the future (the clock was set back) is not
        # believed either.
        live = {ip: m for ip, (m, t) in self.heard.items()
                if 0 <= now - t < self.heard_for and ip not in self.ip_to_mac}
        per = {}
        for m in live.values():
            per[m] = per.get(m, 0) + 1
        self._crowd = sorted(m for m, n in per.items()
                             if n > self.HEARD_PER_MAC)[:4]
        return {ip: m for ip, m in live.items() if per[m] <= self.HEARD_PER_MAC}

    def _avoid(self, pool, busy):
        '''The busy addresses of `pool` allocation skips: the SKIP_MAX it
        would reach first.'''
        return set(heapq.nlargest(self.SKIP_MAX,
                                  (ip for ip in busy if ip in pool),
                                  key=ipaddress.IPv4Address))

    def _heard_ago(self, ip):
        return f'{(time.time() - self.heard[ip][1]) / 60:.0f} min ago'

    def _override(self, kind, msg):
        '''Allocation is ignoring what the sweep heard: say so, at most once
        per heard_for and kind.'''
        now = time.time()
        if not 0 <= now - self._override_logged.get(kind, -1e18) < \
           max(self.heard_for, 60):
            self._override_logged[kind] = now
            logger.error(f'🚨 {msg} Possible ARP spoofing; see --verify.')

    def _former_address(self, mac, pool):
        '''The address `mac` held most recently, if it is still in `pool`.'''
        best = None
        for ip, f in self.former.items():
            if f['mac'] != mac or f.get('block') or ip not in pool: continue
            if best is None or self.last_freed.get(ip, 0.0) > \
                    self.last_freed.get(best, 0.0):
                best = ip
        return best

    def _take_former(self, mac, pool):
        '''Give a returning client the address it held last, if nobody else
        has it (RFC 2131 4.3.1), and take it out of `pool`. Caller holds the
        lock.'''
        ip = self._former_address(mac, pool)
        if not ip or self._busy().get(ip, mac) != mac: return None
        pool.discard(ip)
        logger.info(f'♻️ Returning {ip} to its former holder {mac}.')
        return ip

    def _take_former_block(self, mac):
        '''The compat equivalent of _take_former: the /30 block `mac` held
        last, if every address of it is still free. Returns (client, gateway,
        subnet) and claims the block, or None.'''
        for ip, f in sorted(self.former.items(),
                            key=lambda kv: -self.last_freed.get(kv[0], 0.0)):
            if f['mac'] != mac or not f.get('block'): continue
            block = [str(x) for x in ipaddress.IPv4Network(f['block'])]
            busy = self._busy()
            if not all(x in self.free_ips and busy.get(x, mac) == mac
                       for x in block):
                continue
            for x in block:
                self.free_ips.discard(x)
            logger.info(f'♻️ Returning {f["block"]} to its former holder '
                        f'{mac}.')
            return block[2], block[1], f['block']
        return None

    def next_candidates(self, k):
        '''The addresses dynamic allocation will hand out next, in order: up
        to `k` standard ones, up to `k` playground ones, and, unless `k` is
        0, every address of the /30 block a new compat client would get.
        Caller holds the lock.'''
        busy = self._busy()
        out = []
        for pool in (self.free_ips, self.playground_free_ips):
            avoid = self._avoid(pool, busy)
            out += self._window_order(pool, k, avoid) or \
                self._window_order(pool, k)
        block = self.find_free_slash_30(avoid_busy=True, quiet=True) \
            if k else None
        if block:
            out += [str(x) for x in block]
        return out

    def find_free_slash_30(self, avoid_busy=False, quiet=False):
        '''
        Scans the pool for a block of 4 IPs (net, gateway, client, broadcast)
        Must be aligned to /30 boundaries (last octet 0, 4, 8, 12...)
        With `avoid_busy`, skips up to SKIP_MAX blocks the ARP sweep heard a
        device answer for; see _busy. `quiet` is for looking, not handing
        out: nothing is logged.
        '''
        busy = self._busy() if avoid_busy else {}
        say = (lambda msg: None) if quiet else \
            (lambda msg: self._override('block', msg))
        skipped = []
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
                    hit = [x for x in ips_in_block if x in busy]
                    if hit and len(skipped) < self.SKIP_MAX:
                        skipped.append((candidate_net, hit[0]))
                        continue
                    if hit:
                        say(f'Handing out {candidate_net} although '
                                       f'{busy[hit[0]]} answered ARP for '
                                       f'{hit[0]} {self._heard_ago(hit[0])}: '
                                       f'{self.SKIP_MAX} blocks were skipped '
                                       f'already.')
                    return candidate_net
            except: continue
        if skipped:
            net, x = skipped[0]
            say(f'Handing out {net} although {busy[x]} answered '
                           f'ARP for {x} {self._heard_ago(x)}: no other /30 '
                           f'is free.')
            return net
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

                # A lease that lapsed while we were down went free when it
                # expired, not when we came back -- for a compat client, its
                # whole /30 did, and the block is what it should get back.
                if expires != float('inf') and expires <= now and \
                   ip in self.all_possible_ips:
                    block = self._saved_block(
                        saved_data.get('subnets', {}).get(mac), ip)
                    for x in block or [ip]:
                        self.last_freed[x] = max(self.last_freed.get(x, 0.0),
                                                 expires)
                    self.former[ip] = {'mac': mac, 'expired': True}
                    if block:
                        self.former[ip]['block'] = f'{block[0]}/30'

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

            for ip, r in saved_data.get('released', {}).items():
                if ip not in self.all_possible_ips or \
                   not isinstance(r, dict): continue
                ts = _finite_time(r.get('at'))
                if ts is None: continue
                self.last_freed[ip] = max(self.last_freed.get(ip, 0.0), ts)
                if unicast_mac(r.get('mac')) and ip not in self.former:
                    self.former[ip] = {'mac': r['mac'],
                                       'expired': bool(r.get('expired'))}
                    if r.get('block'):
                        block = self._saved_block({'subnet': r['block']}, ip)
                        if block:
                            self.former[ip]['block'] = f'{block[0]}/30'
        except Exception as e:
            logger.error(f'⚠️ Failed to load lease file: {e}')

    def _saved_block(self, sub, ip):
        '''The addresses of the /30 that `sub` (a saved subnet record) names,
        if it is one inside the pool with `ip` as its client address; else
        None. The file is ours, but a damaged one must not turn into a block
        of any size.'''
        try:
            net = ipaddress.IPv4Network(sub['subnet'])
        except Exception:
            return None
        if net.prefixlen != 30 or not net.subnet_of(self.network):
            return None
        block = [str(x) for x in net]
        return block if block[2] == ip else None

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
            out = {'leases': serializable_leases, 'subnets': self.subnet_leases,
                   'released': self._released_record()}
            tmp_file = self.lease_file + '.tmp'
            with open(tmp_file, 'w') as f: json.dump(out, f, indent=2)
            os.replace(tmp_file, self.lease_file)
        except Exception as e:
            logger.error(f'Failed to write lease file: {e}')

    # How much allocation history is worth keeping on disk.
    RELEASED_KEEP = 7 * 86400
    RELEASED_MAX = 1024

    def _released_record(self):
        '''Recent release history for the lease file: when each currently free
        address was freed, and by whom. Only
        the most recent RELEASED_MAX within RELEASED_KEEP are kept, so the
        file does not grow with the pool and is not rewritten in full on
        every lease change on a large one.'''
        cutoff = time.time() - self.RELEASED_KEEP
        recent = heapq.nlargest(
            self.RELEASED_MAX,
            ((ts, ip) for ip, ts in self.last_freed.items()
             if ts >= cutoff and ip not in self.ip_to_mac))
        out = {}
        for ts, ip in recent:
            r = {'at': round(ts, 1)}
            f = self.former.get(ip)
            if f:
                r['mac'] = f['mac']
                r['expired'] = f['expired']
                if f.get('block'):
                    r['block'] = f['block']
            out[ip] = r
        return out

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

    def release(self, mac, force=False, expired=False):
        with self.cv:
            if mac in self.leases:
                data = self.leases[mac]
                ip = data['ip']
                mode = self._effective_mode(mac, data)
                is_masq = data.get('masq', False)
                hostname = data.get('hostname', '')

                # A --static binding is operator intent, and it outlives any one
                # client's idea of its lease state. A device moved to a manually
                # configured address commonly announces the move with a
                # DHCPRELEASE, and taking that word as permission to dismantle
                # the reservation removes the /30 gateway alias the manual
                # configuration still routes through, drops the client's source
                # NAT, and -- worst -- returns the reserved addresses to the
                # pool for the next client that asks. Keep the reservation
                # exactly as reserve_static_ips() would rebuild it at startup,
                # and report that nothing was freed: the address is still spoken
                # for and its host route has to stay. Only a lease sitting on
                # the reserved address is protected; a static client parked
                # elsewhere is the conflict the startup reconciliation purges,
                # and still has to be torn down. `force` is for the one caller
                # that means it: a profile change, which reallocates from
                # scratch immediately afterwards.
                if not force and mac in self.static_map and \
                   ip == self.static_map[mac][0]:
                    if data['expires'] != float('inf'):
                        data['expires'] = float('inf')
                        self.save_leases()
                    logger.info(f'📌 Kept static reservation {ip} for {mac} '
                                f'across release')
                    return None

                # Check if it was a compat /30 lease
                block = None
                if mac in self.subnet_leases:
                    sub_data = self.subnet_leases.pop(mac, None)
                    block = sub_data['subnet']
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
                        self.return_to_pool(str(x))
                else:
                    # Standard /32 cleanup
                    if self.sys:
                        self.sys.update_client_nft('delete', ip, mode)
                    self.return_to_pool(ip)

                # Remove SRCNAT
                if is_masq and self.sys:
                    gw_ip = str(self.server_ip)
                    if mac in self.subnet_leases:
                        gw_ip = self.subnet_leases[mac]['gateway']
                    self.sys.update_snat('delete', ip, gw_ip)

                # Remember who held it, so that it gets the same address --
                # or the same /30 -- back if it asks again.
                self.former[ip] = {'mac': mac, 'expired': expired}
                if block:
                    self.former[ip]['block'] = block

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
            # Only a client's own lease, or an address that is free, can be
            # declined. Anything else is not the client's to decline, and some
            # of it -- a /30 gateway alias, the server's own address -- would
            # come back out of quarantine as an ordinary free address, to be
            # handed to whoever asks next, who would then answer ARP for
            # another client's gateway.
            if current_owner != mac and ip not in self.free_ips and \
               ip not in self.playground_free_ips:
                logger.warning(f'⚠️ Security: Ignored DECLINE for {ip} from '
                               f'{mac}, which neither holds it nor could have '
                               f'been offered it')
                return
            if current_owner == mac:
                self.release(mac)
                self.former.pop(ip, None)
            if self._quarantine(ip, time.time() + 600):
                self.free_ips.discard(ip)
                self.playground_free_ips.discard(ip)
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
                    self.return_to_pool(ip)
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

            # A --static label is the operator's choice, and it wins. The lease
            # record is rebuilt from scratch when the lease is committed below,
            # so a name that is not reapplied there is simply gone: a client
            # that sends its own option 12 silently renames the host, and one
            # that sends none at all erases the name outright. Both are wrong
            # for a host the operator has deliberately named, because the label
            # is what DNS goes on to publish. Overriding here rather than at the
            # commit keeps the log line, the lease record and the hook argument
            # all describing the same name. Dynamic clients are left alone --
            # for them option 12 is the only name there is.
            if mac in self.static_map and self.static_map[mac][1]:
                hostname = self.static_map[mac][1]

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
                    self.release(mac, force=True)
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
                        target_ip = self._take_former(
                            mac, self.playground_free_ips) or \
                            self._pick_dynamic(self.playground_free_ips)
                        if target_ip:
                            self.playground_free_ips.discard(target_ip)
                            nft_compat_flag = False
                        else:
                            logger.error(f'❌ Playground pool exhausted.')
                            return None
                    # Compat /30
                    elif mode == ClientClassifier.MODE_COMPAT:
                        former = self._take_former_block(mac)
                        subnet = None if former else \
                            self.find_free_slash_30(avoid_busy=True)
                        if former:
                            target_ip, gw, cidr = former
                            subnet_info = (gw, cidr)
                            nft_compat_flag = True
                        elif subnet:
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
                        target_ip = self._take_former(mac, self.free_ips)
                        if target_ip:
                            nft_compat_flag = False
                        elif self.free_ips:
                            for _ in range(5):
                                # Highest first, mostly; see _pick_dynamic.
                                candidate = self._pick_dynamic(self.free_ips)
                                if not candidate: break
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

            # Claim the address out of whichever pool it can still be drawn
            # from. The dynamic paths above take theirs out as they pick it,
            # but a static address is handed to us by the operator: it is out
            # of the main pool from startup and was never out of the playground
            # rotation at all, and a profile change releases the reservation
            # and reallocates it in the same breath, which returns it to the
            # pool and never takes it out again. A leased address left
            # allocatable is handed to a second client. Claiming it here covers
            # every path and costs nothing when it is already claimed.
            self.free_ips.discard(target_ip)
            self.playground_free_ips.discard(target_ip)
            if subnet_info:
                # In compat mode we need to store and create the /30 structure
                self.subnet_leases[mac] = {
                    'gateway': subnet_info[0],
                    'subnet': subnet_info[1]
                }

                # The whole block, not just the client address: the network,
                # gateway and broadcast addresses are infrastructure and must
                # never be allocatable either.
                try:
                    for x in ipaddress.IPv4Network(subnet_info[1]):
                        self.free_ips.discard(str(x))
                except: pass

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
                self.release(mac, expired=True)

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

BROADCAST = b'\xff' * 6

def parse_arp_reply(raw, our_mac):
    '''(sender IP, sender MAC) if `raw` is a well-formed IPv4-over-Ethernet
    ARP reply to `our_mac` (bytes) from a single station, else None.

    Parsed by hand at fixed offsets rather than through a dissector: every
    field is attacker-controlled, and a reply whose hardware address is not
    six bytes must not turn into something that is not a MAC string further
    down. Some stacks broadcast their replies (RFC 5227 allows it); those
    count only if addressed to us inside. A group sender address is
    refused, since it would later be used as a unicast destination.'''
    if len(raw) < 42 or raw[12:14] != b'\x08\x06':
        return None
    # htype 1 (Ethernet), ptype IPv4, hlen 6, plen 4, op 2 (reply)
    if raw[14:22] != b'\x00\x01\x08\x00\x06\x04\x00\x02':
        return None
    if raw[0:6] != our_mac and not (raw[0:6] == BROADCAST and
                                    raw[32:38] == our_mac):
        return None
    sha = raw[22:28]
    if sha[0] & 1 or sha == b'\x00' * 6:
        return None
    return socket.inet_ntoa(raw[28:32]), ':'.join(f'{b:02x}' for b in sha)

def arp_socket_io(iface, server_mac):
    '''Real I/O for ArpSweeper over one raw socket that only sees ARP
    replies that could be addressed to us.'''
    mac_bytes = bytes.fromhex(server_mac.replace(':', ''))
    sock = conf.L2socket(
        iface=iface, promisc=False,
        filter=f'arp and (ether dst {server_mac} or ether broadcast) and '
               f'arp[0:2] = 1 and arp[2:2] = 0x0800 and arp[4] = 6 and '
               f'arp[5] = 4 and arp[6:2] = 2')

    def send(ip, psrc, dst=None):
        sock.send(Ether(dst=dst or 'ff:ff:ff:ff:ff:ff', src=server_mac) /
                  ARP(op=1, hwsrc=server_mac, psrc=psrc, pdst=ip,
                      hwdst=dst or '00:00:00:00:00:00'))

    def recv(timeout):
        '''Replies within `timeout` seconds, and whether there were more
        than could be read: a window that overflowed proves nothing by
        silence.'''
        out = []
        deadline = time.time() + timeout
        while len(out) < ArpSweeper.MAX_REPLIES:
            left = deadline - time.time()
            if left <= 0: return out, False
            ready, _, _ = select.select([sock], [], [], left)
            if not ready: return out, False
            raw = sock.recv_raw()[1]
            r = parse_arp_reply(raw, mac_bytes) if raw else None
            if r: out.append(r)
        # The rest of a flood is left to the socket buffer, which drops it;
        # whatever is read later only counts if it answers the probe then
        # being made.
        left = deadline - time.time()
        if left > 0: time.sleep(left)
        return out, True

    return send, recv

def local_macs():
    '''Every MAC on this host.'''
    try:
        with IPRoute() as ipr:
            return {dict(l['attrs']).get('IFLA_ADDRESS', '').lower()
                    for l in ipr.get_links()} - {'', '00:00:00:00:00:00'}
    except Exception:
        return set()

def local_addrs():
    '''Every IPv4 address configured on this host.'''
    try:
        with IPRoute() as ipr:
            return {dict(a['attrs']).get('IFA_ADDRESS')
                    for a in ipr.get_addr(family=socket.AF_INET)} - {None}
    except Exception:
        return set()

NUD_REACHABLE, NUD_STALE, NUD_NOARP, NUD_PERMANENT = 0x02, 0x04, 0x40, 0x80

def _neighbour(ipr, iface_index, ip):
    '''The kernel's neighbour entry for `ip` on the interface, or None.'''
    for n in ipr.get_neighbours(dst=ip, family=socket.AF_INET,
                                ifindex=iface_index):
        if n['ifindex'] == iface_index:
            return n
    return None

def neigh_locktime(iface):
    '''The interface's neighbour lock time in seconds (the sysctl counts in
    hundredths), or the kernel default if it cannot be read.'''
    try:
        with open(f'/proc/sys/net/ipv4/neigh/{iface}/locktime') as f:
            return max(0, int(f.read())) / 100
    except (OSError, ValueError):
        return 1.0

def guard_neighbour(iface_index, ip, mac):
    '''Make the kernel's neighbour entry for `ip` name `mac`, as a change it
    has only just made, if it has an entry at all. Linux lets an ARP reply
    override an entry only once the entry has gone unchanged for its lock
    time (a second, by default), so for that long a reply from any other
    device is ignored; the sweep repeats this more often than that while it
    listens. Without it, a lessee whose entry is in use answers with no
    change to make, and whichever other device answers takes the entry, and
    the lessee's traffic, over. Toggling the state is what makes it a
    change. Without an entry there is nothing to protect: the kernel does
    not create one from a reply. An entry somebody pinned is left alone;
    replies do not move it anyway.'''
    try:
        with IPRoute() as ipr:
            n = _neighbour(ipr, iface_index, ip)
            if n is None or n['state'] & (NUD_NOARP | NUD_PERMANENT):
                return False
            state = NUD_REACHABLE if n['state'] == NUD_STALE else NUD_STALE
            ipr.neigh('replace', dst=ip, lladdr=mac, ifindex=iface_index,
                      state=state)
            return True
    except Exception as e:
        logger.error(f'⚠️ Could not refresh the neighbour entry for {ip}: {e}')
    return False

def restore_neighbour(iface_index, ip, mac):
    '''Point the kernel's neighbour entry for `ip` back at `mac`, if it now
    names anybody else. Left STALE, so the kernel confirms it by unicast
    before relying on it. No entry, or a pinned one, is left as it is.'''
    try:
        with IPRoute() as ipr:
            n = _neighbour(ipr, iface_index, ip)
            if n is None or n['state'] & (NUD_NOARP | NUD_PERMANENT) or \
               dict(n['attrs']).get('NDA_LLADDR', '').lower() == mac:
                return False
            ipr.neigh('replace', dst=ip, lladdr=mac, ifindex=iface_index,
                      state=NUD_STALE)
            return True
    except Exception as e:
        logger.error(f'⚠️ Could not restore the neighbour entry for {ip}: {e}')
        return False

class ArpSweeper:
    '''Finds addresses that something on the wire uses without a lease.

    DHCP only hears from clients that ask. A device that is configured
    statically, or that simply carries on using an address after its lease
    lapsed, never asks -- and it may send nothing at all for days, so there
    is nothing to overhear either. What it does do, even when otherwise
    idle, is answer ARP for its address. So the server asks, with a
    broadcast who-has (a second responder cannot be found with unicast), in
    this order:

      * whatever is quarantined, or has an open finding, and addresses whose
        lease ran out in the last few days -- the usual squatter;
      * the addresses allocation will hand out next;
      * every leased address, in rotation if they do not all fit;
      * and, on pools up to a /23 or when asked, the rest of the pool,
        trickled so that a full pass takes about REST_PERIOD when the budget
        leaves room for it.

    The first two classes get at most a quarter of each sweep apiece, so
    neither can starve the rest.

    Every probe is a broadcast, which a wireless segment sends over the air
    at the basic rate, waking power-saving clients, and that cost must not
    scale with whatever pool size somebody configures. So it is bounded by
    construction: at most max_per_sweep probes per sweep, never more than
    `rate` broadcasts per second, spread across the interval with jitter. A
    plan that does not fit is trimmed.

    The probes are careful about what they teach other hosts:

      * a request is sent from an address the server uses on the target's
        own subnet, as the kernel would, so that stacks which ignore
        off-subnet requesters still answer -- but never from the target
        itself, which would be a gratuitous announcement. The host's own
        addresses are probed from 0.0.0.0 (an RFC 5227 probe), which no
        cache learns from.
      * replies to a probe reach the kernel as well, so asking a contested
        leased address can move the kernel's neighbour entry to the other
        device, and with it the lessee's traffic. Nobody but the lessee is
        ever asked by unicast for a leased address; its entry is refreshed
        just before the probe and then every half lock time until the
        window closes, which makes the kernel ignore other replies, however
        late they come (guard_neighbour); and should one get through anyway,
        the entry is pointed back at the lessee as soon as the probe is
        over.

    Broadcasts are unacknowledged and easily lost on Wi-Fi, so a responder
    already known -- one with an open finding, or the former holder of a
    lease that ran out -- is also asked by unicast, which is acknowledged
    and retried.

    Detection is alert-only, but for one thing: allocation passes over a
    free address the sweep has recently heard answer (LeaseManager._busy),
    which needs nothing but the answer and ages out by itself. Forcing a
    lessee off its address would let anybody evict any client by answering
    ARP for it, and the alerts say as much rather than recommend that the
    operator do it for them. ARP alone cannot prove that two MACs
    are one host, so a second MAC on a leased address is always a conflict;
    when the two answer for each other, the alert offers that explanation,
    and is made once rather than repeated, since that is what a host on two
    interfaces looks like for as long as it is up.

    A finding is cleared once its address has been silent for SILENT_SWEEPS
    probes that could have heard it: not a probe whose window overflowed,
    and not in a sweep that has stopped hearing even the lessees it probes,
    which says so and is reported by --verify. A MAC that answers for at
    least PROXY_MIN unleased addresses and PROXY_FRACTION of those probed is
    a proxy-ARP host, reported as one finding rather than one per address;
    it is still reported for any leased address it answers for. The
    classification has to be earned again every sweep.

    Every structure fed by replies is capped, and so is what is logged,
    errors and the rest from separate allowances, so that noise cannot
    crowd out an alert; a full table of findings gives up one on a free
    address to make room for one on a lease. An alert that could not be
    logged is tried again at the next sweep.

    `io` returns the (send, recv) pair and is called on the sweeper's own
    thread when it starts; tests set send and recv directly.'''

    PROXY_MIN = 8
    PROXY_FRACTION = 0.5
    SILENT_SWEEPS = 3
    REMIND = 6 * 3600
    FULL_POOL_LIMIT = 512   # a /23
    REST_PERIOD = 4 * 3600
    LAPSED_FOR = 7 * 86400  # how long a lapsed lease is probed first
    # A ceiling on --arp-sweep-rate: at 12 Mb/s a broadcast takes well under
    # a tenth of a millisecond of airtime, so even this is negligible, but a
    # typo must not turn the sweep into a flood.
    MAX_RATE = 5.0
    # Replies read per probe window. A probe is answered by one device, two
    # in a conflict; anything near this is a flood, which says nothing.
    MAX_REPLIES = 64
    MAX_MACS_PER_PROBE = 4
    MAX_CONFLICTS = 256
    MAX_PROXIES = 64
    MAX_LOG = 16            # lines per interval, per allowance
    # Lessees probed without a single answer before the sweep counts as
    # deaf: a few may be asleep or gone, all of them means the sweep.
    BLIND_AFTER = 5
    UNICAST_RETRY = 1.0     # seconds before asking a known responder again
    MAX_FAILURES = 10       # probes in a row before the socket is reopened

    def __init__(self, lease_mgr, server_mac, interval=900, rate=2.0,
                 max_per_sweep=512, candidates=8, full_pool=False, io=None,
                 own_macs=None, own_addrs=None, restore=None, guard=None,
                 locktime=1.0, clock=time.time, sleep=time.sleep, rng=None):
        self.lm = lease_mgr
        self.server_mac = server_mac.lower()
        self.interval = interval
        self.rate = min(rate, self.MAX_RATE)
        self.max_per_sweep = max_per_sweep
        self.candidates = candidates
        self.full_pool = full_pool or \
            lease_mgr.network.num_addresses <= self.FULL_POOL_LIMIT
        self.io = io
        self.own_macs = own_macs or (lambda: set())
        self.own_addrs = own_addrs or (lambda: set())
        self.restore = restore or (lambda ip, mac: False)
        self.guard = guard or (lambda ip, mac: False)
        # Renewed well within the kernel's lock time; with none at all,
        # any reply moves the entry and renewing only shortens the damage.
        self.guard_every = max(0.1, locktime / 2)
        self.send = self.recv = None
        self.clock = clock
        self.sleep = sleep
        self.rng = rng or random.Random()

        # Everything below is guarded by the lease manager's lock, which the
        # allocator and the diagnostics thread also take.
        self.proxies = {}     # mac -> {'since': t, 'answered': n, 'alerted'}
        self.conflicts = {}   # (ip, mac) -> {kind, owner, held, mutual,
                              #               first, alerted, silent}
        self.dropped_conflicts = 0
        self.cursors = {}
        self.last_sweep = None
        self.blind = False
        self.log_left = {'error': self.MAX_LOG, 'other': self.MAX_LOG}
        self.unlogged = 0
        self._mine = set()     # this host's addresses, per sweep
        # Allocation avoids an address for two sweeps after it last answered,
        # so one missed probe does not end that.
        lease_mgr.heard_for = 2 * interval + 60

    # ------------------------------------------------------------- planning
    def budget(self):
        return max(1, min(self.max_per_sweep,
                          int(self.interval * 0.9 * self.rate)))

    def _rotate(self, name, items, room):
        '''Up to `room` of `items`, continuing where the last sweep stopped.'''
        if len(items) <= room:
            return list(items)
        c = self.cursors.get(name, 0) % len(items)
        self.cursors[name] = c + room
        return (items[c:] + items[:c])[:room]

    def _lapsed(self):
        '''Free addresses whose lease ran out recently, most recent first.
        Caller holds the lease lock.'''
        lm = self.lm
        cutoff = self.clock() - self.LAPSED_FOR
        return sorted((ip for ip, f in lm.former.items()
                       if f['expired'] and ip not in lm.ip_to_mac and
                       lm.last_freed.get(ip, 0.0) >= cutoff),
                      key=lambda ip: -lm.last_freed.get(ip, 0.0))

    def plan(self):
        '''The addresses to probe this sweep, most important first.'''
        lm = self.lm
        key = ipaddress.IPv4Address
        with lm.lock:
            suspect = sorted(set(lm.quarantine) |
                             {ip for ip, _ in self.conflicts}, key=key)
            classes = [
                ('suspect', suspect + [ip for ip in self._lapsed()
                                       if ip not in suspect], 4),
                ('candidates', lm.next_candidates(self.candidates), 4),
                ('leased', sorted(lm.ip_to_mac, key=key), 1),
            ]
        budget = self.budget()
        plan, seen = [], set()
        for name, items, share in classes:
            items = [ip for ip in items if ip not in seen]
            room = min(budget - len(plan), max(1, budget // share))
            for ip in self._rotate(name, items, room):
                seen.add(ip)
                plan.append(ip)

        if self.full_pool and len(plan) < budget:
            net = lm.network
            n = net.num_addresses
            quota = min(budget - len(plan),
                        max(1, -(-n * self.interval // self.REST_PERIOD)))
            base = int(net.network_address)
            skip = {str(net.network_address), str(net.broadcast_address)}
            cursor = self.cursors.get('rest', 0)
            i = taken = 0
            while taken < quota and i < n:
                ip = str(ipaddress.IPv4Address(base + (cursor + i) % n))
                i += 1
                if ip in seen or ip in skip: continue
                seen.add(ip)
                plan.append(ip)
                taken += 1
            self.cursors['rest'] = (cursor + i) % n
        return plan

    def _sender(self, ip):
        '''The address to ask from: one this host uses on the target's own
        subnet, as the kernel would, but never the target itself -- that
        would be a gratuitous announcement, and an RFC 5227 host squatting on
        it would defend it to the whole segment. The host's own addresses are
        asked from 0.0.0.0. Caller holds the lease lock.'''
        lm = self.lm
        if ip in self._mine:
            return '0.0.0.0'
        a = ipaddress.IPv4Address(ip)
        for d in lm.subnet_leases.values():
            if a in ipaddress.IPv4Network(d['subnet']):
                return d['gateway']
        if lm.playground_subnet and lm.playground_gateway and \
           a in lm.playground_subnet:
            return lm.playground_gateway
        return str(lm.server_ip)

    def _known(self, ip):
        '''MACs already known to claim `ip`, to be asked again by unicast.
        Never anybody for a leased address: a reply from the other device
        would move the kernel's entry to it, and the lessee answers the
        broadcast anyway. Caller holds the lease lock.'''
        lm = self.lm
        if ip in lm.ip_to_mac:
            return []
        known = [m for (i, m) in self.conflicts if i == ip]
        f = lm.former.get(ip)
        if f and f['expired'] and unicast_mac(f['mac']) and \
           f['mac'] not in known:
            known.append(f['mac'])
        return known[-self.MAX_MACS_PER_PROBE:]

    # -------------------------------------------------------------- probing
    def probe(self, ip, window):
        '''Ask who has `ip`, broadcast and by unicast to anybody known to
        claim it, listening for `window` seconds. Returns (MACs that
        answered, in order; whether the window overflowed). For a leased
        address the lessee's neighbour entry is guarded for the whole
        window: a device in power save may answer seconds late.'''
        with self.lm.lock:
            psrc = self._sender(ip)
            known = self._known(ip)
            owner = self.lm.ip_to_mac.get(ip)
        if owner:
            self.guard(ip, owner)
        self.send(ip, psrc)
        for m in known:
            self.send(ip, psrc, m)
        heard, flooded = [], False

        def listen(t):
            nonlocal flooded
            while t > 0:
                s = min(t, self.guard_every) if owner else t
                replies, over = self.recv(s)
                flooded |= over
                for psrc_, m in replies:
                    if psrc_ != ip or m in heard: continue
                    if len(heard) >= self.MAX_REPLIES:
                        flooded = True
                        break
                    heard.append(m)
                t -= s
                if owner and t > 0:
                    self.guard(ip, owner)
        first = min(self.UNICAST_RETRY, window) if known else 0.0
        if first:
            listen(first)
            for m in known:
                if m not in heard:
                    self.send(ip, psrc, m)
        # Listen out the window: it is what paces the sweep.
        if window > first:
            listen(window - first)
        return heard, flooded

    def _state(self):
        '''Bookkeeping for one sweep's worth of answers.'''
        return {'own': {self.server_mac} | self.own_macs(), 'obs': {},
                'answered': {}, 'unleased': 0, 'probed': 0, 'answering': 0,
                'free': {}, 'also': [], 'leased_probed': 0,
                'lessees_heard': 0, 'flooded': 0}

    def _refresh_mine(self):
        lm = self.lm
        mine = set(self.own_addrs())
        with lm.lock:
            mine.add(str(lm.server_ip))
            mine |= {d['gateway'] for d in lm.subnet_leases.values()}
            if lm.playground_gateway:
                mine.add(lm.playground_gateway)
            self._mine = mine

    def sweep(self):
        self._refresh_mine()
        plan = self.plan()
        started = self.clock()
        st = self._state()
        with self.lm.lock:
            self.dropped_conflicts = 0
            self.log_left = {'error': self.MAX_LOG, 'other': self.MAX_LOG}
        budget = self.budget()
        min_gap = 1.0 / self.rate
        gap = max(min_gap, self.interval * 0.9 / max(1, len(plan)))
        done = set()
        queue = list(plan)
        failures, reopened = 0, False
        while queue and st['probed'] < budget:
            ip = queue.pop(0)
            if ip in done: continue
            done.add(ip)
            wait = max(min_gap, gap * self.rng.uniform(0.75, 1.25))
            owner = None
            try:
                owner = self.evaluate(ip, *self.probe(ip, wait), st)
                failures = 0
            except Exception as e:
                failures += 1
                with self.lm.lock:
                    self._log(logging.ERROR,
                              f'⚠️ ARP probe of {ip} failed: {e}')
                self.sleep(wait)    # a failing socket must not set the pace
                if failures >= self.MAX_FAILURES:
                    # One reopen per sweep; if probing still fails, the next
                    # sweep tries again.
                    if reopened or not self._reopen():
                        break
                    reopened, failures = True, 0
            st['probed'] += 1
            if owner:
                self._restore(ip, owner)
            with self.lm.lock:
                # A host on two interfaces is only recognised as such if the
                # other side's own address is asked in the same sweep.
                queue[:0] = [b for b in st['also'] if b not in done]
                st['also'] = []
        try:
            self.finish(st)
        except Exception as e:
            logger.error(f'⚠️ ARP sweep evaluation failed: {e}')
        with self.lm.lock:
            self.last_sweep = {
                'started': round(started, 1),
                'finished': round(self.clock(), 1),
                'probed': st['probed'], 'answering': st['answering'],
                'lessees_probed': st['leased_probed'],
                'lessees_heard': st['lessees_heard'],
                'flooded': st['flooded'], 'full_pool': self.full_pool}
        logger.debug(f'📡 ARP sweep: probed {st["probed"]} addresses, '
                     f'{st["answering"]} answered by a device without a '
                     f'lease on them; heard {st["lessees_heard"]} of '
                     f'{st["leased_probed"]} lessees.')

    def _log(self, level, msg):
        '''Log within this interval's allowance -- errors and everything
        else from separate ones. Returns whether it was logged. Caller holds
        the lease lock.'''
        kind = 'error' if level >= logging.ERROR else 'other'
        if self.log_left[kind] <= 0:
            self.unlogged += 1
            return False
        self.log_left[kind] -= 1
        logger.log(level, msg)
        return True

    def evaluate(self, ip, heard, flooded, st):
        '''Record the answers to one probe for finish(). Returns the lessee
        of `ip` if somebody else answered for it, so that its neighbour entry
        can be pointed back at it at once.'''
        lm = self.lm
        with lm.lock:
            owner = lm.ip_to_mac.get(ip)
            if owner:
                st['leased_probed'] += 1
                if owner in heard:
                    st['lessees_heard'] += 1
            # The host's own MACs answer for its own addresses; for any
            # other address they are as foreign as anybody (proxy ARP, or a
            # guest sharing the host's MAC).
            foreign = [m for m in heard if m != owner and
                       not (ip in self._mine and m in st['own'])]
            if len(foreign) > self.MAX_MACS_PER_PROBE:
                self._log(logging.WARNING,
                          f'⚠️ {len(foreign)} MACs answer ARP for {ip}; '
                          f'considering only the first '
                          f'{self.MAX_MACS_PER_PROBE}. Possible ARP spoofing.')
                foreign = foreign[:self.MAX_MACS_PER_PROBE]
            vacancy = ip in lm.free_ips or ip in lm.playground_free_ips or \
                ip in lm.quarantine
            st['obs'][ip] = (owner, foreign, vacancy, flooded)
            st['flooded'] += flooded
            if not owner:
                st['unleased'] += 1
                for m in foreign:
                    st['answered'].setdefault(m, set()).add(ip)
                    if vacancy:
                        lm.note_heard(ip, m, self.clock())
            if foreign:
                st['answering'] += 1
            if not (owner and foreign):
                return None
            for m in foreign:
                b = lm.leases.get(m, {}).get('ip')
                if b and b not in st['obs']:
                    st['also'].append(b)
            return owner

    def _restore(self, ip, owner):
        '''Point the neighbour entry for `ip` back at its lessee, if it
        still is the lessee.'''
        with self.lm.lock:
            if self.lm.ip_to_mac.get(ip) != owner: return
        if self.restore(ip, owner):
            with self.lm.lock:
                self._log(logging.WARNING,
                          f'⚠️ Pointed the neighbour entry for {ip} back at '
                          f'its lessee {owner}; another device had answered '
                          f'for it.')

    def finish(self, st):
        '''Decide what a whole sweep's answers mean.'''
        lm = self.lm
        now = self.clock()
        with lm.lock:
            # Blindness: lessees always answer for their own addresses, so a
            # sweep that probed a few of them and heard none is not hearing
            # anything, and its silences must not count.
            blind = st['leased_probed'] >= self.BLIND_AFTER and \
                not st['lessees_heard']
            if blind and not self.blind:
                self._log(logging.ERROR,
                          f'🚨 ARP sweep hears no replies, not even from the '
                          f'{st["leased_probed"]} lessees it probed. No '
                          f'finding is cleared until it does.')
            elif self.blind and not blind and st['leased_probed']:
                self._log(logging.INFO, '✅ ARP sweep hears lessees again.')
            if st['leased_probed']:
                self.blind = blind

            # Proxy ARP: re-earned every sweep, judged against how much was
            # actually probed, so a handful of forged replies cannot get a
            # real squatter ignored.
            proxies = {}
            for m, ips in st['answered'].items():
                if len(ips) >= self.PROXY_MIN and \
                   len(ips) >= self.PROXY_FRACTION * st['unleased']:
                    proxies[m] = len(ips)
            for m in sorted(proxies)[:self.MAX_PROXIES]:
                if m not in self.proxies:
                    self.proxies[m] = {'since': now, 'alerted': None}
                p = self.proxies[m]
                p['answered'] = proxies[m]
                if p['alerted'] is None or now - p['alerted'] >= self.REMIND:
                    if self._log(logging.ERROR,
                                 f'🚨 {m} answers ARP for {proxies[m]} '
                                 f'addresses it holds no lease on, so it is '
                                 f'acting as a proxy-ARP host, and any client '
                                 f'it answers for can have its traffic '
                                 f'intercepted. Find it and turn proxy ARP '
                                 f'off.'):
                        p['alerted'] = now
            for m in [m for m in self.proxies if m not in proxies]:
                del self.proxies[m]
                self._log(logging.INFO,
                          f'✅ {m} no longer behaves like a proxy-ARP host.')

            # Findings: a MAC other than the lessee's answering for a leased
            # address, for one this host uses itself, or for a free one.
            seen = {}
            for ip, (owner, foreign, vacancy, _) in st['obs'].items():
                for m in foreign:
                    if lm.ip_to_mac.get(ip) == m:
                        continue    # it has since been given the address
                    if not owner and m in self.proxies:
                        continue    # reported as a proxy instead
                    held = lm.leases.get(m, {}).get('ip')
                    back = st['obs'].get(held, (None, []))[1] \
                        if held else []
                    if not owner:
                        kind = 'unleased' if vacancy else 'reserved'
                    elif m in self.proxies:
                        kind = 'proxy_arp'
                    elif m in st['own']:
                        kind = 'host'
                    else:
                        kind = 'conflict'
                    seen[(ip, m)] = (kind, owner, held,
                                     bool(owner and held and owner in back))

            for key in list(self.conflicts):
                ip, m = key
                if ip not in st['obs'] or key in seen: continue
                c = self.conflicts[key]
                owner_changed = st['obs'][ip][0] != c['owner']
                deaf = self.blind or st['obs'][ip][3]
                if deaf and not owner_changed: continue
                c['silent'] += 1
                if c['silent'] >= self.SILENT_SWEEPS or owner_changed:
                    del self.conflicts[key]
                    self._log(logging.INFO,
                              f'✅ {m} no longer answers ARP for {ip}; '
                              f'finding cleared.')

            # A device on somebody's lease first: that is traffic going astray
            # now, and forged noise on free addresses must not crowd it out.
            order = {'conflict': 0, 'proxy_arp': 0, 'host': 0, 'reserved': 1,
                     'unleased': 2}
            for key, (kind, owner, held, mutual) in sorted(
                    seen.items(), key=lambda kv: (order[kv[1][0]], kv[0])):
                ip, m = key
                c = self.conflicts.get(key)
                if c is None:
                    if len(self.conflicts) >= self.MAX_CONFLICTS:
                        # Full: make room by giving up the newest finding of
                        # a lesser kind, if there is one.
                        self.dropped_conflicts += 1
                        less = [k for k, v in self.conflicts.items()
                                if order[v['kind']] > order[kind]]
                        if not less:
                            continue
                        del self.conflicts[max(less, key=lambda k: (
                            order[self.conflicts[k]['kind']],
                            self.conflicts[k]['first']))]
                    c = self.conflicts[key] = {'first': now, 'alerted': None}
                # Once the two are seen to answer for each other, one lost
                # broadcast does not make them strangers: that lasts until
                # the other side's finding has itself been cleared.
                if not mutual and c.get('mutual') and \
                   (c['owner'], c['held']) == (owner, held) and \
                   (held, owner) in self.conflicts:
                    mutual = True
                changed =(c.get('kind'), c.get('owner'), c.get('held'),
                           c.get('mutual')) != (kind, owner, held, mutual)
                c.update(kind=kind, owner=owner, held=held, mutual=mutual,
                         silent=0)
                # Two MACs answering for each other are said once: repeating
                # it every few hours for a host that is simply on two
                # interfaces teaches people to ignore the log.
                due = c['alerted'] is None or \
                    (not mutual and now - c['alerted'] >= self.REMIND)
                if changed or due:
                    if self._alert(st, ip, m, c):
                        c['alerted'] = now
            if self.unlogged and self.log_left['other'] > 0:
                self.log_left['other'] -= 1
                logger.warning(f'⚠️ ARP sweep: {self.unlogged} more lines not '
                               f'logged this interval; see --verify.')
                self.unlogged = 0

    def _reopen(self):
        '''Probing keeps failing: open the socket again, since the interface
        may have been recreated. Returns whether that worked.'''
        if not self.io:
            return False
        try:
            self.send, self.recv = self.io()
        except Exception as e:
            logger.error(f'⚠️ ARP sweep cannot reopen its socket: {e}')
            return False
        logger.warning('⚠️ ARP sweep reopened its socket after repeated '
                       'failures.')
        return True

    def _suggest(self, st, owner):
        '''A --static entry that would move the lessee to a free address
        valid for its mode, keeping its name and options. Computed once per
        sweep and mode. Caller holds the lease lock.'''
        lm = self.lm
        mode = lm._effective_mode(owner, lm.leases.get(owner, {}))
        if mode not in st['free']:
            if mode == ClientClassifier.MODE_COMPAT:
                b = lm.find_free_slash_30(avoid_busy=True, quiet=True)
                busy = lm._busy()
                st['free'][mode] = str(list(b)[2]) if b and not any(
                    str(x) in busy for x in b) else None
            else:
                pg = mode == ClientClassifier.MODE_PLAYGROUND
                pool = lm.playground_free_ips if pg else lm.free_ips
                st['free'][mode] = lm._next_dynamic(pool, fallback=False)[0]
        spec = f'--static {owner}={st["free"][mode] or "<a free address>"}'
        name = lm.static_map.get(owner, (None, None))[1]
        if name: spec += f',{name}'
        if mode == ClientClassifier.MODE_COMPAT: spec += ',compat'
        if owner in lm.masq_macs: spec += ',masquerade'
        if mode == ClientClassifier.MODE_PLAYGROUND: spec += ',playground'
        return spec

    def _alert(self, st, ip, m, c):
        '''Log a finding. Returns whether it was logged.'''
        lm = self.lm
        owner, kind = c['owner'], c['kind']
        if kind == 'reserved':
            return self._log(logging.ERROR,
                             f'🚨 IP conflict on {ip}: {m} answers ARP for '
                             f'it, but this server uses it itself (a '
                             f'gateway, network or broadcast address). '
                             f'Reconfigure {m}.')
        if kind == 'unleased':
            f = lm.former.get(ip)
            why = (f'; it held a lease on {ip} that ran out and was never '
                   f'renewed' if f and f['expired'] and f['mac'] == m else '')
            return self._log(logging.ERROR,
                             f'🚨 {ip} is free, but {m} answers ARP for '
                             f'it{why}. The next client given {ip} would '
                             f'share it with {m}. If {m} is legitimate, '
                             f'reserve the address for it with --static '
                             f'{m}={ip} and restart isodhcp; otherwise find '
                             f'it and reconfigure it to use DHCP.')
        name = lm.leases.get(owner, {}).get('hostname')
        o = f'"{name}" {owner}' if name else owner
        if kind == 'proxy_arp':
            return self._log(logging.ERROR,
                             f'🚨 IP conflict on {ip}: proxy-ARP host {m} '
                             f'answers for it, although it is leased to {o}. '
                             f'Traffic meant for {owner} can reach {m}.')
        if kind == 'host':
            return self._log(logging.ERROR,
                             f'🚨 IP conflict on {ip}: this host answers ARP '
                             f'for it through {m}, although it is leased to '
                             f'{o}. Is proxy_arp enabled, or is a guest '
                             f'sharing that MAC (ipvlan, macvtap)?')
        held = c.get('held')
        spec = self._suggest(st, owner)
        if c.get('mutual'):
            return self._log(logging.WARNING,
                             f'⚠️ {m} answers ARP for {ip}, which is leased '
                             f'to {o}, and {owner} answers for {held}, which '
                             f'is leased to {m}. That is what one host with '
                             f'two interfaces on this segment looks like (on '
                             f'Linux, net.ipv4.conf.all.arp_ignore=1 stops '
                             f'it), but ARP cannot tell it apart from '
                             f'spoofing. Reported once while it lasts.')
        if held:
            why = (f'{m} holds {held} itself, and {owner} does not answer for '
                   f'{held} in return, so this is not one host answering on '
                   f'two interfaces. It may be ARP spoofing, or a second '
                   f'address configured on {m}.')
        else:
            why = (f'{m} holds no lease here: it is configured statically, '
                   f'still using a lease that has lapsed, or spoofing ARP.')
        if owner in lm.static_map:
            fix = (f'If {m} is legitimate, reconfigure it to use DHCP, or '
                   f'reserve its address for it with --static {m}={ip} and '
                   f'move the reservation of {owner}, for example to '
                   f'{spec}, then restart isodhcp.')
        else:
            fix = (f'If {m} is legitimate, reconfigure it to use DHCP, or '
                   f'reserve its address for it with --static {m}={ip} and '
                   f'restart isodhcp; {owner} then moves to a free address '
                   f'at its next renewal (add {spec} to choose which).')
        return self._log(logging.ERROR,
                         f'🚨 IP conflict on {ip}: it is leased to {o}, but '
                         f'{m} also answers ARP for it, so traffic meant for '
                         f'{owner} can reach {m} instead. {why} Find out '
                         f'which device is legitimate before acting: {owner} '
                         f'holds a valid lease. {fix}')

    def _avoided(self):
        '''How many free addresses allocation is passing over right now.
        Caller holds the lease lock.'''
        lm = self.lm
        busy = lm._busy()
        return len(lm._avoid(lm.free_ips, busy)) + \
            len(lm._avoid(lm.playground_free_ips, busy))

    def snapshot(self):
        '''State for the diagnostics socket. Caller holds the lease lock.'''
        return {
            'interval': self.interval, 'rate': self.rate,
            'max_per_sweep': self.max_per_sweep, 'budget': self.budget(),
            'full_pool': self.full_pool, 'blind': self.blind,
            'last_sweep': dict(self.last_sweep) if self.last_sweep else None,
            'proxy_macs': sorted(self.proxies),
            'avoided': self._avoided(),
            'dropped_conflicts': self.dropped_conflicts,
            'conflicts': [{'ip': ip, 'mac': m, 'kind': c['kind'],
                           'owner': c['owner'], 'mutual': c.get('mutual'),
                           'since': round(c['first'], 1)}
                          for (ip, m), c in sorted(self.conflicts.items())]}

    def run(self):
        logger.info(f'📡 ARP sweep: every {self.interval}s, at most '
                    f'{self.budget()} addresses at up to {self.rate:g}/s'
                    f'{", whole pool trickled" if self.full_pool else ""}.')
        failed = False
        while True:
            started = self.clock()
            if self.send is None:
                try:
                    self.send, self.recv = self.io()
                    if failed:
                        logger.info('✅ ARP sweep opened its socket.')
                    failed = False
                except Exception as e:
                    if not failed:
                        logger.error(f'⚠️ ARP sweep cannot open its socket, '
                                     f'retrying every {self.interval}s: {e}')
                    failed = True
            if self.send is not None:
                try:
                    self.sweep()
                except Exception as e:
                    logger.error(f'⚠️ ARP sweep failed: {e}')
            # Never longer than an interval, should the clock be set back.
            delay = min(self.interval,
                        started + self.interval - self.clock())
            if delay > 0:
                self.sleep(delay)

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
                 socket_path=None, arp_sweep_interval=900,
                 arp_sweep_rate=2.0, arp_sweep_max=512,
                 arp_sweep_candidates=8, arp_sweep_full=False):
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

        # Script file to notify of state change in leases allocations.
        # This has to exist before the LeaseManager does: its constructor
        # already reconciles the lease table against the configuration, and a
        # static reservation that evicts a dynamic lease reports the eviction
        # through execute_hook right there. Set up afterwards, that first
        # event died on a missing attribute and never reached the hook, so
        # whatever the hook publishes kept the evicted binding. The garbage
        # collector started below can fire the hook just as early.
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

        # Pass configs to LeaseManager
        self.lease_mgr = LeaseManager(self.pool_cidr, self.server_ip,
                                      self.lease_file, self.lease_time,
                                      sys_integrator=self.sys,
                                      static_map=static_map,
                                      compat_macs=self.compat_macs,
                                      masq_macs=self.masq_macs,
                                      state_change_callback=self.execute_hook,
                                      playground_size=playground_size)

        # Active ARP probing for addresses in use without a lease.
        self.arp_sweeper = None
        if arp_sweep_interval > 0:
            self.arp_sweeper = ArpSweeper(
                self.lease_mgr, self.server_mac, interval=arp_sweep_interval,
                rate=arp_sweep_rate, max_per_sweep=arp_sweep_max,
                candidates=arp_sweep_candidates, full_pool=arp_sweep_full,
                io=lambda: arp_socket_io(self.iface, self.server_mac),
                own_macs=local_macs, own_addrs=local_addrs,
                restore=lambda ip, mac: restore_neighbour(self.if_index, ip,
                                                          mac),
                guard=lambda ip, mac: guard_neighbour(self.if_index, ip, mac),
                locktime=neigh_locktime(self.iface))

        # Pre-calculate the "wide" mask (e.g., '255.255.255.0')
        self.wide_netmask = str(self.lease_mgr.network.netmask)
        self.gc_thread = threading.Thread(target=self.garbage_collector,
                                          daemon=True)
        self.gc_thread.start()

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
            arp = self.arp_sweeper.snapshot() if self.arp_sweeper else None
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
            'arp_sweep': arp,
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
            arp = self.arp_sweeper.snapshot() if self.arp_sweeper else None
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

        # F. Devices the ARP sweep found answering for addresses they hold no
        # lease on. Stays listed until the sweep stops hearing them; two
        # lessees answering for each other are most likely one host on two
        # interfaces, so they are listed without raising the alarm.
        for c in (arp['conflicts'] if arp else []):
            whose = {'unleased': 'which is free',
                     'reserved': 'used by this server'}.get(
                         c['kind'], f"leased to {c['owner']}")
            what = {'proxy_arp': ' (proxy-ARP host)',
                    'host': ' (this host)'}.get(c['kind'], '')
            hint = '; one host on two interfaces?' if c.get('mutual') else ''
            add('low' if c.get('mutual') else 'alarming', 'arp',
                'ip_conflict',
                f"{c['mac']}{what} answers ARP for {c['ip']}, {whose}{hint}; "
                f"see the log for what to do", ip=c['ip'])
        for m in (arp['proxy_macs'] if arp else []):
            add('alarming', 'arp', 'proxy_arp',
                f"{m} answers ARP for most unleased addresses it is asked "
                f"about (proxy ARP)", mac=m)
        if arp and arp['blind']:
            add('unknown', 'arp', 'blind',
                'the ARP sweep hears no replies, not even from lessees; '
                'no finding is cleared until it does')
        flooded = ((arp or {}).get('last_sweep') or {}).get('flooded')
        if flooded:
            add('moderate', 'arp', 'flooded',
                f"{flooded} probes of the last ARP sweep drew more replies "
                f"than are read; an answer from a squatter may have been "
                f"missed (possible ARP spoofing)")
        if arp and arp['dropped_conflicts']:
            add('alarming', 'arp', 'conflicts_dropped',
                f"{arp['dropped_conflicts']} further conflicts were not "
                f"tracked (cap reached); possible ARP spoofing")

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
        if self.arp_sweeper:
            threading.Thread(target=self.arp_sweeper.run, daemon=True).start()
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
    if isinstance(o, str):
        return _MAC_RE.sub(lambda mm: _redact_mac(mm.group(0)), o)
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
    a = r.get('arp_sweep')
    if a:
        ls = a['last_sweep']
        last = (f"last probed {ls['probed']}, {ls['answering']} in use "
                f"without a lease" if ls else 'first sweep in progress')
        if ls and ls.get('flooded'):
            last += f", {ls['flooded']} flooded"
        n = len(a['conflicts'])
        avoided = (f", {a['avoided']} not offered while they answer"
                   if a.get('avoided') else '')
        print(f"   ARP sweep: every {a['interval']}s, {last}{avoided}"
              f"{f'  🚨 {n} FINDING(S), see --verify' if n else ''}")
    elif 'arp_sweep' in r:
        print("   ARP sweep: off")
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
    if any(d['resource'] != 'arp' for d in shown
           if d['severity'] in ('alarming', 'moderate')):
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
        '--arp-sweep-interval', type=int, default=900, metavar='SECONDS',
        help='Probe leased, recently lapsed and next-to-be-allocated '
        'addresses with ARP this often, to find devices using an address '
        'without a lease. 0 turns it off.')
    parser.add_argument(
        '--arp-sweep-rate', type=float, default=2.0, metavar='PER_SECOND',
        help=f'Never send broadcast ARP probes faster than this (at most '
        f'{ArpSweeper.MAX_RATE:g}).')
    parser.add_argument(
        '--arp-sweep-max', type=int, default=512, metavar='N',
        help='Probe at most this many addresses per sweep.')
    parser.add_argument(
        '--arp-sweep-candidates', type=int, default=8, metavar='K',
        help='Also probe the next K standard and K playground addresses '
        'allocation will hand out, and, unless K is 0, the next /30 block.')
    parser.add_argument(
        '--arp-sweep-full', action='store_true',
        help='Also trickle through the rest of the pool when it is larger '
        'than a /23 (smaller pools always are).')
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

    # The sweep sends broadcasts, so its limits are not negotiable.
    if args.arp_sweep_interval != 0 and args.arp_sweep_interval < 60:
        logger.critical('⚠️ --arp-sweep-interval must be 0 (off) or >= 60.')
        sys.exit(1)
    if not 0 < args.arp_sweep_rate <= ArpSweeper.MAX_RATE:
        logger.critical(f'⚠️ --arp-sweep-rate must be > 0 and <= '
                        f'{ArpSweeper.MAX_RATE:g}.')
        sys.exit(1)
    if args.arp_sweep_max < 1 or args.arp_sweep_candidates < 0:
        logger.critical('⚠️ --arp-sweep-max must be >= 1 and '
                        '--arp-sweep-candidates >= 0.')
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
            socket_path=args.socket,
            arp_sweep_interval=args.arp_sweep_interval,
            arp_sweep_rate=args.arp_sweep_rate,
            arp_sweep_max=args.arp_sweep_max,
            arp_sweep_candidates=args.arp_sweep_candidates,
            arp_sweep_full=args.arp_sweep_full
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
