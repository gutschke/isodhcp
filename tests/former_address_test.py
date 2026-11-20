#!/usr/bin/env python3
'''A client that asks again gets its former address, or its /30, back.

The wire is simulated: a dict of address -> MACs that answer ARP for it, a
set of MACs that miss broadcasts (Wi-Fi loss), and a clock that only moves
when the sweeper waits for replies. Addresses are documentation-style
values, unrelated to any real deployment.

Run with the venv interpreter:
    python3 tests/former_address_test.py [path/to/isodhcp.py]
'''
import importlib.util
import ipaddress
import json
import logging
import os
import random
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else \
    os.path.join(HERE, os.pardir, 'isodhcp.py')
spec = importlib.util.spec_from_file_location('isodhcp', SRC)
iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iso)

POOL = '192.168.99.0/24'
SERVER = '192.168.99.1'
SERVER_MAC = '02:00:00:00:00:01'
OTHER_OWN_MAC = '02:00:00:00:00:02'     # another interface of the server
STD = {'mode': 'standard', 'masq': False}
COMPAT = {'mode': 'compat', 'masq': False}
OK = True
REAL_TIME = time.time


def check(label, cond, detail=''):
    global OK
    print(f'{"PASS" if cond else "FAIL"}: {label}'
          f'{"  -- " + str(detail) if detail and not cond else ""}')
    OK &= bool(cond)


def mac(i):
    return f'02:00:00:00:{i >> 8:02x}:{i & 0xff:02x}'


class FakeSys:
    isolation_mode = 'test'

    def __getattr__(self, name):
        return lambda *a, **kw: None


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append((record.levelname, record.getMessage()))

    def grep(self, text, level=None):
        return [m for lv, m in self.records
                if text in m and (level is None or lv == level)]


cap = Capture()
iso.logger.addHandler(cap)
iso.logger.setLevel(logging.DEBUG)
# The allocator's passive neighbour-table check must not see this host's
# real ARP cache.
iso.LeaseManager.is_ip_active_in_arp = lambda self, ip: False


def make_lm(td, pool=POOL, **kw):
    return iso.LeaseManager(pool, SERVER, os.path.join(td, 'leases.json'),
                            3600, sys_integrator=FakeSys(), **kw)


class Wire:
    '''answers[ip] = MACs that reply to a who-has for ip; deaf = MACs that
    never hear a broadcast (but do hear unicast).'''

    def __init__(self):
        self.answers = {}
        self.deaf = set()
        self.lm = None              # set by make_sweeper
        self.mute_lessees = False   # lessees answer for themselves unless
        self.now = 1_000_000.0
        self.sent = []          # (time, ip, psrc, dst)
        self.pending = []

    def clock(self):
        return self.now

    def send(self, ip, psrc, dst=None):
        self.sent.append((self.now, ip, psrc, dst))
        who = set(self.answers.get(ip, ()))
        if self.lm and not self.mute_lessees and ip in self.lm.ip_to_mac and \
           ip not in self.answers:
            who.add(self.lm.ip_to_mac[ip])
        for m in sorted(who):
            if (dst is None and m not in self.deaf) or dst == m:
                if (ip, m) not in self.pending:
                    self.pending.append((ip, m))

    def recv(self, timeout):
        self.now += timeout
        out, self.pending = self.pending, []
        return out, False

    def sleep(self, s):
        self.now += s

    def broadcasts(self):
        return [x for x in self.sent if x[3] is None]


def make_sweeper(lm, wire, **kw):
    kw.setdefault('own_macs', lambda: {OTHER_OWN_MAC})
    sw = iso.ArpSweeper(lm, SERVER_MAC, clock=wire.clock, sleep=wire.sleep,
                        **kw)
    sw.send, sw.recv = wire.send, wire.recv
    wire.lm = lm
    iso.time.time = wire.clock      # the lease manager's clock too
    return sw


def restore_time():
    iso.time.time = REAL_TIME


print('--- 1. a returning client gets its address back ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    a = lm.allocate_or_renew(mac(1), None, STD)
    b = lm.allocate_or_renew(mac(2), None, STD)
    lm.release(mac(1))
    lm.release(mac(2))
    lm.leases.clear()
    got = lm.allocate_or_renew(mac(1), None, STD)
    check('its own, not the reuse window\'s choice', got == a, (got, a))
    lm2 = make_lm(td)
    check('remembered across a restart',
          lm2.allocate_or_renew(mac(2), None, STD) == b)

print('--- 2. not if somebody else has it by now ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    a = lm.allocate_or_renew(mac(1), None, STD)
    lm.release(mac(1))
    lm.free_ips.discard(a)
    lm.leases[mac(9)] = {'ip': a, 'expires': time.time() + 3600,
                         'mode': 'standard', 'masq': False}
    lm.ip_to_mac[a] = mac(9)
    got = lm.allocate_or_renew(mac(1), None, STD)
    check('a fresh address instead', got and got != a, got)

print('--- 3. a returning compat client gets its /30 back, across a restart ---')
with tempfile.TemporaryDirectory() as td:
    old = mac(0xd0)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(old, None, COMPAT)
    block = lm.subnet_leases[old]['subnet']
    lm.leases[old]['expires'] = time.time() - 1
    lm.save_leases()
    lm2 = make_lm(td)        # it lapsed while the server was down
    check('the whole block is remembered for it',
          lm2.former.get(ip, {}).get('block') == block, lm2.former.get(ip))
    got = lm2.allocate_or_renew(old, None, COMPAT)
    check('and handed back', got == ip and
          lm2.subnet_leases[old]['subnet'] == block, lm2.subnet_leases.get(old))
    lm.leases[old]['expires'] = time.time() - 1
    lm.get_expired_leases()
    lm3 = make_lm(td)        # it lapsed while the server was up
    check('also after a runtime expiry and a restart',
          lm3.former.get(ip, {}).get('block') == block, lm3.former.get(ip))

print('--- 4. a damaged lease file cannot make a block of any size ---')
with tempfile.TemporaryDirectory() as td:
    json.dump({'leases': {}, 'subnets': {},
               'released': {'192.168.99.6': {'at': 1.0, 'mac': mac(0xd1),
                                             'block': '10.0.0.0/8'},
                            '192.168.99.10': {'at': 1.0, 'mac': mac(0xd2),
                                              'block': '192.168.99.12/30'},
                            '192.168.99.2': {'at': 1.0, 'mac': mac(0xd3),
                                             'block': '192.168.99.0/29'}}},
              open(os.path.join(td, 'leases.json'), 'w'))
    lm = make_lm(td)
    check('blocks that are not the /30 of that address are dropped',
          'block' not in lm.former.get('192.168.99.6', {}) and
          'block' not in lm.former.get('192.168.99.10', {}) and
          'block' not in lm.former.get('192.168.99.2', {}), lm.former)

print('--- 5. a block that is no longer whole is not handed back ---')
with tempfile.TemporaryDirectory() as td:
    old = mac(0xe0)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(old, None, COMPAT)
    block = lm.subnet_leases[old]['subnet']
    lm.release(old)
    gw = str(ipaddress.IPv4Network(block)[1])
    lm.free_ips.discard(gw)            # somebody has its gateway now
    lm.leases[mac(0xe1)] = {'ip': gw, 'expires': time.time() + 3600,
                            'mode': 'standard', 'masq': False}
    lm.ip_to_mac[gw] = mac(0xe1)
    lm.allocate_or_renew(old, None, COMPAT)
    check('a whole block instead', lm.subnet_leases[old]['subnet'] != block,
          lm.subnet_leases.get(old))

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
