#!/usr/bin/env python3
'''Allocation avoids free addresses the ARP sweep heard answer recently.

The wire is simulated: a dict of address -> MACs that answer ARP for it, a
set of MACs that miss broadcasts (Wi-Fi loss), and a clock that only moves
when the sweeper waits for replies. Addresses are documentation-style
values, unrelated to any real deployment.

Run with the venv interpreter:
    python3 tests/arp_avoid_test.py [path/to/isodhcp.py]
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



if not hasattr(iso.LeaseManager, 'note_heard'):
    print('(this revision does not avoid answering addresses)')

print('--- 1. a free address that answers is not offered ---')
with tempfile.TemporaryDirectory() as td:
    squatter = mac(0x20)
    lm = make_lm(td)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    wire = Wire()
    wire.answers[target] = {squatter}
    sw = make_sweeper(lm, wire)
    sw.sweep()
    cap.records.clear()
    got = [lm.allocate_or_renew(mac(0x30 + i), None, STD) for i in range(3)]
    check('skipped', target not in got, got)
    check('said once, with who answered',
          len(cap.grep(f'Not offering {target}: {squatter}', 'WARNING')) == 1,
          cap.records[-4:])
    check('still in the pool', target in lm.free_ips)
    with lm.lock:
        check('counted for --status', sw.snapshot().get('avoided') == 1)
    restore_time()

print('--- 2. silence does not lift it; age does ---')
with tempfile.TemporaryDirectory() as td:
    squatter = mac(0x21)
    lm = make_lm(td)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    wire = Wire()
    wire.answers[target] = {squatter}
    sw = make_sweeper(lm, wire)
    sw.sweep()
    del wire.answers[target]
    wire.now += sw.interval
    got = lm.allocate_or_renew(mac(0x31), None, STD)
    check('one interval later, still avoided', got != target, got)
    wire.now += sw.interval + 61
    got = [lm.allocate_or_renew(mac(0x32 + i), None, STD) for i in range(4)]
    check('after two intervals without an answer, offered again',
          target in got, got)
    restore_time()

print('--- 3. it fails open: nothing else left, hand it out and say so ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td, pool='192.168.99.0/29')
    wire = Wire()
    sw = make_sweeper(lm, wire)
    free = sorted(lm.free_ips, key=ipaddress.IPv4Address)
    for i, ip in enumerate(free):
        wire.answers[ip] = {mac(0x40 + i)}
    sw.sweep()
    cap.records.clear()
    got = [lm.allocate_or_renew(mac(0x50 + i), None, STD)
           for i in range(len(free))]
    check('every address still allocatable', None not in got, got)
    check('said at ERROR, once', len(cap.grep('Handing out', 'ERROR')) == 1,
          cap.grep('Handing out'))
    restore_time()

print('--- 4. at most eight are skipped per pick ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire, candidates=12)
    top = sorted(lm.free_ips, key=ipaddress.IPv4Address)[-12:]
    for i, ip in enumerate(top):
        wire.answers[ip] = {mac(0x60 + i)}
    sw.sweep()
    got = lm.allocate_or_renew(mac(0x70), None, STD)
    rank = sorted(top, key=ipaddress.IPv4Address, reverse=True).index(got) \
        if got in top else None
    # Literal, not the class constant: raising the constant must fail here.
    check('a busy address is handed out once eight have been skipped',
          rank is not None and 8 <= rank < 8 + 4, (got, rank))
    restore_time()

print('--- 5. a MAC answering for many is not believed ---')
with tempfile.TemporaryDirectory() as td:
    forger = mac(0x80)
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        cand = lm.next_candidates(3)
    for ip in cand:
        wire.answers[ip] = {forger}
    sw.sweep()
    cap.records.clear()
    got = lm.allocate_or_renew(mac(0x81), None, STD)
    check('three addresses from one MAC: none avoided', got == cand[0],
          (got, cand))
    check('said at ERROR', cap.grep(forger, 'ERROR'), cap.records[-3:])
    restore_time()

print('--- 6. without a sweep nothing is avoided ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    with lm.lock:
        top = lm.next_candidates(1)[0]
        lm.note_heard(top, mac(0x90), time.time())
    got = lm.allocate_or_renew(mac(0x91), None, STD)
    check('heard_for is 0, so the answer never counted', got == top, got)

print('--- 7. a returning client and its own address ---')
with tempfile.TemporaryDirectory() as td:
    old, other = mac(0xa0), mac(0xa1)
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    ip = lm.allocate_or_renew(old, None, STD)
    lm.leases[old]['expires'] = wire.now - 1
    lm.get_expired_leases()
    wire.answers[ip] = {old}
    sw.sweep()
    check('the former holder gets it back although it answers',
          lm.allocate_or_renew(old, None, STD) == ip)
    lm.release(old)
    wire.answers[ip] = {other}
    sw.sweep()
    got = lm.allocate_or_renew(old, None, STD)
    check('not when somebody else answers for it', got != ip, (got, ip))
    restore_time()

print('--- 8. a compat client is not given a block something answers in ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        block = [str(x) for x in lm.find_free_slash_30()]
    wire.answers[block[1]] = {mac(0xb0)}
    sw.sweep()
    lm.allocate_or_renew(mac(0xb1), None, COMPAT)
    check('another block', lm.subnet_leases[mac(0xb1)]['subnet'] !=
          f'{block[0]}/30', lm.subnet_leases[mac(0xb1)])
    restore_time()

print('--- 9. nothing survives a restart, and the record is bounded ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        for i in range(200):
            lm.note_heard(f'192.168.99.{i + 2}',
                          mac(0xc00 + i), wire.now + i)
    # Literal bound, not the class constant.
    check('at most 64 remembered, the newest',
          len(lm.heard) == 64 and
          min(t for _, t in lm.heard.values()) == wire.now + 136,
          len(lm.heard))
    lm.save_leases()
    restore_time()
    lm2 = make_lm(td)
    check('empty after a restart', not lm2.heard and
          'heard' not in json.load(open(os.path.join(td, 'leases.json'))))

print('--- 10. the sweep keeps probing what allocation avoids ---')
with tempfile.TemporaryDirectory() as td:
    squatter = mac(0xd0)
    lm = make_lm(td)
    for i in range(30):
        lm.allocate_or_renew(mac(0xd10 + i), None, STD)
    wire = Wire()
    sw = make_sweeper(lm, wire, max_per_sweep=20, candidates=2)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    wire.answers[target] = {squatter}
    sw.sweep()
    probed = 0
    for _ in range(6):
        n = len(wire.sent)
        sw.sweep()
        probed += any(i == target for _, i, _, _ in wire.sent[n:])
    got = lm.allocate_or_renew(mac(0xd0f), None, STD)
    check('probed every sweep, so the answer never ages out',
          probed == 6 and got != target, (probed, got))
    restore_time()

def top_free(lm, n):
    return sorted(lm.free_ips, key=ipaddress.IPv4Address)[-n:][::-1]

print('--- 11. the sweep pre-validates what allocation will really give ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        for i, ip in enumerate(top_free(lm, 4)):
            lm.note_heard(ip, mac(0xe00 + i), wire.now)
        cand = lm.next_candidates(1)
    got = lm.allocate_or_renew(mac(0xe10), None, STD)
    check('the next candidate is the next address handed out',
          cand and cand[0] == got, (cand, got))
    restore_time()

print('--- 12. a sweep says nothing about allocating, and suggests no busy address ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0xe20), mac(0xe21)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        busy = top_free(lm, 10)
        for i, b in enumerate(busy):
            lm.note_heard(b, mac(0xe30 + i // 2), wire.now)
        wire.answers.update({b: {mac(0xe30 + i // 2)}
                             for i, b in enumerate(busy)})
    wire.answers[ip] = {lessee, squatter}
    cap.records.clear()
    sw.sweep()
    check('no allocation messages from a sweep',
          not cap.grep('Handing out') and not cap.grep('Not offering'),
          [m for _, m in cap.records if 'Handing' in m or 'offering' in m][:2])
    sug = [m for _, m in cap.records if f'--static {lessee}=' in m]
    named = sug and sug[0].split(f'--static {lessee}=')[1].split(',')[0] \
        .split()[0]
    check('the suggested address is not one somebody answers for',
          named and named not in busy, (named, sug[:1]))
    cap.records.clear()
    lm.allocate_or_renew(mac(0xe40), None, STD)
    check('so a real allocation afterwards still says what it skipped',
          cap.grep('Not offering', 'WARNING'), cap.records[-3:])
    restore_time()

print('--- 13. an answer dated in the future is not believed ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        top = top_free(lm, 1)[0]
        lm.note_heard(top, mac(0xe50), wire.now + 86400)
    got = lm.allocate_or_renew(mac(0xe51), None, STD)
    check('handed out as if never heard', got == top, (got, top))
    restore_time()

print('--- 14. one MAC answering for many cannot push real answers out ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        real = top_free(lm, 1)[0]
        lm.note_heard(real, mac(0xe60), wire.now)
        for i, ip in enumerate(sorted(lm.free_ips)[:150]):
            lm.note_heard(ip, mac(0xe61), wire.now + 1 + i)
    check('the real answer is still remembered',
          lm.heard.get(real, (None,))[0] == mac(0xe60), len(lm.heard))
    got = lm.allocate_or_renew(mac(0xe62), None, STD)
    check('and still avoided', got != real, got)
    restore_time()

print('--- 14b. a MAC not believed once is believed again later ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    dev = mac(0xe65)
    with lm.lock:
        for ip in sorted(lm.free_ips)[:3]:
            lm.note_heard(ip, dev, wire.now)
        wire.now += lm.heard_for + 1
        top = top_free(lm, 1)[0]
        lm.note_heard(top, dev, wire.now)
    got = lm.allocate_or_renew(mac(0xe66), None, STD)
    check('its new answer is recorded and avoided',
          lm.heard.get(top, (None,))[0] == dev and got != top, (got, top))
    restore_time()

print('--- 15. a device back after its record aged out is said again ---')
with tempfile.TemporaryDirectory() as td:
    squatter = mac(0xe70)
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        top = top_free(lm, 1)[0]
        lm.note_heard(top, squatter, wire.now)
    cap.records.clear()
    lm.allocate_or_renew(mac(0xe71), None, STD)
    wire.now += lm.heard_for + 1
    with lm.lock:                       # record has aged out: a pick
        lm._pick_dynamic(lm.free_ips)   # without handing anything out
    with lm.lock:
        lm.note_heard(top, squatter, wire.now)
    lm.allocate_or_renew(mac(0xe73), None, STD)
    check('said twice', len(cap.grep(f'Not offering {top}', 'WARNING')) == 2,
          cap.records[-4:])
    restore_time()

print('--- 16. one override message does not silence another ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td, pool='192.168.99.0/29')
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        frees = sorted(lm.free_ips, key=ipaddress.IPv4Address)
        crowd = sorted(lm.free_ips)[:3]
    cap.records.clear()
    with lm.lock:
        for ip in frees[:3]:
            lm.note_heard(ip, mac(0xe80), wire.now)     # a crowd
        for ip in frees[3:]:
            lm.note_heard(ip, mac(0xe81 + frees.index(ip)), wire.now)
    for i in range(len(frees)):
        lm.allocate_or_renew(mac(0xe90 + i), None, STD)
    check('both the crowd and the hand-out are said',
          cap.grep('Not avoiding', 'ERROR') and
          cap.grep('Handing out', 'ERROR'), cap.records[-5:])
    restore_time()

print('--- 16b. probing the next block to be handed out logs nothing ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td, pool='192.168.99.0/28')
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        for i, base in enumerate((4, 8, 12)):
            lm.note_heard(f'192.168.99.{base + 2}', mac(0xeb0 + i), wire.now)
    cap.records.clear()
    sw.sweep()
    check('no hand-out message from a sweep', not cap.grep('Handing out'),
          [m for _, m in cap.records if 'Handing' in m][:2])
    lm.allocate_or_renew(mac(0xec0), None, COMPAT)
    check('but a real compat allocation says it',
          cap.grep('Handing out', 'ERROR'), cap.records[-3:])
    restore_time()

print('--- 17. --status counts what is actually passed over ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        for i, ip in enumerate(top_free(lm, 12)):
            lm.note_heard(ip, mac(0xea0 + i), wire.now)
        n = sw.snapshot().get('avoided')
    check('at most eight', n == 8, n)
    restore_time()

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
