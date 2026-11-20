#!/usr/bin/env python3
'''ARP sweep, returning a former address, and allocation order.

The wire is simulated: a dict of address -> MACs that answer ARP for it, a
set of MACs that miss broadcasts (Wi-Fi loss), and a clock that only moves
when the sweeper waits for replies. Addresses are documentation-style
values, unrelated to any real deployment.

Run with the venv interpreter:
    python3 tests/arp_sweep_test.py [path/to/isodhcp.py]
Sections 1-3 exercise only LeaseManager allocation and are meaningful
against an older revision too; 3b needs _pick_dynamic (its self-check fails
without it), and the rest need ArpSweeper and are skipped without it.
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


# ---------------------------------------------------------------- allocation
print('--- 1. a just-released address is not the next one handed out ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    a = lm.allocate_or_renew(mac(1), None, STD)
    b = lm.allocate_or_renew(mac(2), None, STD)
    lm.release(mac(1))
    c = lm.allocate_or_renew(mac(3), None, STD)
    check('fresh pool still fills from the top', a == '192.168.99.254', a)
    check('released address is not reused first', c != a, (a, b, c))

print('--- 2. allocation recency survives a restart ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    a = lm.allocate_or_renew(mac(1), None, STD)
    lm.release(mac(1))
    lm2 = make_lm(td)
    c = lm2.allocate_or_renew(mac(3), None, STD)
    check('released address still avoided after restart', c != a, (a, c))

print('--- 3. a lease that lapsed while the server was down counts as freed ---')
with tempfile.TemporaryDirectory() as td:
    json.dump({'leases': {mac(1): {'ip': '192.168.99.254', 'mode': 'standard',
                                   'expires': time.time() - 7200}},
               'subnets': {}}, open(os.path.join(td, 'leases.json'), 'w'))
    lm = make_lm(td)
    c = lm.allocate_or_renew(mac(3), None, STD)
    check('expired-on-disk address is not handed out first',
          c != '192.168.99.254', c)

print('--- 3b. allocation order keeps the pool as compact as highest-first ---')


def churn(seed, picker=None, steps=1200, live_cap=120, compat_p=0.1):
    '''Random /32 and /30 churn on a /24; returns (failures, average free
    /29 blocks, average free /28 blocks) after a warm-up.'''
    with tempfile.TemporaryDirectory() as td:
        lm = make_lm(td)
        lm.save_leases = lambda *a, **kw: None
        if picker:
            lm._pick_dynamic = lambda pool: picker(lm, pool)
        rng = random.Random(seed)
        live, fails, blocks = [], 0, {29: [], 28: []}
        clock = [1000.0]
        iso.time.time = lambda: clock[0]
        try:
            for step in range(steps):
                clock[0] += 10
                if rng.random() < 0.6 and len(live) < live_cap:
                    compat = rng.random() < compat_p
                    m = mac((0x8000 if compat else 0x4000) + step)
                    if lm.allocate_or_renew(m, None,
                                            COMPAT if compat else STD):
                        live.append(m)
                    else:
                        fails += 1
                elif live:
                    lm.release(live.pop(rng.randrange(len(live))))
                if step >= 300:
                    for pfx in blocks:
                        blocks[pfx].append(sum(
                            1 for b in lm.network.subnets(new_prefix=pfx)
                            if all(str(x) in lm.free_ips for x in b
                                   if x != lm.network.network_address)))
        finally:
            restore_time()
        return (fails, sum(blocks[29]) / len(blocks[29]),
                sum(blocks[28]) / len(blocks[28]))


def avg(runs, i):
    return sum(r[i] for r in runs) / len(runs)


strict = lambda lm, pool: max(pool, key=ipaddress.IPv4Address) \
    if pool else None
scatter = lambda lm, pool: random.Random(len(pool)).choice(sorted(pool)) \
    if pool else None
seeds = range(3)
ours = [churn(s) for s in seeds]
ref = [churn(s, strict) for s in seeds]
bad = [churn(s, scatter) for s in seeds]
check('the measure sees fragmentation (a scattering allocator scores worse)',
      avg(bad, 1) < avg(ref, 1) - 2 and avg(bad, 2) < avg(ref, 2) - 1,
      (avg(bad, 1), avg(ref, 1), avg(bad, 2), avg(ref, 2)))
check('free /29 blocks within 0.5 of strict highest-first on average',
      avg(ours, 1) >= avg(ref, 1) - 0.5, (avg(ours, 1), avg(ref, 1)))
check('free /28 blocks within 0.5 of strict highest-first on average',
      avg(ours, 2) >= avg(ref, 2) - 0.5, (avg(ours, 2), avg(ref, 2)))
check('no more allocation failures than strict highest-first',
      avg(ours, 0) <= avg(ref, 0), (avg(ours, 0), avg(ref, 0)))

if not hasattr(iso, 'ArpSweeper'):
    print('\n(no ArpSweeper in this revision; sweep sections skipped)')
    print('\nALL PASS' if OK else '\nFAILURES PRESENT')
    sys.exit(0 if OK else 1)

print('--- 4. the allocator hands out what the sweep pre-validated ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    lm.allocate_or_renew(mac(1), None, STD)
    lm.release(mac(1))
    with lm.lock:
        cand = lm.next_candidates(8)
    got = lm.allocate_or_renew(mac(2), None, STD)
    check('next allocation is the first candidate', got == cand[0],
          (got, cand[:3]))
    with lm.lock:
        check('k=0 asks for no candidates at all',
              lm.next_candidates(0) == [], lm.next_candidates(0))

# --------------------------------------------------------------- detection
print('--- 5. silent squatter on a leased address ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0x10), mac(0x20)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, 'host', STD)
    wire = Wire()
    wire.answers[ip] = {lessee, squatter}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    alerts = cap.grep(f'IP conflict on {ip}', 'ERROR')
    check('conflict raised once, at ERROR', len(alerts) == 1, cap.records[-5:])
    text = alerts[0] if alerts else ''
    check('asks the operator to find out which device is legitimate',
          'which device is legitimate' in text and 'valid lease' in text,
          text)
    check('names spoofing as a possibility', 'spoofing' in text, text)
    check('offers pinning only for a legitimate device',
          f'If {squatter} is legitimate' in text and
          f'--static {squatter}={ip}' in text, text)
    free = text.split(f'--static {lessee}=')[-1].split(' ')[0].rstrip(').') \
        if f'--static {lessee}=' in text else None
    check('names a real free address for the lessee', free in lm.free_ips,
          free)
    check('alert only: lessee keeps its lease', lm.leases[lessee]['ip'] == ip)
    check('leased address not quarantined', ip not in lm.quarantine)
    with lm.lock:
        snap = sw.snapshot()
    check('conflict visible to diagnostics',
          [(c['ip'], c['mac'], c['kind']) for c in snap['conflicts']] ==
          [(ip, squatter, 'conflict')], snap['conflicts'])
    cap.records.clear()
    sw.sweep()
    check('not re-raised within the reminder interval',
          not cap.grep('IP conflict'), cap.records[-3:])
    wire.now += sw.REMIND
    sw.sweep()
    check('re-raised after the reminder interval',
          len(cap.grep('IP conflict', 'ERROR')) == 1)
    wire.answers[ip] = {lessee}
    for _ in range(sw.SILENT_SWEEPS - 1):
        sw.sweep()
    check('conflict still held before enough silent sweeps', sw.conflicts)
    sw.sweep()
    check('conflict clears after silent sweeps', not sw.conflicts,
          sw.conflicts)
    check('clearing is logged', cap.grep('finding cleared'))
    restore_time()

print('--- 5b. the suggested address fits the lessee\'s mode ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0x11), mac(0x21)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, COMPAT)
    wire = Wire()
    wire.answers[ip] = {squatter}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    text = ' '.join(cap.grep(f'IP conflict on {ip}', 'ERROR'))
    free = text.split(f'--static {lessee}=')[-1].split(',')[0]
    check('keeps the lessee\'s compat option', f'--static {lessee}={free},compat'
          in text, text)
    check('compat lessee is offered a /30-aligned client address',
          free != text and int(ipaddress.IPv4Address(free)) % 4 == 2 and
          all(str(ipaddress.IPv4Address(
              (int(ipaddress.IPv4Address(free)) & ~3) + i)) in lm.free_ips
              for i in range(4)), free)
    restore_time()

print('--- 6. static lessee gets the move-the-reservation remedy ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0x10), mac(0x20)
    lm = make_lm(td, static_map={lessee: ('192.168.99.50', 'cam')})
    wire = Wire()
    wire.answers['192.168.99.50'] = {squatter}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    text = ' '.join(cap.grep('IP conflict on 192.168.99.50', 'ERROR'))
    check('suggests moving the reservation',
          'move the reservation' in text and f'--static {lessee}=' in text
          and f'--static {squatter}=192.168.99.50' in text, text)
    restore_time()

print('--- 8. our own MACs and the lessee never count ---')
with tempfile.TemporaryDirectory() as td:
    compat = mac(0x40)
    lm = make_lm(td, static_map={compat: ('192.168.99.10', 'printer')},
                 compat_macs={compat})
    wire = Wire()
    wire.answers['192.168.99.9'] = {SERVER_MAC, OTHER_OWN_MAC}  # gw alias
    wire.answers['192.168.99.10'] = {compat}
    wire.answers['192.168.99.1'] = {OTHER_OWN_MAC}
    sw = make_sweeper(lm, wire)
    for _ in range(int(sw.REST_PERIOD / sw.interval) + 1):
        sw.sweep()
    check('no finding', not sw.conflicts, sw.conflicts)
    check('the /30 gateway was actually probed',
          any(ip == '192.168.99.9' for _, ip, _, _ in wire.sent))
    psrcs = {p for _, ip, p, _ in wire.sent if ip == '192.168.99.10'}
    check('a compat client is asked from its own /30 gateway',
          psrcs == {'192.168.99.9'}, psrcs)
    psrcs = {p for _, ip, p, _ in wire.sent if ip in ('192.168.99.9',
                                                      '192.168.99.1')}
    check('our own addresses are asked from 0.0.0.0, never from themselves',
          psrcs == {'0.0.0.0'}, psrcs)
    restore_time()

print('--- 9. a foreign MAC on a /30 gateway is a conflict with us ---')
with tempfile.TemporaryDirectory() as td:
    compat, other = mac(0x40), mac(0x41)
    lm = make_lm(td, static_map={compat: ('192.168.99.10', 'printer')},
                 compat_macs={compat})
    wire = Wire()
    wire.answers['192.168.99.9'] = {SERVER_MAC, other}
    sw = make_sweeper(lm, wire)
    for _ in range(int(sw.REST_PERIOD / sw.interval) + 1):
        sw.sweep()
    check('reported as reserved-address conflict',
          [c['kind'] for c in sw.conflicts.values()] == ['reserved'],
          sw.conflicts)
    check('infrastructure address not put in the pool',
          '192.168.99.9' not in lm.free_ips and
          '192.168.99.9' not in lm.quarantine)
    restore_time()

print('--- 10. two MACs answering for each other are still a conflict ---')
with tempfile.TemporaryDirectory() as td:
    nic1, nic2 = mac(0x50), mac(0x51)
    lm = make_lm(td)
    a = lm.allocate_or_renew(nic1, 'multi', STD)
    b = lm.allocate_or_renew(nic2, 'multi', STD)
    wire = Wire()
    wire.answers[a] = {nic1, nic2}
    wire.answers[b] = {nic1, nic2}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    check('mutual: still a conflict, since ARP cannot prove one host',
          {c['kind'] for c in sw.conflicts.values()} == {'conflict'} and
          all(c['mutual'] for c in sw.conflicts.values()), sw.conflicts)
    check('mutual: said once per pair, at WARNING, offering two interfaces',
          len(cap.grep('arp_ignore=1', 'WARNING')) == 2 and
          not cap.grep('IP conflict', 'ERROR'), cap.records[-4:])
    cap.records.clear()
    for _ in range(3):
        wire.now += sw.REMIND
        sw.sweep()
    check('mutual: not repeated while nothing changes',
          not cap.grep('arp_ignore') and not cap.grep('IP conflict'),
          cap.records[-3:])
    wire.answers[b] = {nic2}       # one side stops answering for the other
    sw.sweep()
    check('mutual: one lost answer does not undo it',
          not cap.grep('IP conflict') and
          sw.conflicts[(a, nic2)]['mutual'], cap.records[-3:])
    for _ in range(sw.SILENT_SWEEPS):
        sw.sweep()
    check('mutual: once the other side is cleared, it is a one-sided conflict',
          cap.grep(f'IP conflict on {a}', 'ERROR') and
          (b, nic1) not in sw.conflicts, cap.records[-3:])
    restore_time()
with tempfile.TemporaryDirectory() as td:
    nic1, nic2 = mac(0x54), mac(0x55)
    lm = make_lm(td)
    a = lm.allocate_or_renew(nic1, 'multi', STD)
    b = lm.allocate_or_renew(nic2, 'multi', STD)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    for k in range(40):     # every other sweep loses one side's answer
        wire.answers[a] = {nic1, nic2}
        wire.answers[b] = {nic2} if k % 2 else {nic1, nic2}
        sw.sweep()
    check('mutual: intermittent loss is not an ERROR, and said once',
          not cap.grep('IP conflict', 'ERROR') and
          len(cap.grep('arp_ignore=1', 'WARNING')) == 2, cap.records[-4:])
    restore_time()
with tempfile.TemporaryDirectory() as td:
    victim, spoofer = mac(0x52), mac(0x53)
    lm = make_lm(td)
    a = lm.allocate_or_renew(victim, None, STD)
    b = lm.allocate_or_renew(spoofer, None, STD)
    wire = Wire()
    wire.answers[a] = {victim, spoofer}
    wire.answers[b] = {spoofer}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    text = ' '.join(cap.grep(f'IP conflict on {a}', 'ERROR'))
    check('one-sided: a conflict, at ERROR, mentioning spoofing',
          [c['kind'] for c in sw.conflicts.values()] == ['conflict'] and
          'spoofing' in text and 'arp_ignore' not in text,
          (sw.conflicts, text))
    restore_time()

print('--- 7. squatter on a free address: reported, allocation untouched ---')
with tempfile.TemporaryDirectory() as td:
    squatter = mac(0x20)
    lm = make_lm(td)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    wire = Wire()
    wire.answers[target] = {squatter}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    text = ' '.join(cap.grep(f'{target} is free', 'ERROR'))
    check('reported at ERROR, with the remedy for a legitimate device',
          f'--static {squatter}={target}' in text and 'DHCP' in text, text)
    check('visible to diagnostics as unleased',
          sw.conflicts.get((target, squatter), {}).get('kind') == 'unleased',
          sw.conflicts)
    check('alert only: the address stays in the pool', target in lm.free_ips)
    check('nothing about it is written to the lease file',
          set(json.load(open(os.path.join(td, 'leases.json')))) <=
          {'leases', 'subnets', 'released'})
    del wire.answers[target]
    for _ in range(sw.SILENT_SWEEPS):
        sw.sweep()
    check('cleared once silent', not sw.conflicts, sw.conflicts)
    restore_time()

print('--- 7b. the former holder of a lapsed lease: probed first, by unicast too ---')
with tempfile.TemporaryDirectory() as td:
    old = mac(0x72)
    lm = make_lm(td)
    for i in range(20):
        lm.allocate_or_renew(mac(0x700 + i), None, STD)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    ip = lm.allocate_or_renew(old, None, STD)
    lm.leases[old]['expires'] = wire.now - 1
    lm.get_expired_leases()
    wire.answers[ip] = {old}
    wire.deaf.add(old)           # it only hears the unicast
    cap.records.clear()
    sw.sweep()
    check('probed first', wire.broadcasts()[0][1] == ip, wire.broadcasts()[:2])
    check('the former holder is asked by unicast',
          {d for _, i, _, d in wire.sent if i == ip and d} == {old})
    check('diagnosed as carrying on after its lease ran out',
          cap.grep('ran out and was never renewed', 'ERROR'), cap.records[-3:])
    got = lm.allocate_or_renew(old, None, STD)
    check('gets it back when it asks', got == ip, (got, ip))
    restore_time()

print('--- 11. proxy ARP: one finding, not one per address ---')
with tempfile.TemporaryDirectory() as td:
    proxy, lessee = mac(0x60), mac(0x61)
    lm = make_lm(td)
    lip = lm.allocate_or_renew(lessee, None, STD)

    class ProxyWire(Wire):
        on = True

        def send(self, ip, psrc, dst=None):
            super().send(ip, psrc, dst)
            if self.on and dst in (None, proxy):
                self.pending.append((ip, proxy))
    wire = ProxyWire()
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    check('flagged as proxy-ARP', proxy in sw.proxies and
          cap.grep('proxy-ARP host', 'ERROR'))
    check('no finding per free address',
          not [k for k, c in sw.conflicts.items() if c['kind'] == 'unleased'],
          len(sw.conflicts))
    check('still reported for the leased address it answers for',
          sw.conflicts.get((lip, proxy), {}).get('kind') == 'proxy_arp',
          sw.conflicts)
    wire.on = False
    sw.sweep()
    check('classification lapses when it stops', proxy not in sw.proxies)
    restore_time()
with tempfile.TemporaryDirectory() as td:
    victim = mac(0x62)
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    sw.sweep()
    # Forged answers in the victim's name for a few addresses must not get
    # the victim ignored: it is nowhere near answering for most of the pool.
    with lm.lock:
        some = lm.next_candidates(sw.PROXY_MIN)[:sw.PROXY_MIN]
    for ip in some:
        wire.answers[ip] = {victim}
    sw.sweep()
    check('a few forged answers do not make a proxy',
          victim not in sw.proxies and
          len([k for k in sw.conflicts if k[1] == victim]) == len(some),
          (sw.proxies, len(sw.conflicts)))
    restore_time()

# ------------------------------------------------------------- robustness
print('--- 12. probes never claim an address the server does not use ---')
with tempfile.TemporaryDirectory() as td:
    gone, z, y = mac(0x570), mac(0x571), mac(0x572)
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    ip = lm.allocate_or_renew(gone, None, COMPAT)
    block = [str(x) for x in ipaddress.IPv4Network(
        lm.subnet_leases[gone]['subnet'])]
    lm.leases[gone]['expires'] = wire.now - 1
    lm.get_expired_leases()
    # Somebody else now holds the block's former gateway address.
    lm.free_ips.discard(block[1])
    lm.leases[z] = {'ip': block[1], 'expires': wire.now + 3600,
                    'mode': 'standard', 'masq': False}
    lm.ip_to_mac[block[1]] = z
    wire.answers[ip] = {gone}
    for _ in range(int(sw.REST_PERIOD / sw.interval) + 1):
        sw.sweep()
    with lm.lock:
        mine = {SERVER, '0.0.0.0'} | \
            {d['gateway'] for d in lm.subnet_leases.values()}
    bad = [(i, p) for _, i, p, _ in wire.sent if p == i or p not in mine]
    check('every request is from 0.0.0.0 or an address the server uses, '
          'never from its target', not bad, bad[:4])
    check('the lapsed block was actually probed',
          any(i in block for _, i, _, _ in wire.sent))
    restore_time()

print('--- 13. hostile input: floods and failures stay bounded ---')
with tempfile.TemporaryDirectory() as td:
    lessee = mac(0x80)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    wire.answers[ip] = {lessee} | {mac(0x1000 + i) for i in range(300)}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    # Literal bound, not the class constant: a raised cap must fail here.
    check('only a few MACs per probe considered',
          len(sw.conflicts) <= 4, len(sw.conflicts))
    check('log lines per sweep bounded',
          len(cap.records) <= 2 * 16 + 3, len(cap.records))
    real = sw.evaluate
    calls = []

    def flaky(i, heard, flooded, st):
        calls.append(i)
        if len(calls) == 1:
            raise TypeError('malformed')
        return real(i, heard, flooded, st)
    sw.evaluate = flaky
    sw.sweep()
    check('one failing probe does not end the sweep', len(calls) > 1 and
          sw.last_sweep and sw.last_sweep['probed'] == len(calls),
          (len(calls), sw.last_sweep))
    restore_time()
print('--- 14. replies are parsed strictly ---')
ours = bytes.fromhex(SERVER_MAC.replace(':', ''))
sender = bytes.fromhex('020000000099')


def frame(dst=ours, htype=b'\x00\x01', hlen=b'\x06', op=b'\x00\x02',
          ip=b'\xc0\xa8\x63\x05', extra=b'', sha=sender, tha=ours):
    return (dst + sha + b'\x08\x06' + htype + b'\x08\x00' + hlen +
            b'\x04' + op + sha + extra + ip + tha + b'\xc0\xa8\x63\x01')


check('valid reply parsed',
      iso.parse_arp_reply(frame(), ours) == ('192.168.99.5',
                                             '02:00:00:00:00:99'))
check('a 7-byte hardware address is refused',
      iso.parse_arp_reply(frame(hlen=b'\x07', extra=b'\x00'), ours) is None)
check('a request is refused',
      iso.parse_arp_reply(frame(op=b'\x00\x01'), ours) is None)
check('a reply to somebody else is refused',
      iso.parse_arp_reply(frame(dst=b'\x02' * 6, tha=b'\x02' * 6), ours)
      is None)
check('a broadcast reply addressed to us inside is accepted',
      iso.parse_arp_reply(frame(dst=b'\xff' * 6), ours) is not None)
check('a broadcast reply addressed to somebody else is refused',
      iso.parse_arp_reply(frame(dst=b'\xff' * 6, tha=b'\x02' * 6), ours)
      is None)
check('a group sender address is refused',
      iso.parse_arp_reply(frame(sha=b'\x01\x00\x5e\x00\x00\x01'), ours)
      is None and iso.parse_arp_reply(frame(sha=b'\xff' * 6), ours) is None)
check('a truncated frame is refused',
      iso.parse_arp_reply(frame()[:30], ours) is None)

# ------------------------------------------------------------------ bounds
print('--- 15. bounded by construction on a large pool ---')
with tempfile.TemporaryDirectory() as td:
    big = '10.20.0.0/16'
    lm = iso.LeaseManager(big, '10.20.0.1', os.path.join(td, 'l.json'), 3600,
                          sys_integrator=FakeSys())
    for i in range(30):
        lm.allocate_or_renew(mac(0x100 + i), None, STD)
    wire = Wire()
    sw = make_sweeper(lm, wire, interval=900, rate=2.0)
    check('no full sweep above a /23 without the flag', not sw.full_pool)
    plan = sw.plan()
    check('only leases, candidates, lapsed and suspect addresses are probed',
          len(plan) <= 30 + 3 * 8 + 4, len(plan))
    wire = Wire()
    sw = make_sweeper(lm, wire, interval=900, rate=2.0, full_pool=True)
    t0 = wire.now
    sw.sweep()
    times = [t for t, *_ in wire.broadcasts()]
    gaps = [b - a for a, b in zip(times, times[1:])]
    check('never faster than the rate cap', min(gaps) >= 0.5 - 1e-9,
          min(gaps))
    check('a sweep fits its interval', wire.now - t0 <= 1.2 * 900,
          wire.now - t0)
    sw = make_sweeper(lm, wire, interval=60, rate=10.0, max_per_sweep=10000)
    check('rate is clamped to MAX_RATE', sw.rate == iso.ArpSweeper.MAX_RATE)
    check('rate cap also bounds the budget',
          sw.budget() <= 60 * iso.ArpSweeper.MAX_RATE, sw.budget())
    restore_time()

print('--- 15a. a quick unicast answer does not speed the sweep up ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire, rate=0.5, interval=900)
    with lm.lock:
        cand = lm.next_candidates(4)
    for ip in cand:
        wire.answers[ip] = {mac(0x400)}
    sw.sweep()                   # now they are findings: known responders
    wire.sent.clear()
    sw.sweep()
    check('known responders are asked by unicast',
          any(d for _, i, _, d in wire.sent if i in cand))
    times = [t for t, *_ in wire.broadcasts()]
    gaps = [b - a for a, b in zip(times, times[1:])]
    check('never faster than the rate cap with known responders',
          gaps and min(gaps) >= 2.0 - 1e-9, min(gaps) if gaps else None)
    restore_time()

print('--- 15b. on a small pool the rest is trickled, not swept whole ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        cand = set(lm.next_candidates(sw.candidates))
    plan = sw.plan()
    # A /24 at the defaults: 256 addresses over a 4 h pass, 15 min apart.
    check('per sweep, only a slice of the rest', len(set(plan) - cand) <= 16,
          len(set(plan) - cand))
    seen = set()
    for _ in range(int(14400 / 900)):
        seen |= set(sw.plan())
    check('a full pass covers every host address in REST_PERIOD',
          len(seen) >= 253, len(seen))
    restore_time()

print('--- 16. findings are probed before leases ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    for i in range(40):
        lm.allocate_or_renew(mac(0x200 + i), None, STD)
    wire = Wire()
    sw = make_sweeper(lm, wire, max_per_sweep=30, candidates=1)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    wire.answers[target] = {mac(0x300)}
    sw.sweep()
    check('found', (target, mac(0x300)) in sw.conflicts)
    sw.candidates = 0
    probed = 0
    for _ in range(10):
        n = len(wire.sent)
        sw.sweep()
        probed += any(ip == target for _, ip, _, _ in wire.sent[n:])
    check('an open finding is probed every sweep even when leases fill it',
          probed == 10, probed)
    leased = set(lm.ip_to_mac)
    seen = set()
    for _ in range(6):
        seen |= set(sw.plan())
    check('all leases still covered in rotation', leased <= seen,
          len(leased - seen))
    restore_time()

print('--- 17. a conflict whose lease ends becomes an unleased finding ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0x90), mac(0x91)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    wire.answers[ip] = {lessee, squatter}
    sw = make_sweeper(lm, wire)
    sw.sweep()
    lm.release(lessee)
    wire.answers[ip] = {squatter}       # the lessee has gone
    sw.sweep()
    check('same pair, now unleased',
          {k: c['kind'] for k, c in sw.conflicts.items()} ==
          {(ip, squatter): 'unleased'}, sw.conflicts)
    restore_time()

print('--- 19. a contested lease: no unicast to the other device, cache restored at once ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0xa0), mac(0xa1)
    lm = make_lm(td)
    for i in range(10):
        lm.allocate_or_renew(mac(0xa10 + i), None, STD)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    wire.answers[ip] = {lessee, squatter}
    restored, guarded = [], []
    sw = make_sweeper(lm, wire, restore=lambda i, m: restored.append(
        (i, m, len(wire.broadcasts()))) or True,
        guard=lambda i, m: guarded.append((i, m, len(wire.broadcasts()))))
    sw.sweep()
    sw.sweep()
    check('nobody is asked by unicast for a leased address',
          not [d for _, i, _, d in wire.sent if i == ip and d], wire.sent[:3])
    probe_no = [n for n, x in enumerate(wire.broadcasts(), 1) if x[1] == ip]
    bc = wire.broadcasts()
    leased_probes = [n for n, x in enumerate(bc, 1) if x[1] in lm.ip_to_mac]
    check('every leased address has its entry refreshed just before its probe',
          all((bc[n - 1][1], n - 1) in {(i, k) for i, _, k in guarded}
              for n in leased_probes) and
          all(lm.ip_to_mac[i] == m for i, m, _ in guarded), guarded[:3])
    during = {}
    for i, _, k in guarded:
        if k and bc[k - 1][1] == i:
            during[k] = during.get(k, 0) + 1
    check('and again throughout its window, more often than the lock time',
          all(during.get(n, 0) >= 3 for n in leased_probes),
          (during, leased_probes[:5]))
    check('but not once the window is over',
          all(bc[k - 1][1] == i or (k < len(bc) and bc[k][1] == i)
              for i, _, k in guarded if k), guarded[:5])
    check('and no unleased one',
          all(i in lm.ip_to_mac for i, _, _ in guarded))
    check('the neighbour entry is pointed back right after the probe',
          [(i, m) for i, m, _ in restored] == [(ip, lessee)] * 2 and
          [n for _, _, n in restored] == probe_no, (restored, probe_no))
    restore_time()

print('--- 20. a sweep that hears no lessees clears nothing ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    for i in range(8):
        lm.allocate_or_renew(mac(0xb0 + i), None, STD)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    wire.answers[target] = {mac(0xbf)}
    sw.sweep()
    del wire.answers[target]
    wire.mute_lessees = True
    cap.records.clear()
    for _ in range(sw.SILENT_SWEEPS + 1):
        sw.sweep()
    check('blind: the finding stays', (target, mac(0xbf)) in sw.conflicts)
    check('blind: said so at ERROR, once',
          len(cap.grep('hears no replies', 'ERROR')) == 1)
    with lm.lock:
        check('blind: visible to diagnostics', sw.snapshot()['blind'])
    wire.mute_lessees = False
    for _ in range(sw.SILENT_SWEEPS):
        sw.sweep()
    check('hearing again: the finding clears', not sw.conflicts, sw.conflicts)
    restore_time()

print('--- 21. a probe window that overflowed proves nothing ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    wire.answers[target] = {mac(0xc0)}
    sw.sweep()
    del wire.answers[target]
    real_recv = wire.recv

    def recv(t):
        out, _ = real_recv(t)
        return out, wire.sent[-1][1] == target
    sw.recv = recv
    for _ in range(sw.SILENT_SWEEPS + 1):
        sw.sweep()
    check('a finding is not cleared by flooded silence',
          (target, mac(0xc0)) in sw.conflicts and not sw.blind, sw.conflicts)
    restore_time()

print('--- 22. this host answering for an address it does not have ---')
with tempfile.TemporaryDirectory() as td:
    lessee = mac(0xc1)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    wire.answers[ip] = {lessee, OTHER_OWN_MAC}
    sw = make_sweeper(lm, wire)
    sw.sweep()
    check('reported as this host answering',
          sw.conflicts.get((ip, OTHER_OWN_MAC), {}).get('kind') == 'host',
          sw.conflicts)
    restore_time()

print('--- 25. noise cannot crowd out an alert ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0xe0), mac(0xe1)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    with lm.lock:
        frees = lm.next_candidates(8)
    for i, f in enumerate(frees):
        wire.answers[f] = {mac(0x2000 + 8 * i + k) for k in range(6)}
    wire.answers[ip] = {lessee, squatter}
    sw = make_sweeper(lm, wire)
    cap.records.clear()
    sw.sweep()
    check('the conflict is logged despite the noise',
          cap.grep(f'IP conflict on {ip}', 'ERROR'), len(cap.records))
    restore_time()

print('--- 27. a declined address is not handed back as a former one ---')
with tempfile.TemporaryDirectory() as td:
    c = mac(0xf2)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(c, None, STD)
    lm.decline_ip(c, ip)
    lm.quarantine[ip] = 0
    lm.process_quarantine_expiry()
    got = lm.allocate_or_renew(c, None, STD)
    check('a client is not given back what it declined', got != ip, got)

print('--- 29. a conflict\'s kind follows what the other device turns out to be ---')
with tempfile.TemporaryDirectory() as td:
    lessee, other = mac(0x500), mac(0x501)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    wire.answers[ip] = {lessee, other}
    sw = make_sweeper(lm, wire)
    sw.sweep()
    first = sw.conflicts.get((ip, other), {}).get('kind')

    class Everywhere(Wire):
        pass
    orig = wire.send

    def send(i, psrc, dst=None):
        orig(i, psrc, dst)
        if dst in (None, other) and (i, other) not in wire.pending:
            wire.pending.append((i, other))
    wire.send = sw.send = send
    sw.sweep()
    check('conflict, then proxy_arp once it answers for everything',
          first == 'conflict' and
          sw.conflicts.get((ip, other), {}).get('kind') == 'proxy_arp',
          (first, sw.conflicts.get((ip, other))))
    restore_time()

print('--- 30. playground addresses are asked from the playground gateway ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td, playground_size=16)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    sw.sweep()
    pg = [(i, p) for _, i, p, _ in wire.sent
          if ipaddress.IPv4Address(i) in lm.playground_subnet and
          i != lm.playground_gateway]
    check('from the playground gateway',
          pg and all(p == lm.playground_gateway for _, p in pg), pg[:3])
    restore_time()

print('--- 34b. a lease that passes to the other device mid-sweep is no conflict ---')
with tempfile.TemporaryDirectory() as td:
    lessee, other = mac(0x531), mac(0x532)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    wire.answers[ip] = {lessee, other}
    sw = make_sweeper(lm, wire)
    real_finish = sw.finish

    def finish(st):
        with lm.lock:
            lm.release(lessee)
            lm.free_ips.discard(ip)
            lm.leases[other] = {'ip': ip, 'expires': wire.now + 3600,
                                'mode': 'standard', 'masq': False}
            lm.ip_to_mac[ip] = other
        return real_finish(st)
    sw.finish = finish
    sw.sweep()
    check('no conflict for the new lessee', not sw.conflicts, sw.conflicts)
    restore_time()

print('--- 35. dropped conflicts are counted per sweep, not forever ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    sw.dropped_conflicts = 5
    sw.sweep()
    check('reset by a sweep that dropped nothing', sw.dropped_conflicts == 0)
    restore_time()

print('--- 36. a socket that keeps failing: paced, reopened once per sweep ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    opened = []

    def broken_send(*a):
        raise OSError('gone')

    def io():
        opened.append(1)
        return broken_send, wire.recv
    sw = make_sweeper(lm, wire, io=io)
    sw.send = broken_send
    t0 = wire.now
    sw.sweep()
    check('reopened once in the sweep', len(opened) == 1, len(opened))
    check('failures are paced, not a tight loop',
          wire.now - t0 >= 19 * 0.5 - 1e-9, wire.now - t0)
    sw.sweep()
    check('the next sweep may reopen again', len(opened) == 2, len(opened))
    restore_time()

print('--- 37. a socket that cannot be opened is retried, not given up ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    tries = []

    class Stop(Exception):
        pass

    def io():
        tries.append(1)
        raise OSError('no socket')

    def sleep(s):
        if len(tries) >= 3:
            raise Stop()
        wire.now += s
    sw = iso.ArpSweeper(lm, SERVER_MAC, io=io, clock=wire.clock, sleep=sleep)
    cap.records.clear()
    try:
        sw.run()
    except Stop:
        pass
    check('retried every interval', len(tries) == 3, len(tries))
    check('said once', len(cap.grep('cannot open its socket', 'ERROR')) == 1)

print('--- 38. --redact hides every MAC, in lists too ---')
r = iso._redact_obj({'arp_sweep': {'proxy_macs': ['02:00:00:00:12:34'],
                                   'conflicts': [{'owner': '02:00:00:00:56:78'}]}})
check('no full MAC left', '12:34' not in json.dumps(r) and
      '56:78' not in json.dumps(r), r)

print('--- 39. a full table gives up a free-address finding for a lease ---')
with tempfile.TemporaryDirectory() as td:
    lessee, squatter = mac(0x3000), mac(0x3001)
    lm = make_lm(td)
    ip = lm.allocate_or_renew(lessee, None, STD)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    sw.MAX_CONFLICTS = 4
    with lm.lock:
        frees = lm.next_candidates(4)
    for i, f in enumerate(frees):
        wire.answers[f] = {mac(0x3100 + i)}
    sw.sweep()
    check('the table is full of free-address findings',
          len(sw.conflicts) == 4 and
          {c['kind'] for c in sw.conflicts.values()} == {'unleased'},
          sw.conflicts)
    wire.answers[ip] = {lessee, squatter}
    cap.records.clear()
    sw.sweep()
    check('a lease conflict still gets in, and is logged',
          (ip, squatter) in sw.conflicts and len(sw.conflicts) == 4 and
          cap.grep(f'IP conflict on {ip}', 'ERROR'), sw.conflicts)
    check('and what was given up is counted', sw.dropped_conflicts >= 1)
    sw.MAX_CONFLICTS = len(sw.conflicts)
    wire.answers[frees[0]] = {mac(0x3200)}
    sw.sweep()
    check('a free-address finding never pushes out a lease conflict',
          (ip, squatter) in sw.conflicts, sw.conflicts)
    restore_time()

print('--- 40. overflowed windows are counted ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    real_recv = wire.recv

    def recv(t):
        out, _ = real_recv(t)
        return out, wire.sent[-1][1] == target
    sw.recv = recv
    sw.sweep()
    check('the last sweep says how many', sw.last_sweep.get('flooded') == 1,
          sw.last_sweep)
    sw.recv = real_recv
    sw.sweep()
    check('and stops saying it', sw.last_sweep.get('flooded') == 0)
    restore_time()

print('--- 41. a damaged MAC from the lease file is never a destination ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        f = sorted(lm.free_ips)[5]
        lm.former[f] = {'mac': 'ff:ff:ff:ff:ff:ff', 'expired': True}
        lm.last_freed[f] = wire.now - 60
        lm.former[sorted(lm.free_ips)[6]] = {'mac': 'garbage', 'expired': True}
    sw.sweep()
    check('no unicast to a group or malformed MAC',
          not [d for _, _, _, d in wire.sent
               if d in ('ff:ff:ff:ff:ff:ff', 'garbage')], wire.sent[:3])
    check('and the address is still probed',
          f in [x[1] for x in wire.broadcasts()])
    restore_time()

print('--- 42. the clock going back does not stop the sweep ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    slept = []

    class Stop(Exception):
        pass

    def sleep(s):
        slept.append(s)
        if len(slept) >= 2:
            raise Stop()
        wire.now += s
    sw = iso.ArpSweeper(lm, SERVER_MAC, io=lambda: (wire.send, wire.recv),
                        clock=wire.clock, sleep=sleep)
    real_sweep = sw.sweep

    def sweep():
        real_sweep()
        wire.now -= 86400       # set back a day during the sweep
    sw.sweep = sweep
    try:
        sw.run()
    except Stop:
        pass
    check('never sleeps longer than an interval',
          slept and max(slept) <= sw.interval, slept)
    restore_time()

print('--- 43. one probe never collects more MACs than it reads ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    with lm.lock:
        target = lm.next_candidates(1)[0]
    sw.recv = lambda t: ([(target, mac(0x4000 + i)) for i in range(100)],
                         False)
    heard, flooded = sw.probe(target, 1.0)
    check('capped, and said to be flooded',
          len(heard) == sw.MAX_REPLIES and flooded, (len(heard), flooded))
    restore_time()

print('--- 44. the guard is renewed within the interface\'s own lock time ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    ip = lm.allocate_or_renew(mac(0x4100), None, STD)
    wire = Wire()
    guarded = []
    sw = make_sweeper(lm, wire, locktime=0.2,
                      guard=lambda i, m: guarded.append(wire.now))
    t0 = wire.now
    sw.probe(ip, 2.0)
    gaps = [b - a for a, b in zip(guarded, guarded[1:])]
    check('never longer apart than half of it',
          gaps and max(gaps) <= 0.1 + 1e-9, gaps[:5])
    restore_time()

print('--- 45. a full table of free-address findings keeps the old ones ---')
with tempfile.TemporaryDirectory() as td:
    lm = make_lm(td)
    wire = Wire()
    sw = make_sweeper(lm, wire)
    sw.MAX_CONFLICTS = 3
    with lm.lock:
        frees = lm.next_candidates(4)
    for i, f in enumerate(frees[:3]):
        wire.answers[f] = {mac(0x4200 + i)}
    sw.sweep()
    old = set(sw.conflicts)
    wire.answers[frees[3]] = {mac(0x4210)}
    sw.sweep()
    check('a new one of the same kind does not push one out',
          set(sw.conflicts) == old and sw.dropped_conflicts == 1,
          (sw.conflicts.keys(), old, sw.dropped_conflicts))
    restore_time()

print('--- 18. the socket layer sends broadcast and unicast who-has ---')
sent = []


class FakeSock:
    def send(self, pkt):
        sent.append(pkt)


iso.conf.L2socket = lambda **kw: FakeSock()
send, recv = iso.arp_socket_io('test0', SERVER_MAC)
send('192.168.99.77', '192.168.99.1')
send('192.168.99.77', '192.168.99.1', '02:00:00:00:00:99')
p, u = sent
check('broadcast frame for discovery',
      p[iso.Ether].dst == 'ff:ff:ff:ff:ff:ff' and p[iso.ARP].op == 1 and
      p[iso.ARP].pdst == '192.168.99.77')
check('unicast frame to a known responder',
      u[iso.Ether].dst == '02:00:00:00:00:99' and
      u[iso.ARP].hwdst == '02:00:00:00:00:99')

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
