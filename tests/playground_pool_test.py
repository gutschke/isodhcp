#!/usr/bin/env python3
'''The playground is a second pool, carved out of the main one at startup.
An address handed back to the wrong pool migrates between the two: the
playground shrinks, and an isolated client can be handed an address inside
the permissive playground subnet.

Addresses are RFC 1918 documentation-style values, unrelated to any real
deployment. Run: python3 tests/playground_pool_test.py [path/to/isodhcp.py]
'''
import importlib.util
import ipaddress
import os
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
PG = '02:00:00:00:00:30'

OK = True


class FakeSys:
    isolation_mode = 'test'
    nft_iso = nft_compat = nft_gw = nft_net = nft_bcast = 'set'
    nft_subnet = nft_playground = nft_playground_subnet = 'set'

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args))
        return record


def check(label, cond, detail=''):
    global OK
    print(f'{"PASS" if cond else "FAIL"}: {label}'
          f'{"  -- " + str(detail) if detail and not cond else ""}')
    OK &= bool(cond)


def pools_disjoint(lm):
    '''The two pools must never share an address, and neither may hold one
    that belongs to the other side of the boundary.'''
    problems = []
    both = lm.free_ips & lm.playground_free_ips
    if both:
        problems.append(f'in both pools: {sorted(both)}')
    strays = [ip for ip in lm.free_ips
              if ipaddress.IPv4Address(ip) in lm.playground_subnet]
    if strays:
        problems.append(f'playground addresses in the main pool: {strays}')
    outside = [ip for ip in lm.playground_free_ips
               if ipaddress.IPv4Address(ip) not in lm.playground_subnet]
    if outside:
        problems.append(f'main addresses in the playground pool: {outside}')
    return problems


def make(tmpdir):
    return iso.LeaseManager(POOL, SERVER, os.path.join(tmpdir, 'leases.json'),
                            3600, sys_integrator=FakeSys(), playground_size=16)


PROFILE = {'mode': iso.ClientClassifier.MODE_PLAYGROUND, 'masq': False}

print('--- 1. a released playground address goes back to the playground ---')
with tempfile.TemporaryDirectory() as td:
    lm = make(td)
    before_main, before_pg = set(lm.free_ips), set(lm.playground_free_ips)
    ip = lm.allocate_or_renew(PG, 'kiosk', PROFILE)
    check('address came from the playground',
          ipaddress.IPv4Address(ip) in lm.playground_subnet, ip)
    check('address is claimed while leased',
          ip not in lm.free_ips and ip not in lm.playground_free_ips)

    lm.release(PG)
    check('address is back in the playground pool',
          ip in lm.playground_free_ips,
          sorted(lm.playground_free_ips, key=ipaddress.IPv4Address)[:3])
    check('address did NOT migrate to the main pool', ip not in lm.free_ips)
    check('both pools are exactly as they started',
          lm.free_ips == before_main and lm.playground_free_ips == before_pg,
          f'main {len(lm.free_ips)} vs {len(before_main)}, '
          f'pg {len(lm.playground_free_ips)} vs {len(before_pg)}')
    check('pools stay disjoint', pools_disjoint(lm) == [], pools_disjoint(lm))

print('--- 2. expiry takes the same path as an explicit release ---')
with tempfile.TemporaryDirectory() as td:
    lm = make(td)
    before_pg = set(lm.playground_free_ips)
    ip = lm.allocate_or_renew(PG, 'kiosk', PROFILE)
    lm.leases[PG]['expires'] = time.time() - 1
    lm.get_expired_leases()
    check('expired address is back in the playground pool',
          ip in lm.playground_free_ips and ip not in lm.free_ips)
    check('playground pool is whole again',
          lm.playground_free_ips == before_pg)
    check('pools stay disjoint', pools_disjoint(lm) == [], pools_disjoint(lm))

print('--- 3. a declined playground address stays out until quarantine ends ---')
with tempfile.TemporaryDirectory() as td:
    lm = make(td)
    before_pg = set(lm.playground_free_ips)
    ip = lm.allocate_or_renew(PG, 'kiosk', PROFILE)
    lm.decline_ip(PG, ip)
    check('quarantined address is allocatable from neither pool',
          ip not in lm.free_ips and ip not in lm.playground_free_ips,
          f'main={ip in lm.free_ips} pg={ip in lm.playground_free_ips}')
    check('address is actually quarantined', ip in lm.quarantine)

    lm.quarantine[ip] = time.time() - 1
    lm.process_quarantine_expiry()
    check('released from quarantine into the playground pool',
          ip in lm.playground_free_ips and ip not in lm.free_ips,
          f'main={ip in lm.free_ips} pg={ip in lm.playground_free_ips}')
    check('playground pool is whole again',
          lm.playground_free_ips == before_pg)
    check('pools stay disjoint', pools_disjoint(lm) == [], pools_disjoint(lm))

print('--- 4. a main-pool client is unaffected ---')
with tempfile.TemporaryDirectory() as td:
    dyn = '02:00:00:00:00:40'
    lm = make(td)
    before_main, before_pg = set(lm.free_ips), set(lm.playground_free_ips)
    ip = lm.allocate_or_renew(dyn, 'laptop',
                              {'mode': iso.ClientClassifier.MODE_STANDARD,
                               'masq': False})
    check('address came from the main pool',
          ipaddress.IPv4Address(ip) not in lm.playground_subnet, ip)
    lm.release(dyn)
    check('address is back in the main pool',
          ip in lm.free_ips and ip not in lm.playground_free_ips)
    check('both pools are exactly as they started',
          lm.free_ips == before_main and lm.playground_free_ips == before_pg)
    check('pools stay disjoint', pools_disjoint(lm) == [], pools_disjoint(lm))

print('--- 5. a compat /30 still returns to the main pool ---')
with tempfile.TemporaryDirectory() as td:
    cm = '02:00:00:00:00:50'
    lm = make(td)
    before_main, before_pg = set(lm.free_ips), set(lm.playground_free_ips)
    ip = lm.allocate_or_renew(cm, 'legacy',
                              {'mode': iso.ClientClassifier.MODE_COMPAT,
                               'masq': True})
    block = [str(x) for x in
             ipaddress.IPv4Network(lm.subnet_leases[cm]['subnet'])]
    lm.release(cm)
    check('whole /30 is back in the main pool',
          all(x in lm.free_ips for x in block), block)
    check('none of it leaked into the playground',
          not any(x in lm.playground_free_ips for x in block))
    check('both pools are exactly as they started',
          lm.free_ips == before_main and lm.playground_free_ips == before_pg)
    check('pools stay disjoint', pools_disjoint(lm) == [], pools_disjoint(lm))

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
