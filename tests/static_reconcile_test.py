#!/usr/bin/env python3
'''Two reconciliation defects around static reservations.

1. A static MAC whose reloaded lease sits on the wrong address: the
   reservation is committed on top of it, leaving the old address indexed to
   that MAC and permanently out of the free pool.
2. An operator profile change releases the reservation and reallocates it,
   but nothing takes the address back out of the free pool, so it can be
   handed to a second client. A static playground address is never taken out
   of the playground rotation at all.

Addresses are RFC 1918 documentation-style values, unrelated to any real
deployment. Run: python3 tests/static_reconcile_test.py [path/to/isodhcp.py]
'''
import importlib.util
import ipaddress
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else \
    os.path.join(HERE, os.pardir, 'isodhcp.py')
spec = importlib.util.spec_from_file_location('isodhcp', SRC)
iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iso)

POOL = '192.168.99.0/24'
SERVER = '192.168.99.1'
MAC = '02:00:00:00:00:10'

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


def index_desync(lm):
    '''The invariant --verify checks: every indexed address belongs to a
    lease that actually holds it.'''
    return sorted(ip for ip, mac in lm.ip_to_mac.items()
                  if lm.leases.get(mac, {}).get('ip') != ip)


def double_allocatable(lm):
    '''No leased address, nor any address of a leased /30, may be free.'''
    bad = set()
    for mac, data in lm.leases.items():
        if data['ip'] in lm.free_ips:
            bad.add(data['ip'])
        sub = lm.subnet_leases.get(mac)
        if sub:
            for x in ipaddress.IPv4Network(sub['subnet']):
                if str(x) in lm.free_ips:
                    bad.add(str(x))
    return sorted(bad)


def write_leases(path, leases, subnets=None):
    json.dump({'leases': leases, 'subnets': subnets or {}}, open(path, 'w'))


def make(tmpdir, **kw):
    kw.setdefault('static_map', {MAC: ('192.168.99.50', 'cam')})
    return iso.LeaseManager(POOL, SERVER, os.path.join(tmpdir, 'leases.json'),
                            3600, sys_integrator=FakeSys(), **kw)


print('--- 1. static MAC reloaded on the wrong address (standard) ---')
with tempfile.TemporaryDirectory() as td:
    lf = os.path.join(td, 'leases.json')
    write_leases(lf, {MAC: {'ip': '192.168.99.77', 'mode': 'standard'}})
    lm = make(td)
    check('reservation is held', lm.leases[MAC]['ip'] == '192.168.99.50')
    check('stale address no longer indexed',
          lm.ip_to_mac.get('192.168.99.77') is None,
          sorted(lm.ip_to_mac.items()))
    check('stale address back in the free pool',
          '192.168.99.77' in lm.free_ips)
    check('no index desync', index_desync(lm) == [], index_desync(lm))

print('--- 2. static MAC reloaded on the wrong /30 (compat) ---')
with tempfile.TemporaryDirectory() as td:
    lf = os.path.join(td, 'leases.json')
    write_leases(lf, {MAC: {'ip': '192.168.99.78', 'mode': 'compat'}},
                 {MAC: {'gateway': '192.168.99.77',
                        'subnet': '192.168.99.76/30'}})
    lm = make(td, static_map={MAC: ('192.168.99.10', 'cam')},
              compat_macs={MAC})
    check('reservation is held', lm.leases[MAC]['ip'] == '192.168.99.10')
    check('reserved /30 is the right one',
          lm.subnet_leases[MAC]['subnet'] == '192.168.99.8/30',
          lm.subnet_leases.get(MAC))
    check('stale address no longer indexed',
          lm.ip_to_mac.get('192.168.99.78') is None,
          sorted(lm.ip_to_mac.items()))
    check('stale /30 back in the free pool',
          all(f'192.168.99.{n}' in lm.free_ips for n in (76, 77, 78, 79)),
          sorted(x for x in lm.free_ips if x.startswith('192.168.99.7')))
    check('no index desync', index_desync(lm) == [], index_desync(lm))

print('--- 3. profile change on a static compat client ---')
with tempfile.TemporaryDirectory() as td:
    lm = make(td, static_map={MAC: ('192.168.99.10', 'p')},
              compat_macs={MAC}, masq_macs={MAC})
    lm.allocate_or_renew(MAC, 'p', {'mode': iso.ClientClassifier.MODE_COMPAT,
                                    'masq': True})
    lm.allocate_or_renew(MAC, 'p', {'mode': iso.ClientClassifier.MODE_COMPAT,
                                    'masq': False})
    check('reservation is held', lm.leases[MAC]['ip'] == '192.168.99.10')
    check('the /30 is not allocatable to anybody else',
          double_allocatable(lm) == [], double_allocatable(lm))

print('--- 4. profile change on a static standard client ---')
with tempfile.TemporaryDirectory() as td:
    lm = make(td, masq_macs={MAC})
    lm.allocate_or_renew(MAC, 'cam', {'mode': iso.ClientClassifier.MODE_STANDARD,
                                      'masq': True})
    lm.allocate_or_renew(MAC, 'cam', {'mode': iso.ClientClassifier.MODE_COMPAT,
                                      'masq': True})
    check('address is not allocatable to anybody else',
          double_allocatable(lm) == [], double_allocatable(lm))

print('--- 5. a dynamic client must still get a pool address back ---')
with tempfile.TemporaryDirectory() as td:
    dyn = '02:00:00:00:00:20'
    lm = make(td)
    ip = lm.allocate_or_renew(dyn, 'laptop',
                              {'mode': iso.ClientClassifier.MODE_STANDARD,
                               'masq': False})
    check('dynamic address claimed', ip not in lm.free_ips)
    lm.release(dyn)
    check('dynamic address released', ip in lm.free_ips)
    check('no index desync', index_desync(lm) == [], index_desync(lm))
    check('nothing double-allocatable', double_allocatable(lm) == [],
          double_allocatable(lm))

print('--- 6. a static playground address must leave the playground rotation ---')
with tempfile.TemporaryDirectory() as td:
    # Ask an unreserved manager where the playground landed, then reserve one
    # of its addresses for a static client.
    probe = iso.LeaseManager(POOL, SERVER, os.path.join(td, 'probe.json'),
                             3600, sys_integrator=FakeSys(),
                             playground_size=16)
    pg_ip = sorted(probe.playground_free_ips, key=ipaddress.IPv4Address)[0]
with tempfile.TemporaryDirectory() as td:
    lm = iso.LeaseManager(POOL, SERVER, os.path.join(td, 'leases.json'), 3600,
                          sys_integrator=FakeSys(), playground_size=16,
                          static_map={MAC: (pg_ip, 'kiosk')})
    lm.allocate_or_renew(MAC, 'kiosk',
                         {'mode': iso.ClientClassifier.MODE_PLAYGROUND,
                          'masq': False})
    check('reservation is held', lm.leases[MAC]['ip'] == pg_ip)
    check('reserved address is out of the playground rotation',
          pg_ip not in lm.playground_free_ips,
          sorted(lm.playground_free_ips, key=ipaddress.IPv4Address)[:4])

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
