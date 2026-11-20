#!/usr/bin/env python3
'''A DHCPDECLINE must not be able to put an address the server uses itself
-- a /30 gateway alias, the server address -- into quarantine, from where
it would come back out as an ordinary free address.

Documentation-style addresses only. Run:
    python3 tests/decline_infra_test.py [path/to/isodhcp.py]'''
import importlib.util
import logging
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
iso.logger.setLevel(logging.CRITICAL)
iso.LeaseManager.is_ip_active_in_arp = lambda self, ip: False

OK = True


def check(label, cond, detail=''):
    global OK
    print(f'{"PASS" if cond else "FAIL"}: {label}'
          f'{"  -- " + str(detail) if detail and not cond else ""}')
    OK &= bool(cond)


class FakeSys:
    isolation_mode = 'test'

    def __getattr__(self, name):
        return lambda *a, **kw: None


COMPAT = {'mode': 'compat', 'masq': False}
STD = {'mode': 'standard', 'masq': False}
with tempfile.TemporaryDirectory() as td:
    lm = iso.LeaseManager('192.168.99.0/24', '192.168.99.1',
                          os.path.join(td, 'l.json'), 3600,
                          sys_integrator=FakeSys())
    client, other = '02:00:00:00:00:10', '02:00:00:00:00:20'
    lm.allocate_or_renew(client, None, COMPAT)
    gw = lm.subnet_leases[client]['gateway']

    lm.decline_ip(other, gw)
    check('a DECLINE of a /30 gateway is ignored', gw not in lm.quarantine)
    lm.decline_ip(other, '192.168.99.1')
    check('a DECLINE of the server address is ignored',
          '192.168.99.1' not in lm.quarantine)

    # Whatever the path into quarantine, expiry must not free them.
    lm.quarantine[gw] = time.time() - 1
    lm.process_quarantine_expiry()
    check('a /30 gateway never comes back as a free address',
          gw not in lm.free_ips, sorted(lm.free_ips)[:3])

    mine = lm.allocate_or_renew(other, None, STD)
    lm.decline_ip(other, mine)
    check('a client can still decline its own lease',
          mine in lm.quarantine and mine not in lm.free_ips)
    free = max(lm.free_ips)
    lm.decline_ip('02:00:00:00:00:30', free)
    check('a free address offered to a client can still be declined',
          free in lm.quarantine)

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
