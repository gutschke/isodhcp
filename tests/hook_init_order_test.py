#!/usr/bin/env python3
'''Startup hook events must reach the hook script.

A --static entry that takes an address leased dynamically to another MAC
evicts that lease while LeaseManager is still being constructed, and the
eviction is reported through UnnumberedDHCPServer.execute_hook. If the server
sets up hook_file/base_env only after building the LeaseManager, the callback
fails with an AttributeError (logged as "Hook callback failed") and the 'del'
event never reaches the hook.

Addresses are documentation-style values, unrelated to any real deployment.
Run with the venv interpreter:
    python3 tests/hook_init_order_test.py [path/to/isodhcp.py]
The optional path lets the same test be pointed at an older revision.
'''
import importlib.util
import json
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

POOL = '192.168.99.0/24'
SERVER = '192.168.99.1'
STATIC_MAC = '02:00:00:00:00:10'
DYN_MAC = '02:00:00:00:00:20'
ADDR = '192.168.99.50'

OK = True


def check(label, cond, detail=''):
    global OK
    print(f'{"PASS" if cond else "FAIL"}: {label}'
          f'{"  -- " + str(detail) if detail and not cond else ""}')
    OK &= bool(cond)


class FakeSys:
    isolation_mode = 'test'

    def __init__(self, *a, **kw):
        pass

    def __getattr__(self, name):
        return lambda *a, **kw: None


class FakeIPRoute:
    def __init__(self, *a, **kw):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def link_lookup(self, **kw):
        return [1]

    def __getattr__(self, name):
        return lambda *a, **kw: []


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


with tempfile.TemporaryDirectory() as td:
    lease_file = os.path.join(td, 'leases.json')
    json.dump({'leases': {DYN_MAC: {'ip': ADDR, 'mode': 'standard',
                                    'expires': time.time() + 3600}},
               'subnets': {}}, open(lease_file, 'w'))
    events = os.path.join(td, 'events')
    hook = os.path.join(td, 'hook.sh')
    with open(hook, 'w') as f:
        f.write(f'#!/bin/sh\necho "$@" >> "{events}"\n')
    os.chmod(hook, 0o755)

    iso.get_if_hwaddr = lambda iface: '02:00:00:00:00:01'
    iso.IPRoute = FakeIPRoute
    iso.SystemIntegrator = FakeSys
    iso.resolve_socket_path = lambda *a, **kw: os.path.join(td, 'diag.sock')

    cap = Capture()
    iso.logger.addHandler(cap)
    iso.logger.setLevel(logging.DEBUG)

    srv = iso.UnnumberedDHCPServer(
        'test0', server_ip=SERVER, pool_cidr=POOL, dns_server=SERVER,
        lease_file=lease_file, static_map={STATIC_MAC: (ADDR, 'cam')},
        hook_file=hook)

    # The hook runs asynchronously; give it a moment to write.
    for _ in range(50):
        if os.path.exists(events):
            break
        time.sleep(0.05)
    lines = open(events).read().splitlines() if os.path.exists(events) else []

    failures = [m for m in cap.records if 'Hook callback failed' in m]
    check('static reservation took the address',
          srv.lease_mgr.leases[STATIC_MAC]['ip'] == ADDR)
    check('dynamic lease was evicted', DYN_MAC not in srv.lease_mgr.leases)
    check('eviction is logged',
          any('Evicting dynamic lease' in m and DYN_MAC in m
              for m in cap.records))
    check('no hook callback failure at startup', not failures, failures)
    check('eviction reached the hook as a del event',
          any(l.split()[:3] == ['del', DYN_MAC, ADDR] for l in lines), lines)

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
