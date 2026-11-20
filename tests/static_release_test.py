#!/usr/bin/env python3
'''Regression test: a DHCPRELEASE must not dismantle a --static reservation,
while a dynamic lease must still be torn down completely.

Addresses are RFC 1918 documentation-style values, unrelated to any real
deployment. Run: python3 tests/static_release_test.py [path/to/isodhcp.py]
'''
import ipaddress
import importlib.util
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

STATIC_MAC = '02:00:00:00:00:10'
STATIC_IP = '192.168.99.10'          # /30 block 192.168.99.8/30, gw .9
STATIC_BLOCK = [f'192.168.99.{n}' for n in (8, 9, 10, 11)]

DYN_MAC = '02:00:00:00:00:20'


class FakeSys:
    '''Records every system-integration call instead of touching the box.'''
    isolation_mode = 'test'
    nft_iso = nft_compat = nft_gw = nft_net = nft_bcast = 'set'
    nft_subnet = nft_playground = nft_playground_subnet = 'set'

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args))
        return record


def make_manager(tmpdir, sysint):
    return iso.LeaseManager(
        POOL, SERVER, os.path.join(tmpdir, 'leases.json'), 3600,
        sys_integrator=sysint,
        static_map={STATIC_MAC: (STATIC_IP, 'printer')},
        compat_macs={STATIC_MAC}, masq_macs={STATIC_MAC})


def snapshot(lm):
    '''Everything a static reservation consists of.'''
    return {
        'lease': dict(lm.leases.get(STATIC_MAC, {})),
        'subnet': dict(lm.subnet_leases.get(STATIC_MAC, {})),
        'owner': lm.ip_to_mac.get(STATIC_IP),
        'free_overlap': sorted(set(STATIC_BLOCK) & lm.free_ips),
    }


def check(label, cond, detail=''):
    print(f'{"PASS" if cond else "FAIL"}: {label}{" -- " + detail if detail and not cond else ""}')
    return bool(cond)


def main():
    ok = True
    with tempfile.TemporaryDirectory() as tmpdir:
        # --- static compat + masquerade client -------------------------------
        sysint = FakeSys()
        lm = make_manager(tmpdir, sysint)
        profile = {'mode': iso.ClientClassifier.MODE_COMPAT, 'masq': True}
        lm.allocate_or_renew(STATIC_MAC, 'printer', profile)
        before = snapshot(lm)
        sysint.calls.clear()

        lm.release(STATIC_MAC)
        after = snapshot(lm)

        ok &= check('static reservation unchanged by release',
                    before == after, f'{before} != {after}')
        ok &= check('static /30 still recorded',
                    after['subnet'].get('subnet') == '192.168.99.8/30')
        ok &= check('static addresses still out of the free pool',
                    after['free_overlap'] == [])
        ok &= check('static lease still permanent',
                    after['lease'].get('expires') == float('inf'))
        ok &= check('no system teardown for a static client',
                    sysint.calls == [], f'{sysint.calls}')

        # A restart must reproduce exactly the same state.
        sysint2 = FakeSys()
        fresh = make_manager(tmpdir, sysint2)
        fresh_snap = snapshot(fresh)
        ok &= check('state matches what a restart rebuilds',
                    {k: v for k, v in fresh_snap.items() if k != 'lease'} ==
                    {k: v for k, v in after.items() if k != 'lease'} and
                    fresh_snap['lease']['ip'] == after['lease']['ip'] and
                    fresh_snap['lease']['expires'] == after['lease']['expires']
                    and fresh_snap['lease']['masq'] == after['lease']['masq'],
                    f'{fresh_snap} != {after}')

    # --- dynamic client must still be torn down ------------------------------
    with tempfile.TemporaryDirectory() as tmpdir:
        sysint = FakeSys()
        lm = make_manager(tmpdir, sysint)
        profile = {'mode': iso.ClientClassifier.MODE_COMPAT, 'masq': True}
        dyn_ip = lm.allocate_or_renew(DYN_MAC, 'laptop', profile)
        dyn_sub = dict(lm.subnet_leases[DYN_MAC])
        sysint.calls.clear()

        released = lm.release(DYN_MAC)
        names = [c[0] for c in sysint.calls]

        ok &= check('dynamic release returns the address', released == dyn_ip)
        ok &= check('dynamic lease gone', DYN_MAC not in lm.leases)
        ok &= check('dynamic /30 gone', DYN_MAC not in lm.subnet_leases)
        ok &= check('dynamic block returned to the pool',
                    all(str(x) in lm.free_ips
                        for x in ipaddress.IPv4Network(dyn_sub['subnet'])))
        ok &= check('dynamic alias removed', 'del_alias_ip' in names, str(names))
        ok &= check('dynamic nft entries removed',
                    'update_client_nft' in names and
                    'update_compat_block' in names, str(names))
        # update_snat's delete path matches on the client address alone, so the
        # gateway argument is immaterial here; only the delete itself matters.
        ok &= check('dynamic SNAT removed',
                    any(c[0] == 'update_snat' and c[1][0] == 'delete'
                        and c[1][1] == dyn_ip for c in sysint.calls),
                    str(sysint.calls))

    print('\nALL PASS' if ok else '\nFAILURES PRESENT')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
