#!/usr/bin/env python3
'''A conflict found by the ARP sweep shows in --status and turns --verify
red (exit 2) until it clears. Documentation-style addresses only.
Run: python3 tests/arp_diag_test.py [path/to/isodhcp.py]'''
import argparse
import contextlib
import importlib.util
import io
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else \
    os.path.join(HERE, os.pardir, 'isodhcp.py')
spec = importlib.util.spec_from_file_location('isodhcp', SRC)
iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iso)

OK = True


def check(label, cond, detail=''):
    global OK
    print(f'{"PASS" if cond else "FAIL"}: {label}'
          f'{"  -- " + str(detail) if detail and not cond else ""}')
    OK &= bool(cond)


class Fake:
    isolation_mode = 'test'

    def __init__(self, *a, **kw): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def link_lookup(self, **kw): return [1]
    def __getattr__(self, name):
        if name.startswith('nft'): return None   # no nft sets configured
        return lambda *a, **kw: []


iso.get_if_hwaddr = lambda iface: '02:00:00:00:00:01'
iso.IPRoute = Fake
iso.SystemIntegrator = Fake
iso.LeaseManager.is_ip_active_in_arp = lambda self, ip: False

with tempfile.TemporaryDirectory() as td:
    iso.resolve_socket_path = lambda *a, **kw: os.path.join(td, 's')
    srv = iso.UnnumberedDHCPServer(
        'test0', server_ip='192.168.99.1', pool_cidr='192.168.99.0/24',
        dns_server='192.168.99.1', lease_file=os.path.join(td, 'l.json'))
    srv.diag_firewall = lambda req: {}
    lm, sw = srv.lease_mgr, srv.arp_sweeper
    lessee, squatter = '02:00:00:00:00:10', '02:00:00:00:00:20'
    ip = lm.allocate_or_renew(lessee, 'x', {'mode': 'standard', 'masq': False})
    replies = {ip: {lessee, squatter}}
    sw.send = lambda a, psrc, dst=None: setattr(sw, '_last', a)
    sw.recv = lambda t: ([(sw._last, m) for m in replies.get(sw._last, ())],
                         False)
    sw.sweep()

    def verify():
        r = srv.diag_verify({})
        return r, iso._diag_exit_code('verify', r)

    st = srv.diag_status({})
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        iso.render_status(st, argparse.Namespace())
    check('status shows the finding', 'FINDING' in out.getvalue(),
          out.getvalue())
    r, rc = verify()
    kinds = [d['kind'] for d in r['discrepancies'] if d['resource'] == 'arp']
    sev = [d['severity'] for d in r['discrepancies'] if d['resource'] == 'arp']
    check('verify reports it as alarming',
          kinds == ['ip_conflict'] and sev == ['alarming'], (kinds, sev))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        # Only the ARP finding: the fakes leave routes "missing" too, and
        # those rightly earn the hint.
        only = dict(r, discrepancies=[d for d in r['discrepancies']
                                      if d['resource'] == 'arp'])
        iso.render_verify(only, argparse.Namespace(all=False))
    check('no reload hint for an ARP conflict',
          'systemctl reload' not in out.getvalue(), out.getvalue())

    replies[ip] = {lessee}
    for _ in range(sw.SILENT_SWEEPS):
        sw.sweep()
    r, rc = verify()
    check('verify goes green once the squatter is gone',
          not [d for d in r['discrepancies'] if d['resource'] == 'arp'],
          r['discrepancies'])

    srv2 = iso.UnnumberedDHCPServer(
        'test0', server_ip='192.168.99.1', pool_cidr='192.168.99.0/24',
        dns_server='192.168.99.1', lease_file=os.path.join(td, 'l2.json'),
        arp_sweep_interval=0)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        iso.render_status(srv2.diag_status({}), argparse.Namespace())
    check('status says when the sweep is off',
          'ARP sweep: off' in out.getvalue(), out.getvalue())

    # Two lessees answering for each other: listed, but not alarming.
    nic1, nic2 = '02:00:00:00:00:31', '02:00:00:00:00:32'
    a = lm.allocate_or_renew(nic1, None, {'mode': 'standard', 'masq': False})
    b = lm.allocate_or_renew(nic2, None, {'mode': 'standard', 'masq': False})
    replies.update({a: {nic1, nic2}, b: {nic1, nic2}})
    sw.sweep()
    r, rc = verify()
    sev = sorted(d['severity'] for d in r['discrepancies']
                 if d['resource'] == 'arp')
    check('a mutual pair is listed as low, not alarming',
          sev == ['low', 'low'], sev)
    # The lessee leaves and the squatter stays: alarming again.
    lm.release(nic2)
    replies[b] = {nic1}
    sw.sweep()
    r, rc = verify()
    sev = [(d['severity'], d['ip']) for d in r['discrepancies']
           if d['resource'] == 'arp' and d['ip'] == b]
    check('a device answering for a free address is alarming',
          sev == [('alarming', b)], sev)

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
