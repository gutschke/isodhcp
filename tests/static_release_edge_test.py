#!/usr/bin/env python3
'''Side cases around the static-release fix: standard /32 statics, a static
client parked on the wrong address, and an operator profile change.
Run: python3 tests/static_release_edge_test.py [path/to/isodhcp.py]'''
import importlib.util, json, os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, os.pardir, 'isodhcp.py')
spec = importlib.util.spec_from_file_location('isodhcp', SRC)
iso = importlib.util.module_from_spec(spec); spec.loader.exec_module(iso)
class FakeSys:
    isolation_mode='test'
    nft_iso=nft_compat=nft_gw=nft_net=nft_bcast=nft_subnet=nft_playground=nft_playground_subnet='set'
    def __init__(self): self.calls=[]
    def __getattr__(self,n):
        def r(*a,**k): self.calls.append((n,a))
        return r
ok=True
def check(l,c,d=''):
    global ok
    print(('PASS' if c else 'FAIL')+': '+l+(('  -- '+str(d)) if (d and not c) else '')); ok &= bool(c)

MAC='02:00:00:00:00:10'; DYN='02:00:00:00:00:20'
# 1. static standard /32
with tempfile.TemporaryDirectory() as td:
    lm=iso.LeaseManager('192.168.99.0/24','192.168.99.1',os.path.join(td,'l.json'),3600,
        sys_integrator=FakeSys(), static_map={MAC:('192.168.99.50','cam')}, masq_macs={MAC})
    lm.allocate_or_renew(MAC,'cam',{'mode':iso.ClientClassifier.MODE_STANDARD,'masq':True})
    lm.release(MAC)
    check('static /32 lease kept', lm.leases.get(MAC,{}).get('ip')=='192.168.99.50')
    check('static /32 not returned to pool', '192.168.99.50' not in lm.free_ips)
    check('static /32 ownership kept', lm.ip_to_mac.get('192.168.99.50')==MAC)

# 2. static client found on the wrong address at startup must still be purged
with tempfile.TemporaryDirectory() as td:
    lf=os.path.join(td,'l.json')
    json.dump({'leases':{MAC:{'ip':'192.168.99.77','expires':9e18,'mode':'standard'}},'subnets':{}}, open(lf,'w'))
    lm=iso.LeaseManager('192.168.99.0/24','192.168.99.1',lf,3600, sys_integrator=FakeSys(),
        static_map={MAC:('192.168.99.50','cam')})
    check('stale address purged', '192.168.99.77' in lm.free_ips and lm.ip_to_mac.get('192.168.99.77') is None,
          (sorted(lm.ip_to_mac.items())))
    check('static address held', lm.leases[MAC]['ip']=='192.168.99.50')

# 3. operator profile change still tears down and rebuilds
with tempfile.TemporaryDirectory() as td:
    s=FakeSys()
    lm=iso.LeaseManager('192.168.99.0/24','192.168.99.1',os.path.join(td,'l.json'),3600,
        sys_integrator=s, static_map={MAC:('192.168.99.10','p')}, compat_macs={MAC}, masq_macs={MAC})
    lm.allocate_or_renew(MAC,'p',{'mode':iso.ClientClassifier.MODE_COMPAT,'masq':True})
    s.calls.clear()
    lm.allocate_or_renew(MAC,'p',{'mode':iso.ClientClassifier.MODE_STANDARD,'masq':False})
    names=[c[0] for c in s.calls]
    check('profile change tears the /30 down', 'del_alias_ip' in names, names)
    check('profile change leaves no /30 record', MAC not in lm.subnet_leases)
    check('profile change keeps the address', lm.leases[MAC]['ip']=='192.168.99.10')
    check('profile change does not free the address', '192.168.99.10' not in lm.free_ips)
print('\nALL PASS' if ok else '\nFAILURES PRESENT')
sys.exit(0 if ok else 1)
