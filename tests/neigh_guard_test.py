#!/usr/bin/env python3
'''guard_neighbour / restore_neighbour / neigh_locktime against a real kernel
neighbour table, in a throwaway network namespace (never the host's own:
the script re-executes itself under unshare first). Documentation-style
addresses.

    python3 tests/neigh_guard_test.py [path/to/isodhcp.py]
Needs unshare(1) and iproute2, and either root or unprivileged user
namespaces; without them it exits 77 (skipped).
'''
import importlib.util, os, socket, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                      os.path.join(HERE, os.pardir, 'isodhcp.py'))
if os.environ.get('NEIGH_TEST_NS') != '1':
    env = dict(os.environ, NEIGH_TEST_NS='1')
    unshare = ['unshare', '-n'] if os.geteuid() == 0 else ['unshare', '-rn']
    try:
        usable = subprocess.call(unshare + ['ip', 'link', 'show', 'lo'],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL) == 0
    except OSError:
        usable = False
    if not usable:
        print('SKIP: cannot create a network namespace here')
        sys.exit(77)
    sys.exit(subprocess.call(unshare + [sys.executable, __file__, SRC],
                             env=env))

spec = importlib.util.spec_from_file_location('isodhcp', SRC)
iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iso)

OK = True
def check(label, cond, detail=''):
    global OK
    print(f'{"PASS" if cond else "FAIL"}: {label}'
          f'{"  -- " + str(detail) if detail and not cond else ""}')
    OK &= bool(cond)

def sh(c):
    return subprocess.run(c, shell=True, capture_output=True,
                          text=True).stdout.strip()

for c in ('ip link set lo up', 'ip link add va type veth peer name vb',
          'ip link add vc type dummy', 'ip link set va up',
          'ip link set vb up', 'ip link set vc up',
          'ip addr add 10.0.0.1/24 dev va', 'ip addr add 10.0.1.1/24 dev vc'):
    subprocess.run(c, shell=True, check=True)
VA = socket.if_nametoindex('va')
IP, A, B = '10.0.0.2', '02:00:00:00:00:aa', '02:00:00:00:00:bb'
show = lambda dev='va': sh(f'ip neigh show {IP} dev {dev} nud all')

print('--- 1. a dynamic entry is refreshed with the lessee, state toggled ---')
sh(f'ip neigh replace {IP} lladdr {B} dev va nud reachable')
check('guard on REACHABLE', iso.guard_neighbour(VA, IP, A) and
      A in show() and 'STALE' in show(), show())
check('guard on STALE', iso.guard_neighbour(VA, IP, A) and
      A in show() and 'REACHABLE' in show(), show())

print('--- 2. a pinned entry is left alone ---')
for nud in ('permanent', 'noarp'):
    sh(f'ip neigh replace {IP} lladdr {A} dev va nud {nud}')
    check(f'guard leaves {nud}', not iso.guard_neighbour(VA, IP, A) and
          nud.upper() in show(), show())
    sh(f'ip neigh replace {IP} lladdr {B} dev va nud {nud}')
    check(f'restore leaves {nud}', not iso.restore_neighbour(VA, IP, A) and
          B in show() and nud.upper() in show(), show())
sh(f'ip neigh del {IP} dev va')

print('--- 3. restore points a moved entry back, and only that ---')
sh(f'ip neigh replace {IP} lladdr {B} dev va nud reachable')
check('moved back', iso.restore_neighbour(VA, IP, A) and A in show(), show())
check('already right: nothing to do', not iso.restore_neighbour(VA, IP, A))
sh(f'ip neigh del {IP} dev va')

print('--- 4. no entry: nothing created ---')
check('guard', not iso.guard_neighbour(VA, IP, A) and not show(), show())
check('restore', not iso.restore_neighbour(VA, IP, A) and not show(), show())

print('--- 5. an entry for the same address on another interface ---')
sh(f'ip neigh replace {IP} lladdr {B} dev vc nud reachable')
check('guard does not act on it',
      not iso.guard_neighbour(VA, IP, A) and not show(), show())
check('restore does not act on it',
      not iso.restore_neighbour(VA, IP, A) and not show(), show())
check('and it is untouched', B in show('vc') and 'REACHABLE' in show('vc'),
      show('vc'))

print('--- 6. lock time ---')
sh('echo 50 > /proc/sys/net/ipv4/neigh/va/locktime')
check('read from the interface', iso.neigh_locktime('va') == 0.5,
      iso.neigh_locktime('va'))
check('kernel default when it cannot be read',
      iso.neigh_locktime('nonexistent0') == 1.0)

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
