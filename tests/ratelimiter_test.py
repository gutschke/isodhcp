#!/usr/bin/env python3
'''The per-MAC rate limiter: admission, refill, and the bound on how
many clients it tracks. Loads only the RateLimiter class, so it needs
neither scapy nor pyroute2. A failed check raises.
Run: python3 tests/ratelimiter_test.py [path/to/isodhcp.py]'''
import time, threading, logging, re

# Load the REAL RateLimiter class source straight from the file (no scapy needed)
import os, sys
src = open(sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, 'isodhcp.py')).read()
m = re.search(r'\nclass RateLimiter:.*?\nclass LeaseManager:', src, re.S)
assert m, "could not locate RateLimiter class"
class_src = m.group(0).rsplit('\nclass LeaseManager:', 1)[0]

ns = {'threading': threading, 'time': time, 'logging': logging,
      'logger': logging.getLogger('test')}
exec(class_src, ns)
RateLimiter = ns['RateLimiter']

def mac(i): return f'02:00:00:00:00:{i:02x}'

rl = RateLimiter(rate=2.0, burst=5, max_clients=4)

# 1. Fill to cap with distinct MACs -> all admitted
assert all(rl.is_allowed(mac(i)) for i in range(4)), "initial fill should admit"
assert len(rl.clients) == 4

# 2. New MAC at saturation -> fail closed (prune frees nothing, all fresh)
assert rl.is_allowed(mac(99)) is False, "new MAC at cap must be dropped"
assert rl._full_alerted is True, "saturation alert should be set"
assert len(rl.clients) == 4, "dropped MAC must not be inserted"

# 3. Throttle: a second new MAC immediately should NOT rescan (last_prune recent)
lp = rl._last_prune
assert rl.is_allowed(mac(98)) is False
assert rl._last_prune == lp, "prune should be throttled within 1s"

# 4. Existing MAC keeps being served during saturation
served = sum(1 for _ in range(4) if rl.is_allowed(mac(0)))
assert served >= 1, "already-tracked client must still be served during saturation"

# 5. Recovery: age all entries past 1h, cleanup prunes them, alert re-arms
for d in rl.clients.values():
    d['last_update'] = time.time() - 4000
rl.cleanup()
assert len(rl.clients) == 0, "cleanup should drop all stale entries"
assert rl._full_alerted is False, "alert should re-arm after headroom returns"

# 6. After recovery a brand-new MAC is admitted again
assert rl.is_allowed(mac(50)) is True, "new MAC admitted after recovery"

# 7. Per-MAC token bucket still rate-limits a chatty single MAC
rl2 = RateLimiter(rate=2.0, burst=5, max_clients=1000)
allowed = sum(1 for _ in range(100) if rl2.is_allowed(mac(7)))
assert allowed == 5, f"burst should cap a single MAC at 5 back-to-back, got {allowed}"

print("RateLimiter behavior: ALL 7 CHECKS PASSED")
