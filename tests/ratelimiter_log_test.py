#!/usr/bin/env python3
'''The per-MAC rate limiter must say when it starts dropping a client, once
per episode, so "client never asked" and "client was dropped" can be told
apart in the log -- without logging at the refill rate during a flood.

Run with the venv interpreter:
    python3 tests/ratelimiter_log_test.py [path/to/isodhcp.py]
'''
import importlib.util
import logging
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else \
    os.path.join(HERE, os.pardir, 'isodhcp.py')
spec = importlib.util.spec_from_file_location('isodhcp', SRC)
iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iso)

MAC = '02:00:00:00:00:07'
OK = True


def check(label, cond, detail=''):
    global OK
    print(f'{"PASS" if cond else "FAIL"}: {label}'
          f'{"  -- " + str(detail) if detail and not cond else ""}')
    OK &= bool(cond)


class Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


cap = Capture()
iso.logger.addHandler(cap)
iso.logger.setLevel(logging.DEBUG)


class Clock:
    t = 1000.0


iso.time.time = lambda: Clock.t


def limited_lines():
    return [m for m in cap.records if MAC in m and 'Rate limiting' in m]


rl = iso.RateLimiter(rate=2.0, burst=5)

# A burst beyond the bucket: 5 admitted, the rest dropped, one line.
allowed = sum(rl.is_allowed(MAC) for _ in range(20))
check('burst admits exactly the bucket', allowed == 5, allowed)
check('first episode logged once', len(limited_lines()) == 1, limited_lines())

# A sustained flood: one token trickles in every 0.5 s and is spent at once.
# That must not re-arm the message.
for _ in range(40):
    Clock.t += 0.5
    for _ in range(10):
        rl.is_allowed(MAC)
check('sustained flood does not re-log', len(limited_lines()) == 1,
      len(limited_lines()))

# The client goes quiet long enough to refill, then bursts again: new episode.
Clock.t += 10
sum(rl.is_allowed(MAC) for _ in range(20))
check('new episode after going quiet logs again', len(limited_lines()) == 2,
      len(limited_lines()))

# A well-behaved client is never logged.
cap.records.clear()
other = '02:00:00:00:00:08'
for _ in range(20):
    Clock.t += 1
    rl.is_allowed(other)
check('well-behaved client never logged',
      not [m for m in cap.records if other in m], cap.records)

# A flood of fresh MACs, each limited once, must not become a flood of log.
cap.records.clear()
Clock.t += 100
for i in range(200):
    m = f'02:00:00:00:01:{i:02x}'
    for _ in range(6):
        rl.is_allowed(m)
lines = [x for x in cap.records if 'Rate limiting' in x]
check('flood of limited MACs logs at most once a second',
      len(lines) == 1, len(lines))
Clock.t += 2
rl.is_allowed('02:00:00:00:02:00')
for _ in range(6):
    rl.is_allowed('02:00:00:00:02:00')
lines = [x for x in cap.records if 'Rate limiting' in x]
check('the next line reports how many went unmentioned',
      len(lines) == 2 and '199 more MACs' in lines[-1], lines[-1:])

print('\nALL PASS' if OK else '\nFAILURES PRESENT')
sys.exit(0 if OK else 1)
