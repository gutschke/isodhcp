#!/bin/bash
# Run every tests/*_test.py against isodhcp.py (or the file given), and
# report each as PASS, FAIL or SKIP. Exits non-zero if any test failed.
#
#   tests/run_tests.sh [path/to/isodhcp.py]
#
# PYTHON selects the interpreter (default: python3); it needs scapy and
# pyroute2, e.g. from a venv: PYTHON=venv/bin/python tests/run_tests.sh
#
# A test counts as failed if it exits non-zero or prints FAILURES PRESENT or
# a traceback, whatever its exit status. Exit status 77 means skipped (the
# environment cannot run it), and is reported as such, never as a pass.
cd "$(dirname "$0")/.." || exit 1
PY=${PYTHON:-python3}
SRC=$(realpath "${1:-isodhcp.py}") || exit 1
LOGS=$(mktemp -d) || exit 1
pass=0 fail=0 skip=0
for t in tests/*_test.py; do
  n=$(basename "$t" .py)
  "$PY" "$t" "$SRC" > "$LOGS/$n.log" 2>&1
  rc=$?
  if [ $rc = 77 ]; then
    echo "SKIP $n"; skip=$((skip + 1))
  elif [ $rc != 0 ] || grep -q 'FAILURES PRESENT\|Traceback' "$LOGS/$n.log"; then
    echo "FAIL $n (exit $rc)"; grep '^FAIL\|Error' "$LOGS/$n.log" | head -5
    fail=$((fail + 1))
  else
    echo "PASS $n"; pass=$((pass + 1))
  fi
done
echo "$pass passed, $fail failed, $skip skipped (logs in $LOGS)"
[ $fail = 0 ]
