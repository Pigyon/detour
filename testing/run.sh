#!/usr/bin/env bash
#
# The dynamic suite from TESTING.md, as something that runs.
#
# Every fixture is built here rather than assumed, because the first version of
# this plan listed commands against files that only ever existed in one shell.
# Re-running it in a fresh clone would have failed on the first line.
#
#   ./testing/run.sh           lab and offline checks only
#   ./testing/run.sh --live    also probe the live targets in TESTING.md
#
# Live targets are published practice applications plus one public redirector
# used as a false-positive control. Probing them is rate limited and scoped.

set -uo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
OUT="${OUT:-/tmp/detour-testing}"
LAB_PORT="${LAB_PORT:-20300}"
SITE_PORT="${SITE_PORT:-20500}"
REC_PORT="${REC_PORT:-20860}"
PROXY_PORT="${PROXY_PORT:-20700}"
MIS_PORT="${MIS_PORT:-20800}"
HID_PORT="${HID_PORT:-20900}"
LAB="http://127.0.0.1:${LAB_PORT}"
D="$ROOT/bin/detour"
LIVE=0
[ "${1:-}" = "--live" ] && LIVE=1

pass=0
fail=0
skip=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok()   { pass=$((pass+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
note() { skip=$((skip+1)); printf '  \033[33mSKIP\033[0m %s\n' "$1"; }

# check NAME EXPECTED ACTUAL
check() {
  if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1: expected $2, got $3"; fi
}

# atleast NAME MINIMUM ACTUAL
atleast() {
  if [ "${3:-0}" -ge "$2" ] 2>/dev/null; then ok "$1 ($3)"; else bad "$1: expected at least $2, got ${3:-none}"; fi
}

# findings COUNT-FROM-STDERR: detour prints "N findings" as its last stderr line
findings() { "$@" 2>&1 >/dev/null | tail -1 | awk '{print $1}'; }

# elapsed_ms CMD...: how long CMD took, in milliseconds.
elapsed_ms() {
  local t0 t1
  t0=$(date +%s%3N)
  "$@" >/dev/null 2>&1
  t1=$(date +%s%3N)
  echo $((t1 - t0))
}

# says NAME PATTERN CMD...: run CMD and require PATTERN in what it printed.
#
# Not `cmd | grep -q`: under pipefail a command that exits non-zero fails the
# pipeline even when grep matched, and refusing a bad flag is exactly the case
# where detour exits non-zero. Every check written that way could only fail.
says() {
  local name="$1" pat="$2" out
  shift 2
  out=$("$@" 2>&1)
  if printf '%s' "$out" | grep -qi -- "$pat"; then
    ok "$name"
  else
    bad "$name: $(printf '%s' "$out" | head -2 | tr '\n' ' ')"
  fi
}

# denies NAME PATTERN CMD...: the same, inverted.
denies() {
  local name="$1" pat="$2" out
  shift 2
  out=$("$@" 2>&1)
  if printf '%s' "$out" | grep -qi -- "$pat"; then
    bad "$name: $(printf '%s' "$out" | grep -i -- "$pat" | head -2 | tr '\n' ' ')"
  else
    ok "$name"
  fi
}

cleanup() {
  [ -n "${LAB_PID:-}"  ] && kill "$LAB_PID"  2>/dev/null
  [ -n "${SITE_PID:-}" ] && kill "$SITE_PID" 2>/dev/null
  [ -n "${REC_PID:-}"  ] && kill "$REC_PID"  2>/dev/null
  [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null
  [ -n "${MIS_PID:-}"  ] && kill "$MIS_PID"  2>/dev/null
  [ -n "${HID_PID:-}"  ] && kill "$HID_PID"  2>/dev/null
  return 0
}
trap cleanup EXIT

# ---------------------------------------------------------------- setup

say "setup"
# An interrupted run leaves its listeners behind. They have to go before the
# build, not after it: a lab still running holds bin/detour open, and the
# linker cannot overwrite a running binary.
for p in "$LAB_PORT" "$SITE_PORT" "$REC_PORT" "$PROXY_PORT" "$MIS_PORT" "$HID_PORT"; do
  pid=$(ss -lptnH "sport = :$p" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
done
sleep 1

if ! ( cd "$ROOT" && make build ) >"/tmp/detour-build.log" 2>&1; then
  echo "build failed:"; tail -20 /tmp/detour-build.log; exit 1
fi
rm -rf "$OUT" && mkdir -p "$OUT"

"$D" lab --addr "127.0.0.1:${LAB_PORT}" >/dev/null 2>&1 &
LAB_PID=$!
sleep 2

if ! curl -s -o /dev/null --max-time 5 "$LAB/a01"; then
  echo "lab did not start on ${LAB_PORT}"; exit 1
fi
ok "lab listening on ${LAB_PORT}"

# Scope files. Every run against anything real uses one.
for pair in "127.0.0.1 lab" "brokencrystals.com t1" \
            "public-firing-range.appspot.com t2" "trace.kucoin.com t3" \
            "ginandjuice.shop t4" "out.reddit.com r6"; do
  set -- $pair
  echo "$1" > "$OUT/$2.scope"
done

# The lab's own catalog is the URL list. Building it from --list rather than
# hardcoding keeps it correct when the catalog changes.
"$D" lab --list 2>/dev/null | python3 -c "
import json, sys, urllib.parse
all_u, dec = [], []
for e in json.load(sys.stdin):
    p = e['probe']
    if e.get('param') and '?' not in p:
        p += '?' + e['param'] + '=' + urllib.parse.quote(e.get('probe_value') or 'https://allowed.lab/', '')
    u = '$LAB' + p
    all_u.append(u)
    if e['kind'] == 'decoy':
        dec.append(u)
open('$OUT/lab.txt', 'w').write('\n'.join(all_u) + '\n')
open('$OUT/decoys.txt', 'w').write('\n'.join(dec) + '\n')
"
ok "lab url list: $(wc -l < "$OUT/lab.txt") urls, $(wc -l < "$OUT/decoys.txt") decoys"

# A Burp export and a HAR, so the importers are exercised on real shapes.
cat > "$OUT/burp.xml" <<EOF
<?xml version="1.0"?>
<items>
  <item>
    <url>$LAB/a01?url=https://allowed.lab/</url>
    <request base64="false"><![CDATA[GET /a01?url=https://allowed.lab/ HTTP/1.1
Host: 127.0.0.1:${LAB_PORT}

]]></request>
    <response base64="false"><![CDATA[HTTP/1.1 302 Found
Location: https://allowed.lab/

]]></response>
  </item>
  <item>
    <url>$LAB/a07?url=https://allowed.lab/</url>
    <request base64="false"><![CDATA[GET /a07?url=https://allowed.lab/ HTTP/1.1
Host: 127.0.0.1:${LAB_PORT}

]]></request>
    <response base64="false"><![CDATA[HTTP/1.1 302 Found
Location: https://allowed.lab/

]]></response>
  </item>
</items>
EOF

python3 - <<EOF
import json
entry = lambda u, loc: {
  "startedDateTime": "2026-01-01T00:00:00Z", "time": 1, "cache": {},
  "timings": {"send": 0, "wait": 1, "receive": 0},
  "request": {"method": "GET", "url": u, "httpVersion": "HTTP/1.1",
              "headers": [], "queryString": [], "cookies": [],
              "headersSize": -1, "bodySize": -1},
  "response": {"status": 302 if loc else 200, "statusText": "Found",
               "httpVersion": "HTTP/1.1",
               "headers": [{"name": "Location", "value": loc}] if loc else [],
               "cookies": [], "content": {"size": 0, "mimeType": "text/html"},
               "redirectURL": "", "headersSize": -1, "bodySize": -1}}
har = {"log": {"version": "1.2", "creator": {"name": "detour-testing", "version": "1"},
       "entries": [entry("$LAB/a01?url=https://allowed.lab/", "https://allowed.lab/"),
                   entry("$LAB/b04?next=L2FjY291bnQ%3D", "")]}}
open("$OUT/capture.har", "w").write(json.dumps(har))
EOF

printf '# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/\tFALSE\t0\tlab_session\tauthed\n' > "$OUT/cookies.txt"
echo '{not json' > "$OUT/bad.har"
ok "fixtures written"

# ---------------------------------------------------------------- oracle

say "oracle: the lab is the only target whose answer is known exactly"

"$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --out "$OUT/lab" \
  --rate 200 --concurrency 8 >/dev/null 2>&1

TECH=$(python3 -c "
import json
print(len({json.loads(l)['technique_id'] for l in open('$OUT/lab/findings.jsonl')}))
" 2>/dev/null)
MECH=$(python3 -c "
import json
print(len({json.loads(l)['mechanism'] for l in open('$OUT/lab/findings.jsonl')}))
" 2>/dev/null)
check "L2 distinct techniques" 28 "$TECH"
check "L2 distinct mechanisms" 9 "$MECH"

check "L3 decoys stay silent" 0 "$(findings "$D" attack "$OUT/decoys.txt" --scope-file "$OUT/lab.scope" --rate 200)"

rm -f "$OUT/lab.ckpt"
R1=$(findings "$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --resume "$OUT/lab.ckpt" --rate 200 --concurrency 8)
R2=$(findings "$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --resume "$OUT/lab.ckpt" --rate 200 --concurrency 8)
check "L4 resume keeps its findings" "$R1" "$R2"

"$D" js "$LAB/app/signin" --scope-file "$OUT/lab.scope" >/dev/null 2>&1 \
  && ok "L5 js stage ran" || bad "L5 js stage"

if "$D" js "$LAB/c02" --scope-file "$OUT/lab.scope" --findings 2>/dev/null > "$OUT/c02.jsonl" \
   && [ -s "$OUT/c02.jsonl" ] \
   && "$D" confirm -l "$OUT/c02.jsonl" --scope-file "$OUT/lab.scope" --out "$OUT/c02conf" 2>&1 | grep -q "confirmed"; then
  ok "L7 browser promotes a client-side finding"

  # F8: a promotion the reviewer cannot look at is not much of a promotion.
  atleast "F8 the browser writes artifacts" 1 \
    "$(find "$OUT/c02conf" -name '*.har' -o -name '*.png' 2>/dev/null | wc -l)"
  [ -n "$(ls -A "$OUT/c02conf" 2>/dev/null)" ] && ok "F15 confirm --out writes files" || bad "F15 confirm --out"

  # An artifact nothing points at is an orphan. The report has to name it.
  if find "$OUT/c02conf" \( -name '*.har' -o -name '*.png' \) -printf '%f\n' 2>/dev/null \
     | while read -r a; do grep -qrF -- "$a" "$OUT/c02conf" --include='*.md' --include='*.json' || exit 1; done; then
    ok "F8 every artifact is named in the output"
  else
    bad "F8 an artifact is written but never referenced"
  fi
else
  note "L7 browser (needs Chrome)"
fi

# ---------------------------------------------------------------- filters

say "every mechanism is reportable and the parts sum to the whole"
TOTAL=0
for m in query crlf header host path meta refresh blob hpp js nuclei; do
  n=$(findings "$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --filter "$m" --rate 200 --concurrency 8)
  TOTAL=$((TOTAL + ${n:-0}))
done
WHOLE=$(wc -l < "$OUT/lab/findings.jsonl")
check "F1 filter parts sum to the whole" "$WHOLE" "$TOTAL"
# A bad mechanism has to be refused before any traffic leaves, so this is
# timed as well as checked: it used to run the whole scan first.
t0=$(date +%s)
out=$("$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --filter bogus 2>&1)
printf '%s' "$out" | grep -q 'unknown mechanism'; r=$?
el=$(( $(date +%s) - t0 ))
if [ $r -eq 0 ] && [ $el -le 5 ]; then
  ok "F2 an unknown mechanism is refused up front (${el}s)"
else
  bad "F2 unknown mechanism (exit $r after ${el}s)"
fi

says "F2 an unwritable report directory is refused up front" 'report directory' \
  "$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --out /proc/nope

# ---------------------------------------------------------------- safety

say "safety"

SC=$("$D" scope test https://google.com https://www.google.com 'https://google.com./' \
        https://example.com https://ginandjuice.shop 2>&1)
if [ "$(echo "$SC" | grep -c CANARY)" = 4 ] && echo "$SC" | grep -q 'IN-SCOPE.*ginandjuice'; then
  ok "S1 both destinations refused, including subdomain and trailing dot"
else
  bad "S1 scope guard"; echo "$SC" | sed 's/^/      /'
fi

for bad_dest in '   ' 'https://' 'nonsense' '?a=b'; do
  says "S6 refused destination '$bad_dest'" 'redirect destination' \
    "$D" --redirect-to "$bad_dest" scope test https://example.org
done

# Internal addresses must never enter a payload. The recorder is on loopback,
# so the target's own host is expected and only a foreign internal host fails.
cat > "$OUT/recorder.py" <<'PYEOF'
import http.server, socketserver, signal, sys, urllib.parse
SEEN = []
FOREIGN = ("169.254.169.254", "10.0.0.7", "localhost",
           "metadata.google.internal", "2130706433", "192.168.", "172.16.")
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN.append(self.path)
        self.send_response(200); self.send_header("Content-Length", "2")
        self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
class S(socketserver.ThreadingTCPServer): allow_reuse_address = True
def dump(*a):
    foreign = []
    for path in SEEN:
        q = urllib.parse.urlparse(path).query
        for _, vals in urllib.parse.parse_qs(q, keep_blank_values=True).items():
            for v in vals:
                if ("google.com" in v or "example.com" in v) and any(f in v for f in FOREIGN):
                    foreign.append(v)
    print(len(SEEN), len(foreign))
    sys.stdout.flush(); sys.exit(0)
signal.signal(signal.SIGTERM, dump)
S(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PYEOF

python3 "$OUT/recorder.py" "$REC_PORT" > "$OUT/rec.out" 2>&1 &
REC_PID=$!
sleep 2
printf '%s\n' \
  "http://127.0.0.1:${REC_PORT}/go?url=http://169.254.169.254/latest/meta-data/" \
  "http://127.0.0.1:${REC_PORT}/go?img=http://127.0.0.1:8080/x" \
  "http://127.0.0.1:${REC_PORT}/p?next=http://10.0.0.7/" \
  "http://127.0.0.1:${REC_PORT}/q?u=http://localhost/admin" \
  "http://127.0.0.1:${REC_PORT}/r?d=http://metadata.google.internal/" > "$OUT/internal.txt"
"$D" attack "$OUT/internal.txt" --scope-file <(echo 127.0.0.1) --rate 500 >/dev/null 2>&1
sleep 1; kill -TERM "$REC_PID" 2>/dev/null; sleep 2; REC_PID=""
check "S4 foreign internal hosts in payloads" 0 "$(awk '{print $2}' "$OUT/rec.out")"

PASSIVE=$("$D" "$LAB/a01?url=https://allowed.lab/" --passive --scope-file "$OUT/lab.scope" 2>&1)
echo "$PASSIVE" | grep -q 'no payloads sent' && ok "S5 --passive sends nothing" || bad "S5 --passive"

# ---------------------------------------------------------------- flags

say "flags"

printf '%s\n%s\n' "$LAB/a01?url=https://allowed.lab/" "$LAB/a07?url=https://allowed.lab/" > "$OUT/burp.equiv"
printf '%s\n%s\n' "$LAB/a01?url=https://allowed.lab/" "$LAB/b04?next=L2FjY291bnQ%3D"     > "$OUT/har.equiv"
check "X1 burp xml import matches the same urls as a list" \
  "$(findings "$D" attack "$OUT/burp.equiv" --scope-file "$OUT/lab.scope" --rate 200 --concurrency 8)" \
  "$(findings "$D" attack "$OUT/burp.xml"   --scope-file "$OUT/lab.scope" --rate 200 --concurrency 8)"
check "X2 har import matches the same urls as a list" \
  "$(findings "$D" attack "$OUT/har.equiv"   --scope-file "$OUT/lab.scope" --rate 200 --concurrency 8)" \
  "$(findings "$D" attack "$OUT/capture.har" --scope-file "$OUT/lab.scope" --rate 200 --concurrency 8)"
atleast "X3 stdin" 1 "$(head -3 "$OUT/lab.txt" | "$D" attack - --scope-file "$OUT/lab.scope" --rate 200 2>&1 >/dev/null | tail -1 | awk '{print $1}')"
says "X4 malformed har is a clear error" 'har' \
  "$D" attack "$OUT/bad.har" --scope-file "$OUT/lab.scope"

# X5 is the absent-binary case, so the stub must not be on PATH here.
says "X5 an absent nuclei is a clean no-op" 'nuclei: skipped' \
  env PATH="/usr/bin:/bin" "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") \
  --scope-file "$OUT/lab.scope" --nuclei --rate 200

mkdir -p "$OUT/fakebin"
cat > "$OUT/fakebin/nuclei" <<'NEOF'
#!/bin/sh
echo '{"template-id":"open-redirect","matched-at":"http://example.test/x","info":{"name":"Open Redirect"}}'
NEOF
chmod +x "$OUT/fakebin/nuclei"
PATH="$OUT/fakebin:$PATH" "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") \
  --scope-file "$OUT/lab.scope" --nuclei --out "$OUT/nuc" --rate 200 >/dev/null 2>&1
grep -q '"mechanism":"nuclei"' "$OUT/nuc/findings.jsonl" 2>/dev/null \
  && ok "X6 nuclei results reach the report" || bad "X6 nuclei results"

atleast "F3 --keyword" 1 "$(findings "$D" attack <(echo "$LAB/a07?url=FUZZ") --scope-file "$OUT/lab.scope" --keyword FUZZ --rate 200)"

A=$(findings "$D" attack <(echo "$LAB/oauth/authorize?redirect_uri=https://allowed.lab/callback") --scope-file "$OUT/lab.scope" --rate 200)
B=$(findings "$D" attack <(echo "$LAB/oauth/authorize?redirect_uri=https://allowed.lab/callback") --scope-file "$OUT/lab.scope" --escalate --rate 200)
check "F7 --escalate adds no findings of its own" "$A" "$B"

N=$("$D" select "$OUT/lab.txt" 2>&1 >/dev/null | awk '{print $1}')
V=$("$D" select "$OUT/lab.txt" --vendor-only 2>&1 >/dev/null | awk '{print $1}')
if [ "${V:-0}" -lt "${N:-0}" ]; then ok "F6 --vendor-only narrows ($N to $V)"; else bad "F6 --vendor-only"; fi

cat > "$OUT/cfg.yaml" <<'CEOF'
redirect-to: https://fromfile.example
CEOF
says "F13 --config file layer" CANARY "$D" --config "$OUT/cfg.yaml" scope test https://fromfile.example
says "F13 flag overrides file" CANARY "$D" --config "$OUT/cfg.yaml" --redirect-to https://fromflag.example scope test https://fromflag.example
says "--canary still honoured" CANARY "$D" --canary old.example scope test https://old.example

# A linked site, so crawl depth has something to reach.
rm -rf "$OUT/site" && mkdir -p "$OUT/site/a/b"
echo '<html><body><a href="/a/one.html">1</a><a href="/go?url=https://example.com">g</a></body></html>' > "$OUT/site/index.html"
echo '<html><body><a href="/a/b/two.html">2</a></body></html>' > "$OUT/site/a/one.html"
echo '<html><body><a href="/a/b/three.html">3</a></body></html>' > "$OUT/site/a/b/two.html"
echo '<html><body><a href="/final?u=https://example.com">f</a></body></html>' > "$OUT/site/a/b/three.html"
( cd "$OUT/site" && python3 -m http.server "$SITE_PORT" >/dev/null 2>&1 ) &
SITE_PID=$!
sleep 2

d1=$("$D" harvest "http://127.0.0.1:${SITE_PORT}/" --scope-file <(echo 127.0.0.1) --depth 1 2>&1 >/dev/null | awk '{print $1}')
d3=$("$D" harvest "http://127.0.0.1:${SITE_PORT}/" --scope-file <(echo 127.0.0.1) --depth 3 2>&1 >/dev/null | awk '{print $1}')
if [ "${d3:-0}" -gt "${d1:-0}" ]; then ok "F9 --depth reaches further ($d1 to $d3)"; else bad "F9 --depth ($d1 to $d3)"; fi

s1=$("$D" harvest "http://127.0.0.1:${SITE_PORT}/" --scope-file <(echo 127.0.0.1) --crawl=false 2>&1 >/dev/null | awk '{print $4}')
s2=$("$D" harvest "http://127.0.0.1:${SITE_PORT}/" --scope-file <(echo 127.0.0.1) 2>&1 >/dev/null | awk '{print $4}')
if [ "${s2:-0}" -gt "${s1:-0}" ]; then ok "F16 --crawl adds a source"; else bad "F16 --crawl"; fi

# --concurrency has to matter for a single URL, which is the targeted case.
t1=$(elapsed_ms "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") --scope-file "$OUT/lab.scope" \
       --concurrency 1 --rate 1000 --delay 30ms)
t8=$(elapsed_ms "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") --scope-file "$OUT/lab.scope" \
       --concurrency 16 --rate 1000 --delay 30ms)
if [ "$t8" -lt "$t1" ] && [ "$t1" -lt 300000 ]; then
  ok "F17 --concurrency speeds one url (${t1}ms to ${t8}ms)"
else
  bad "F17 --concurrency (${t1}ms to ${t8}ms)"
fi

"$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") --scope-file "$OUT/lab.scope" \
  --cookies-file "$OUT/cookies.txt" --header 'X-Test: yes' --rate 200 >/dev/null 2>&1 \
  && ok "--cookies-file and --header accepted" || bad "--cookies-file"

says "F12 --log-level debug reports" 'level=DEBUG' \
  "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") --scope-file "$OUT/lab.scope" --log-level debug --rate 200

says "F13 environment layer" CANARY env DETOUR_REDIRECT_TO=https://fromenv.example "$D" scope test https://fromenv.example
says "F13 flag overrides environment" CANARY env DETOUR_REDIRECT_TO=https://fromenv.example "$D" --redirect-to https://fromflag.example scope test https://fromflag.example

# --deep is the difference between probing the parameters a url already has
# and guessing the ones it might accept.
# A name nothing links to, so only brute force can find it.
python3 "$ROOT/testing/hidden.py" "$HID_PORT" >/dev/null 2>&1 &
HID_PID=$!
sleep 2
HID="http://127.0.0.1:${HID_PORT}/x"
n0=$(findings "$D" "$HID" --scope-file <(echo 127.0.0.1) --crawl=false --js=false --rate 500 --concurrency 8)
n1=$(findings "$D" "$HID" --scope-file <(echo 127.0.0.1) --crawl=false --js=false --deep --rate 500 --concurrency 8)
if [ "${n0:-0}" -eq 0 ] && [ "${n1:-0}" -gt 0 ]; then
  ok "F5 --deep finds an unlinked parameter the cheap signals miss (${n0} to ${n1})"
else
  bad "F5 --deep (${n0} to ${n1}, expected 0 then more)"
fi
kill "$HID_PID" 2>/dev/null; HID_PID=""

# F10: the pacing flags have to actually pace.
#
# Timed from the shell rather than parsed out of `time`, and bounded at both
# ends. A run reported once as 10444s, which is longer than the whole suite
# takes: a check that passes on a nonsense measurement cannot catch anything.
q0=$(elapsed_ms "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") --scope-file "$OUT/lab.scope" --rate 200 --concurrency 8)
q1=$(elapsed_ms "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") --scope-file "$OUT/lab.scope" --rate 2 --delay 200ms --concurrency 1)
if [ "$q1" -gt "$q0" ] && [ "$q1" -lt 300000 ]; then
  ok "F10 --rate and --delay slow the run (${q0}ms to ${q1}ms)"
else
  bad "F10 pacing (${q0}ms to ${q1}ms)"
fi

# E2: when every archive is unreachable, harvest has to say so rather than
# return an empty list that reads like a clean result.
says "E2 a total archive failure is reported" 'every source failed' \
  "$D" harvest example.org --scope-file <(echo example.org) --proxy http://127.0.0.1:1

# F15: the commands that offer --out have to write something.
rm -rf "$OUT/out-harvest" "$OUT/out-select" "$OUT/out-js"
"$D" harvest "127.0.0.1:${LAB_PORT}" --scope-file "$OUT/lab.scope" --depth 1 --out "$OUT/out-harvest" >/dev/null 2>&1
"$D" select "$OUT/lab.txt" --out "$OUT/out-select" >/dev/null 2>&1
"$D" js "$LAB/app/signin" --scope-file "$OUT/lab.scope" --out "$OUT/out-js" >/dev/null 2>&1
for c in harvest select js; do
  if [ -n "$(ls -A "$OUT/out-$c" 2>/dev/null)" ]; then ok "F15 $c --out writes files"; else bad "F15 $c --out"; fi
done
[ -n "$(ls -A "$OUT/lab" 2>/dev/null)" ] && ok "F15 attack --out writes files" || bad "F15 attack --out"

# E8: an interrupt without --resume must still report what it proved.
#
# This is the case E7 hides: with a checkpoint the findings survive in the
# file, so a run that threw away everything in memory still looked correct on
# the next pass. Without one, Ctrl-C used to cost the entire scan.
rm -rf "$OUT/stopped"
"$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --out "$OUT/stopped" \
  --rate 500 --concurrency 8 > "$OUT/stopped.out" 2>"$OUT/stopped.err" &
SP=$!
sleep 8; kill -INT "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; rc=$?
atleast "E8 an interrupt still reports its findings" 1 "$(wc -l < "$OUT/stopped.out")"
says "E8 an interrupt says it stopped early" 'stopped early' cat "$OUT/stopped.err"
[ -s "$OUT/stopped/REPORT.md" ] && ok "E8 an interrupt still writes the report" || bad "E8 interrupt wrote no report"
check "E8 an interrupt is not an error exit" 0 "$rc"
denies "E8 a stopped run does not double-wrap its reason" 'worker pool: worker pool' cat "$OUT/stopped.err"

# E7: an interrupted run has to leave a checkpoint the next one can use.
rm -f "$OUT/int.ckpt"
"$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --resume "$OUT/int.ckpt" --rate 200 --concurrency 8 >/dev/null 2>&1 &
AP=$!
sleep 6; kill -INT "$AP" 2>/dev/null; wait "$AP" 2>/dev/null
if [ -s "$OUT/int.ckpt" ]; then
  after=$(findings "$D" attack "$OUT/lab.txt" --scope-file "$OUT/lab.scope" --resume "$OUT/int.ckpt" --rate 200 --concurrency 8)
  check "E7 an interrupted run resumes to the same total" "$WHOLE" "$after"
  atleast "E7 the interrupt left real work recorded" 1 "$(wc -l < "$OUT/int.ckpt")"
else
  bad "E7 interrupt left no checkpoint"
fi

# ---------------------------------------------------------------- failure

say "failure behaviour"

T0=$(date +%s)
"$D" attack <(echo "http://10.255.255.1/go?url=x") --scope-file <(echo 10.255.255.1) --timeout 1s --rate 200 >/dev/null 2>&1
EL=$(( $(date +%s) - T0 ))
if [ "$EL" -le 15 ]; then ok "E1 a blackholed host is fail fast (${EL}s)"; else bad "E1 blackholed host took ${EL}s"; fi

COV=$("$D" attack <(echo "http://127.0.0.1:59999/go?url=x") --scope-file <(echo 127.0.0.1) --rate 200 2>&1 >/dev/null)
echo "$COV" | grep -q '0 of 1 urls answered' && ok "a zero says why" || bad "coverage line"

says "E6 a missing scope file stops the run" 'scope file' \
  "$D" attack "$OUT/lab.txt" --scope-file /nonexistent


# ------------------------------------------------- proxy and credentials

say "what the run actually sent"

python3 "$ROOT/testing/proxy.py" "$PROXY_PORT" "$OUT/proxy.log" >/dev/null 2>&1 &
PROXY_PID=$!
sleep 2

printf '%s\n%s\n' "$LAB/a01?url=https://allowed.lab/" "http://offscope.test/go?url=x" > "$OUT/proxied.txt"
"$D" attack "$OUT/proxied.txt" --scope-file "$OUT/lab.scope" \
  --proxy "http://127.0.0.1:${PROXY_PORT}" \
  --header 'Authorization: Bearer SECRET' --cookies-file "$OUT/cookies.txt" \
  --rate 200 --concurrency 4 >/dev/null 2>&1
sleep 1

PROXIED=$(wc -l < "$OUT/proxy.log")
atleast "F14 every request goes through the proxy" 10 "$PROXIED"

# The destination is what payloads point at. detour must never request it.
check "S2 requests to the redirect destination" 0 \
  "$(awk -F'\t' '$1 ~ /google\.com$/' "$OUT/proxy.log" | wc -l)"
check "S2 requests to a host outside the scope" 0 \
  "$(awk -F'\t' '$1 != "127.0.0.1"' "$OUT/proxy.log" | wc -l)"
check "S3 credentials sent off scope" 0 \
  "$(awk -F'\t' '$1 != "127.0.0.1" && ($2 != "-" || $3 != "-")' "$OUT/proxy.log" | wc -l)"
# Without this the two checks above would pass on an empty header set.
atleast "S3 credentials do reach the host in scope" 1 \
  "$(awk -F'\t' '$1 == "127.0.0.1" && $2 ~ /SECRET/' "$OUT/proxy.log" | wc -l)"

# X7: nuclei has to inherit the same ceiling and the same proxy.
cat > "$OUT/fakebin/nuclei" <<NEOF
#!/bin/sh
echo "\$@" >> "$OUT/nuclei.argv"
echo '{"template-id":"open-redirect","matched-at":"http://example.test/x","info":{"name":"Open Redirect"}}'
NEOF
chmod +x "$OUT/fakebin/nuclei"
PATH="$OUT/fakebin:$PATH" "$D" attack <(echo "$LAB/a01?url=https://allowed.lab/") \
  --scope-file "$OUT/lab.scope" --nuclei --proxy "http://127.0.0.1:${PROXY_PORT}" \
  --rate 3 >/dev/null 2>&1
if grep -q -- "-rate-limit 3" "$OUT/nuclei.argv" && grep -q -- "-proxy http://127.0.0.1:${PROXY_PORT}" "$OUT/nuclei.argv"; then
  ok "X7 nuclei inherits the rate limit and the proxy"
else
  bad "X7 nuclei inherits rate and proxy: $(cat "$OUT/nuclei.argv" 2>/dev/null)"
fi

kill "$PROXY_PID" 2>/dev/null; PROXY_PID=""

# ------------------------------------------------- a host that answers badly

say "a host that answers badly"

python3 "$ROOT/testing/misbehave.py" "$MIS_PORT" > "$OUT/mis.out" 2>&1 &
MIS_PID=$!
sleep 2

for path in ok 403 429; do
  t0=$(date +%s)
  "$D" attack <(echo "http://127.0.0.1:${MIS_PORT}/${path}?url=https://allowed.lab/") \
    --scope-file <(echo 127.0.0.1) --rate 500 --concurrency 4 >/dev/null 2>&1
  eval "T_$path=$(( $(date +%s) - t0 ))"
done

# The request count is only half of it. Halving the rate once per request took
# a requested 500 rps to the 0.1 floor in a dozen refusals, and the same
# eighty-eight requests then took fifteen minutes.
if [ "${T_403:-999}" -le 120 ]; then
  ok "E3 a host that refuses everything does not stall the run (${T_403}s)"
else
  bad "E3 a host refusing everything took ${T_403}s against ${T_ok}s for a healthy one"
fi

# A hostile Refresh header and six malformed meta tags, which is where the
# parser crashed the whole run once before.
denies "E5 hostile Refresh and meta tags survive" 'panic\|goroutine [0-9]* \[' \
  "$D" attack <(echo "http://127.0.0.1:${MIS_PORT}/nasty?url=https://allowed.lab/") \
  --scope-file <(echo 127.0.0.1) --rate 500

T0=$(date +%s)
"$D" attack <(echo "http://127.0.0.1:${MIS_PORT}/slow?url=https://allowed.lab/") \
  --scope-file <(echo 127.0.0.1) --timeout 2s --rate 500 >/dev/null 2>&1
EL=$(( $(date +%s) - T0 ))
if [ "$EL" -le 20 ]; then ok "F11 --timeout bounds a host that never answers (${EL}s)"; else bad "F11 --timeout took ${EL}s"; fi

kill -TERM "$MIS_PID" 2>/dev/null; sleep 2; MIS_PID=""
N_OK=$(awk '$1=="/ok"{print $2}'   "$OUT/mis.out")
N_403=$(awk '$1=="/403"{print $2}' "$OUT/mis.out")
N_429=$(awk '$1=="/429"{print $2}' "$OUT/mis.out")
check "E4 a 403 costs no more requests than a 200" "${N_OK:-0}" "${N_403:-0}"
if [ "${N_429:-0}" -gt 0 ] && [ "${N_429:-0}" -lt "${N_OK:-0}" ]; then
  ok "E3 a host that rate limits is not given the payload matrix (${N_429} vs ${N_OK})"
else
  bad "E3 rate limited host got ${N_429:-0} requests against ${N_OK:-0} for a healthy one"
fi

# ---------------------------------------------------------------- output

say "output"

while read -r verdict rest; do
  [ "$verdict" = PASS ] && ok "$rest" || bad "$rest"
done < <(python3 - <<EOF
import json, glob, re
d = "$OUT/lab"
rep = open(d + "/REPORT.md").read()
fd = sorted(glob.glob(d + "/findings/*"))
one = open(fd[0] + "/REPORT.md").read() if fd else ""
sar = json.load(open(d + "/report.sarif"))
rs = sar["runs"][0]["results"]
rules = {x["id"] for x in sar["runs"][0]["tool"]["driver"]["rules"]}
j = json.load(open(d + "/findings.json"))
body = rep + one + open(d + "/findings.json").read()
for name, good in [
  ("run report groups by endpoint", rep.count("\n## ") > 0),
  ("a report per finding", len(fd) > 0),
  ("proof and remediation present", "## Proof of concept" in one and "## Remediation" in one),
  ("no em dashes in output", chr(8212) not in rep + one),
  ("sarif kind and level conformant", not [r for r in rs if r.get("kind") != "fail" and r.get("level") not in (None, "none")]),
  ("every sarif ruleId resolves", all(r["ruleId"] in rules for r in rs)),
  ("json carries root cause and fingerprint", all("root_cause" in x and "fingerprint" in x for x in j)),
  ("no scoring anywhere", not re.search(r"cvss|severity|score", body, re.I)),
  ("no internal marker leaks", "detour-redirector" not in body),
]:
    print(("PASS " if good else "FAIL ") + name)
EOF
)

# ---------------------------------------------------------------- live

if [ "$LIVE" = 1 ]; then
  say "live targets (published practice apps, rate limited)"

  atleast "T1 brokencrystals" 20 \
    "$(findings "$D" attack <(echo 'https://brokencrystals.com/api/goto?url=https://brokencrystals.com/') \
        --scope-file "$OUT/t1.scope" --rate 5 --timeout 8s)"

  printf '%s\n' \
    'https://public-firing-range.appspot.com/redirect/parameter?url=/' \
    'https://public-firing-range.appspot.com/redirect/parameter/NOSTARTSWITHJS?url=/' \
    'https://public-firing-range.appspot.com/redirect/meta?q=/' > "$OUT/t2.txt"
  "$D" attack "$OUT/t2.txt" --scope-file "$OUT/t2.scope" --out "$OUT/t2" --rate 5 --timeout 8s >/dev/null 2>&1
  M=$(python3 -c "
import json, os
p = '$OUT/t2/findings.jsonl'
print(sum(1 for l in open(p) if json.loads(l)['mechanism'] == 'meta') if os.path.exists(p) else 0)
")
  atleast "T2 firing range meta refresh found" 1 "$M"

  atleast "R1 urldom/redirect" 10 \
    "$(findings "$D" attack <(echo 'https://public-firing-range.appspot.com/urldom/redirect?url=https://example.com') \
        --scope-file "$OUT/t2.scope" --rate 5 --timeout 8s)"

  # The control: a redirector that validates correctly must stay silent.
  check "R6 a correct validator is not reported" 0 \
    "$(findings "$D" attack <(echo 'https://out.reddit.com/?url=https://example.com') \
        --scope-file "$OUT/r6.scope" --rate 3 --timeout 8s)"

  # T3 needs a real archived envelope; a synthetic one returns 400 and proves
  # nothing. It is fetched rather than pinned so no third party's data is
  # stored in this repo, and cached under OUT so a re-run in the same session
  # does not depend on the archive twice. The archive answered on one run and
  # not the next, which is a flaky check, not a flaky tool.
  # Cached outside OUT, which is wiped at the start of every run, so the
  # archive is asked once rather than once per run.
  ENV_CACHE="${TMPDIR:-/tmp}/detour-t3-envelope"
  CDX="http://web.archive.org/cdx/search/cdx?url=trace.kucoin.com*&output=text&fl=original&collapse=urlkey&limit=400"
  if [ ! -s "$ENV_CACHE" ]; then
    for attempt in 1 2 3; do
      raw=$(curl -s --max-time 60 "$CDX" 2>/dev/null)
      printf '%s' "$raw" | grep -m1 -E 'track/click[0-9]*/[A-Za-z0-9_-]{40,}' > "$ENV_CACHE"
      [ -s "$ENV_CACHE" ] && break

      # The archive answers with an HTML outage page rather than an error,
      # which is worth saying out loud: it is not the same as having no
      # envelope to find.
      case "$raw" in
        *"Temporarily Offline"*|*"<html"*) ENV_WHY="the archive is offline" ;;
        *)                                 ENV_WHY="the archive had no envelope" ;;
      esac

      sleep 5
    done
  fi

  if [ -s "$ENV_CACHE" ]; then
    "$D" attack "$ENV_CACHE" --scope-file "$OUT/t3.scope" --out "$OUT/t3" --rate 3 --timeout 8s >/dev/null 2>&1
    grep -q '"mechanism":"blob"' "$OUT/t3/findings.jsonl" 2>/dev/null \
      && ok "T3 opaque envelope decoded and attacked" || bad "T3 opaque envelope"
  else
    note "T3 (${ENV_WHY:-no envelope} after three tries)"
  fi
fi

# ---------------------------------------------------------------- result

say "result"
printf '  %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
