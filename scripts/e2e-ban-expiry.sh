#!/usr/bin/env bash
# End-to-end: a ban that expires is enforced again when the same address earns a new one.
# usage: e2e-ban-expiry.sh <stalwart image>
#
# With a ban period set, upstream v0.16.24 lifts the first ban on time, but every later ban of that
# address is logged (security.authentication-ban) and NOT enforced: block_ip `insert`s into a set that
# compares by address alone, so the expired entry stays, and the stored entry conflicts and keeps its
# old expiry (measured on a throwaway, 2026-10-02; only a restart or ReloadBlockedIps cleared it).
# Patch 0006 replaces both. All four ban kinds (auth, abuse, loiter, scan) go through block_ip; this
# exercises the auth one. One client container keeps one address throughout.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
CLI=stalwartlabs/cli:1.0.13
NET=e2e-ban-$$; C=e2e-ban-stalwart-$$; K=e2e-ban-client-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
pw() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }
ADMIN=$(pw); PA=$(pw)
docker network create "$NET" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
cli() { docker run --rm --network "$NET" -e STALWART_URL=http://stalwart:8080 -e STALWART_USER=admin -e STALWART_PASSWORD="$ADMIN" "$CLI" --no-color "$@"; }
docker run -d --name "$K" --network "$NET" -e PA="$PA" -e ADMIN="$ADMIN" python:3.12-alpine sleep 600 >/dev/null
docker exec "$K" python3 -c "
import time,urllib.request
for _ in range(90):
    try: urllib.request.urlopen('http://stalwart:8080/healthz/ready',timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit('stalwart never became ready')"
id_of() { awk '/Created/ {print $3}'; }
D1=$(cli create Domain --json '{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}' | id_of)
cli create Account/User --json "{\"name\":\"alice\",\"domainId\":\"$D1\",\"credentials\":{\"0\":{\"@type\":\"Password\",\"secret\":\"$PA\"}}}" >/dev/null
# 3 failures an hour bans for 20 s. Set through JMAP as the admin, then reloaded.
docker exec -i "$K" python3 - <<'PY'
import base64,json,os,urllib.request
B="http://stalwart:8080"; h={"Authorization":"Basic "+base64.b64encode(f"admin:{os.environ['ADMIN']}".encode()).decode(),"Content-Type":"application/json"}
aid=json.load(urllib.request.urlopen(urllib.request.Request(B+"/jmap/session",headers=h)))["primaryAccounts"]["urn:stalwart:jmap"]
r=json.load(urllib.request.urlopen(urllib.request.Request(B+"/jmap/",headers=h,data=json.dumps({"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
  "methodCalls":[["x:Security/set",{"accountId":aid,"update":{"singleton":{"authBanRate":{"count":3,"period":3600000},"authBanPeriod":20000}}},"s"]]}).encode())))
assert "singleton" in (r["methodResponses"][0][1].get("updated") or {}), r
PY
cli create action/ReloadSettings >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,imaplib,json,os,ssl,time,urllib.request
fails=[]
def check(ok,msg): print(("PASS " if ok else "FAIL ")+msg); ok or fails.append(msg)
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
def login(user,pw):
    try:
        M=imaplib.IMAP4_SSL("stalwart",993,ssl_context=ctx,timeout=10); M.login(user,pw); M.logout(); return "ok"
    except imaplib.IMAP4.error: return "refused"      # the server answered NO: not blocked
    except (OSError,imaplib.IMAP4.abort): return "blocked"   # dropped at connect or LOGIN: blocked
good=lambda: login("alice@one.test",os.environ["PA"])
bad=lambda: login("nobody@one.test","wrong")
def blocked_ip():
    B="http://stalwart:8080"; h={"Authorization":"Basic "+base64.b64encode(f"admin:{os.environ['ADMIN']}".encode()).decode(),"Content-Type":"application/json"}
    aid=json.load(urllib.request.urlopen(urllib.request.Request(B+"/jmap/session",headers=h)))["primaryAccounts"]["urn:stalwart:jmap"]
    r=json.load(urllib.request.urlopen(urllib.request.Request(B+"/jmap/",headers=h,data=json.dumps({"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
      "methodCalls":[["x:BlockedIp/query",{"accountId":aid},"q"],["x:BlockedIp/get",{"accountId":aid,"#ids":{"resultOf":"q","name":"x:BlockedIp/query","path":"/ids"}},"g"]]}).encode())))
    return r["methodResponses"][1][1]["list"]
check(good()=="ok", "before any failure, alice signs in")
for _ in range(4): bad()
check(good()=="blocked", "after 4 failures (limit 3/h) the address is banned")
time.sleep(25)
check(good()=="ok", "25 s later (ban period 20 s) the first ban has lifted")
bad()   # the hour's counter is still over the limit, so this one failure earns a new ban
check(good()=="blocked", "one more failure: the address is banned AGAIN and the ban is ENFORCED")
time.sleep(3)
check(good()=="blocked", "3 s later the new ban still holds")
entries=blocked_ip(); now=time.time()
import datetime
exp=[datetime.datetime.fromisoformat(e["expiresAt"].replace("Z","+00:00")).timestamp() for e in entries if e.get("expiresAt")]
check(len(entries)==1 and exp and exp[0]>now, f"exactly one stored ban for the address, expiring in the future ({len(entries)} stored)")
time.sleep(25)
check(good()=="ok", "and the second ban lifts on time too")
print(f"{len(fails)} failure(s)"); raise SystemExit(1 if fails else 0)
PY
