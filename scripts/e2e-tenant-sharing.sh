#!/usr/bin/env bash
# End-to-end: sharing never crosses tenants. usage: e2e-tenant-sharing.sh <stalwart image>
#
# Two tenants stand in for two customers: alice@one.test (tenant one) and bob@two.test (tenant two),
# plus carol@one.test beside alice. Upstream v0.16.24 accepts a JMAP `shareWith` and an IMAP `SETACL`
# naming an account in ANOTHER tenant (DAV and the JMAP directory already refuse that). The patch
# makes both refuse it, answering as for an account that does not exist, and leaves sharing inside
# a tenant working. Every assertion runs in both directions: refused across tenants, allowed within.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
CLI=stalwartlabs/cli:1.0.13
NET=e2e-tenant-$$; C=e2e-tenant-stalwart-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
pw() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }
ADMIN=$(pw); PA=$(pw); PB=$(pw); PC=$(pw)
docker network create "$NET" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
cli() { docker run --rm --network "$NET" -e STALWART_URL=http://stalwart:8080 -e STALWART_USER=admin -e STALWART_PASSWORD="$ADMIN" "$CLI" --no-color "$@"; }
docker run --rm --network "$NET" python:3.12-alpine python3 -c "
import time,urllib.request
for _ in range(90):
    try: urllib.request.urlopen('http://stalwart:8080/healthz/ready',timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit('stalwart never became ready')"
id_of() { awk '/Created/ {print $3}'; }
T1=$(cli create Tenant --json '{"name":"one"}' | id_of); T2=$(cli create Tenant --json '{"name":"two"}' | id_of)
D1=$(cli create Domain --json "{\"name\":\"one.test\",\"memberTenantId\":\"$T1\",\"dkimManagement\":{\"@type\":\"Manual\"},\"dnsManagement\":{\"@type\":\"Manual\"}}" | id_of)
D2=$(cli create Domain --json "{\"name\":\"two.test\",\"memberTenantId\":\"$T2\",\"dkimManagement\":{\"@type\":\"Manual\"},\"dnsManagement\":{\"@type\":\"Manual\"}}" | id_of)
mk() { cli create Account/User --json "{\"name\":\"$1\",\"domainId\":\"$2\",\"memberTenantId\":\"$3\",\"credentials\":{\"0\":{\"@type\":\"Password\",\"secret\":\"$4\"}}}" | id_of; }
mk alice "$D1" "$T1" "$PA" >/dev/null; mk carol "$D1" "$T1" "$PC" >/dev/null; mk bob "$D2" "$T2" "$PB" >/dev/null
docker run --rm -i --network "$NET" -e PA="$PA" -e PB="$PB" -e PC="$PC" python:3.12-alpine python3 - <<'PY'
import base64,imaplib,json,os,ssl,sys,urllib.request,urllib.error
B="http://stalwart:8080"; fails=[]
def sess(u,p):
    a="Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
    return a,json.load(urllib.request.urlopen(urllib.request.Request(B+"/jmap/session",headers={"Authorization":a})))
def call(a,calls,using=("urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail")):
    r=urllib.request.Request(B+"/jmap/",data=json.dumps({"using":list(using),"methodCalls":calls}).encode(),headers={"Authorization":a,"Content-Type":"application/json"})
    return json.load(urllib.request.urlopen(r))["methodResponses"]
def check(ok,msg): print(("PASS " if ok else "FAIL ")+msg); ok or fails.append(msg)
aa,sa=sess("alice@one.test",os.environ["PA"]); ab,sb=sess("bob@two.test",os.environ["PB"]); ac,sc=sess("carol@one.test",os.environ["PC"])
mine=lambda s: s["primaryAccounts"]["urn:ietf:params:jmap:mail"]
alice,bob,carol=mine(sa),mine(sb),mine(sc)
mbs=call(aa,[["Mailbox/get",{"accountId":alice,"properties":["role"]},"m"]])[0][1]["list"]
role={m["role"]:m["id"] for m in mbs}
def share(box,who):
    r=call(aa,[["Mailbox/set",{"accountId":alice,"update":{role[box]:{"shareWith":{who:{"mayReadItems":True}}}}},"s"]])[0][1]
    return r.get("updated") is not None and role[box] in (r.get("updated") or {})
check(not share("inbox",bob), "JMAP: alice cannot share her Inbox with bob (another tenant)")
check(alice not in sess("bob@two.test",os.environ["PB"])[1]["accounts"], "JMAP: bob's session does not gain alice's account")
check(share("sent",carol), "JMAP: alice CAN share her Sent with carol (same tenant)")
check(alice in sess("carol@one.test",os.environ["PC"])[1]["accounts"], "JMAP: carol's session then lists alice's account")
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
M=imaplib.IMAP4_SSL("stalwart",993,ssl_context=ctx); M.login("alice@one.test",os.environ["PA"])
t,d=M._simple_command("SETACL","Drafts","bob@two.test","lr")
check(t!="OK", f"IMAP: SETACL Drafts bob@two.test refused ({t} {d})")
t2,d2=M._simple_command("SETACL","Drafts","nobody@two.test","lr")
check(t!="OK" and str(d)==str(d2), "IMAP: the refusal is the same as for an account that does not exist")
t,d=M._simple_command("SETACL","Drafts","carol@one.test","lr")
check(t=="OK", f"IMAP: SETACL Drafts carol@one.test allowed ({t})")
M.logout()
print("RESULT", "fail" if fails else "pass", len(fails)); sys.exit(1 if fails else 0)
PY
