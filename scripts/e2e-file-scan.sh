#!/usr/bin/env bash
# End-to-end: every stored file is scanned, and capped. usage: e2e-file-scan.sh <stalwart image>
#
# A real clamd (clamav/clamav 1.4.5, MainThrive's) beside the image, which is started with
# STALWART_FILE_SCAN_CLAMD naming it. Upstream v0.16.24 stores the EICAR test file through both
# WebDAV PUT and JMAP FileNode/set, and lets JMAP store a file past the 25 MiB cap WebDAV enforces
# (both measured). The patch refuses EICAR on both paths and stores nothing, refuses the oversized
# JMAP file, still stores clean files, and fails CLOSED: with clamd gone, an upload is refused.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
CLI=stalwartlabs/cli:1.0.13
CLAM=clamav/clamav:1.4.5_base
NET=e2e-scan-$$; C=e2e-scan-stalwart-$$; AV=e2e-scan-clamd-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$AV" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
pw() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }
ADMIN=$(pw); PA=$(pw)
docker network create "$NET" >/dev/null
docker run -d --name "$AV" --network "$NET" --network-alias clamd "$CLAM" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -e STALWART_FILE_SCAN_CLAMD=clamd:3310 \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
cli() { docker run --rm --network "$NET" -e STALWART_URL=http://stalwart:8080 -e STALWART_USER=admin -e STALWART_PASSWORD="$ADMIN" "$CLI" --no-color "$@"; }
# clamd downloads its signatures on first start; wait for it to answer PING.
docker run --rm --network "$NET" python:3.12-alpine python3 -c "
import socket,time,urllib.request
for _ in range(90):
    try: urllib.request.urlopen('http://stalwart:8080/healthz/ready',timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit('stalwart never became ready')
for _ in range(120):
    try:
        s=socket.create_connection(('clamd',3310),timeout=3); s.sendall(b'zPING\0')
        if s.recv(16).startswith(b'PONG'): break
    except OSError: pass
    time.sleep(5)
else: raise SystemExit('clamd never answered PING')"
id_of() { awk '/Created/ {print $3}'; }
D1=$(cli create Domain --json '{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}' | id_of)
cli create Account/User --json "{\"name\":\"alice\",\"domainId\":\"$D1\",\"credentials\":{\"0\":{\"@type\":\"Password\",\"secret\":\"$PA\"}}}" >/dev/null
probe() { # $1 = phase: scan | down
docker run --rm -i --network "$NET" -e PA="$PA" -e PHASE="$1" python:3.12-alpine python3 - <<'PY'
import base64,json,os,sys,urllib.request,urllib.error
B="http://stalwart:8080"; fails=[]; PHASE=os.environ["PHASE"]
A="Basic "+base64.b64encode(f"alice@one.test:{os.environ['PA']}".encode()).decode()
EICAR=rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
CLEAN=b"a clean file\n"
def req(m,p,body=None,ct=None):
    h={"Authorization":A}; ct and h.update({"Content-Type":ct})
    try:
        with urllib.request.urlopen(urllib.request.Request(B+p,data=body,method=m,headers=h)) as r: return r.status,r.read()
    except urllib.error.HTTPError as e: return e.code,e.read()
def check(ok,msg): print(("PASS " if ok else "FAIL ")+msg); ok or fails.append(msg)
s=json.loads(req("GET","/jmap/session")[1]); acct=s["primaryAccounts"]["urn:ietf:params:jmap:mail"]
up=s["uploadUrl"].replace("{accountId}",acct); up=up[up.index("/jmap"):]
home="/dav/file/alice%40one.test/"
def node(name,payload):
    blob=json.loads(req("POST",up,payload,"application/octet-stream")[1])["blobId"]
    r=json.loads(req("POST","/jmap/",json.dumps({"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:filenode"],
      "methodCalls":[["FileNode/set",{"accountId":acct,"create":{"f":{"name":name,"blobId":blob,"parentId":None}}},"c"]]}).encode(),"application/json")[1])["methodResponses"][0][1]
    return (r.get("notCreated") or {}).get("f",{}).get("type") or "created"
if PHASE=="scan":
    check(req("PUT",home+"clean.txt",CLEAN,"text/plain")[0]==201, "WebDAV: a clean file is stored (201)")
    st=req("PUT",home+"eicar.com",EICAR,"application/octet-stream")[0]
    check(st==403, f"WebDAV: EICAR is refused ({st})")
    check(req("GET",home+"eicar.com")[0]==404, "WebDAV: and nothing was stored")
    check(node("jclean.txt",CLEAN)=="created", "JMAP: a clean file is stored")
    t=node("jeicar.com",EICAR)
    check(t=="forbidden", f"JMAP: EICAR is refused ({t})")
    check(req("GET",home+"jeicar.com")[0]==404, "JMAP: and nothing was stored")
    t=node("big.bin",os.urandom(30*1024*1024))
    check(t=="tooLarge", f"JMAP: a 30 MiB file is refused like WebDAV refuses it ({t})")
else:
    st=req("PUT",home+"later.txt",CLEAN,"text/plain")[0]
    check(st==503, f"WebDAV: with clamd gone, an upload is refused, not stored unscanned ({st})")
    t=node("jlater.txt",CLEAN)
    check(t=="forbidden", f"JMAP: with clamd gone, an upload is refused ({t})")
print("RESULT", "fail" if fails else "pass", len(fails)); sys.exit(1 if fails else 0)
PY
}
rc=0
probe scan || rc=1
docker rm -f "$AV" >/dev/null
probe down || rc=1
exit $rc
