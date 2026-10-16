#!/usr/bin/env bash
# End-to-end: the server holds at most STALWART_MAX_LARGE_UPLOADS large request bodies at once, across all accounts.
# usage: e2e-upload-cap.sh <stalwart image>
#
# Each account is bounded upstream (4 requests at once, a pending-upload quota), but nothing bounds the sum: at a 2 GiB
# limit, ~70 parallel 25 MiB uploads from different accounts OOM-kill the process, and every upload and session on it
# is lost (measured on the -nologo1 image, MAI-1000). Patch 0010 counts a body once it passes 1 MiB and refuses one
# past the cap, retryably: WebDAV 429 with Retry-After, JMAP 429. Here the cap is 2: two uploads are held open past
# 1 MiB, a third (WebDAV and JMAP, other accounts) is refused while they are, a small body is not, and once they finish
# the slots are back: the same pattern holds a second time, after a too-large body that was refused mid-way too.
# A refused body is read to its end and dropped, so the client gets the 429, not a reset connection.
# Against -nologo1 the refusals FAIL (it has no cap).
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-cap-$$; C=e2e-cap-stalwart-$$; K=e2e-cap-client-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
ADMIN=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
docker network create "$NET" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -e STALWART_MAX_LARGE_UPLOADS=2 \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" python:3.12-alpine sleep 900 >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,http.client,json,os,sys,threading,time,urllib.request,urllib.error
B="http://stalwart:8080"; fails=[]
for _ in range(90):
    try: urllib.request.urlopen(B+"/healthz/ready",timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit("stalwart never became ready")
# The verdict line is fixed text, so build.yml can name it; what was seen goes on the next line.
def check(ok,msg,got=""): print(("PASS " if ok else "FAIL ")+msg); got!="" and print(f"     got: {got}"); ok or fails.append(msg)
basic=lambda u,p: "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:stalwart:jmap"]
def req(path,auth,raw=None,ctype="application/json",method=None):
    h={"Authorization":auth}
    if raw is not None: h["Content-Type"]=ctype
    try:
        with urllib.request.urlopen(urllib.request.Request(B+path,data=raw,headers=h,method=method),timeout=60) as x: return x.status,x.headers,x.read()
    except urllib.error.HTTPError as e: return e.code,e.headers,e.read()
    except OSError as e: return type(e).__name__,{},b""
def r1(auth,call): return json.loads(req("/jmap/",auth,json.dumps({"using":U,"methodCalls":[call]}).encode())[2])["methodResponses"][0]
ADM=basic("admin",os.environ["ADMIN"]); A=json.loads(req("/jmap/session",ADM)[2])["primaryAccounts"]["urn:stalwart:jmap"]
D=r1(ADM,["x:Domain/set",{"accountId":A,"create":{"d":{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}}},"d"])[1]["created"]["d"]["id"]
PW=base64.b64encode(os.urandom(18)).decode(); NAMES=[f"u{i}" for i in range(12)]
r=r1(ADM,["x:Account/set",{"accountId":A,"create":{n:{"@type":"User","name":n,"domainId":D,"credentials":{"0":{"@type":"Password","secret":PW}}} for n in NAMES}},"c"])[1]
if len(r.get("created") or {})!=len(NAMES): raise SystemExit(f"accounts not created: {r}")
AU={n:basic(f"{n}@one.test",PW) for n in NAMES}
def jacct(n): return json.loads(req("/jmap/session",AU[n])[2])["primaryAccounts"]["urn:ietf:params:jmap:mail"]
MiB=1024*1024
def dav(n,size,name="f.bin"): return req(f"/dav/file/{n}%40one.test/{name}",AU[n],os.urandom(size),"application/octet-stream","PUT")
def jup(n,size): return req(f"/jmap/upload/{jacct(n)}/",AU[n],os.urandom(size),"application/octet-stream","POST")
class Held(threading.Thread):
    # A WebDAV PUT of 3 MiB that sends 1.5 MiB (past the 1 MiB mark), then waits for `go` before the rest.
    def __init__(self,n,go): super().__init__(); self.n=n; self.go=go; self.status=None
    def run(self):
        c=http.client.HTTPConnection("stalwart",8080,timeout=120)
        c.putrequest("PUT",f"/dav/file/{self.n}%40one.test/held.bin")
        c.putheader("Authorization",AU[self.n]); c.putheader("Content-Type","application/octet-stream"); c.putheader("Content-Length",str(3*MiB)); c.endheaders()
        c.send(os.urandom(3*MiB//2)); self.go.wait(); c.send(os.urandom(3*MiB//2))
        self.status=c.getresponse().status
def round_(tag,a,b,x,y,z):
    go=threading.Event(); hs=[Held(a,go),Held(b,go)]; [h.start() for h in hs]
    time.sleep(3)   # both bodies are past 1 MiB on the server: both slots are held
    # 8 MiB: the refusal comes at 1 MiB, and the client must still READ it after sending the other 7. A server that
    # answers and closes on the unread rest resets the connection, and the client sees a network error instead.
    LARGE=8*MiB
    st,hd,_=dav(x,LARGE)
    check(st==429, f"{tag}: with 2 large uploads in flight, a third WebDAV PUT from another account is refused retryably", st)
    check(st==429 and hd.get("Retry-After")=="5", f"{tag}: the WebDAV refusal says when to retry", hd.get("Retry-After"))
    st,_,body=jup(y,LARGE)
    check(st==429, f"{tag}: and a third JMAP upload from another account too", f"{st} {body[:100]!r}")
    st,_,_=dav(z,256*1024,"small.bin")
    check(st==201, f"{tag}: a small body is never counted, so it is stored", st)
    go.set(); [h.join() for h in hs]
    check([h.status for h in hs]==[201,201], f"{tag}: the two held uploads complete", [h.status for h in hs])
    st,_,_=dav(x,LARGE)
    check(st in (201,204), f"{tag}: once they are done, the refused WebDAV PUT is stored on retry", st)
    st,_,_=jup(y,LARGE)
    check(st==200, f"{tag}: and the refused JMAP upload", st)
round_("first",*NAMES[0:5])
# A body refused as too large AFTER it passed 1 MiB, and a burst of sequential large uploads, must give their slots back.
st,_,_=dav(NAMES[5],25*MiB+1,"over.bin")
check(st==413, "one byte over the WebDAV cap is still refused as too large, not as busy", st)
for i in range(4): dav(NAMES[6],2*MiB,f"seq{i}.bin")
round_("again",*NAMES[7:12])
sys.exit(1 if fails else 0)
PY
