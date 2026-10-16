#!/usr/bin/env bash
# End-to-end: the server holds at most STALWART_MAX_LARGE_UPLOADS large request bodies, and at most
# STALWART_MAX_LARGE_MESSAGES large messages, at once, across all accounts and senders.
# usage: e2e-upload-cap.sh <stalwart image>
#
# Each account is bounded upstream (4 requests at once, a pending-upload quota), but nothing bounds the sum: at a 2 GiB
# limit, ~70 parallel 25 MiB uploads from different accounts OOM-kill the process, and every upload and session on it
# is lost (measured on the -nologo1 image, MAI-1000). Patch 0010 counts a body once it passes 1 MiB and refuses one
# past the cap, retryably: WebDAV 429 with Retry-After, JMAP 429. Here the cap is 2: two uploads are held open past
# 1 MiB, a third (WebDAV and JMAP, other accounts) is refused while they are, a small body is not, and once they finish
# the slots are back: the same pattern holds a second time, after a too-large body that was refused mid-way too.
# A refused body is read to its end and dropped, so the client gets the 429, not a reset connection.
#
# Messages: a 25 MiB message costs about 160 MiB while SMTP holds it, before authentication, bounded only per sender
# IP, and about 80 MiB by IMAP APPEND (measured, MAI-1000). Patch 0010 counts one once it passes 5 MiB, so ordinary
# mail is never counted. Here that cap is 2 too: two SMTP messages are held open past 5 MiB, a third (DATA and BDAT)
# gets 452 after its body is read and dropped, an IMAP APPEND gets NO [UNAVAILABLE] (synchronizing literal: before
# it is sent; LITERAL+: after), and a burst of ordinary messages up to 4.5 MiB is all accepted while the cap is full.
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
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -e STALWART_MAX_LARGE_UPLOADS=2 -e STALWART_MAX_LARGE_MESSAGES=2 \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" python:3.12-alpine sleep 900 >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,http.client,json,os,socket,ssl,sys,threading,time,urllib.request,urllib.error
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

def eml(size):
    # About `size` bytes of base64 lines: no line starts with ".", so it is sent as is.
    raw=os.urandom(size*3//4)
    return (b"From: s@example.net\r\nTo: x@one.test\r\nSubject: cap\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + b"".join(base64.b64encode(raw[i:i+57])+b"\r\n" for i in range(0,len(raw),57)))
# A fresh install throttles each sender IP to 5 new SMTP connections a second, and closes the rest at the banner:
# open at most 4 a second, so that limit never answers for the cap.
OPENED=[0.0]; OPEN_LOCK=threading.Lock()
class Smtp:
    def __init__(self):
        with OPEN_LOCK:
            time.sleep(max(0,OPENED[0]+0.25-time.time())); OPENED[0]=time.time()
        self.c=socket.create_connection(("stalwart",25),timeout=120); self.f=self.c.makefile("rb"); self.banner=self.reply()
    def reply(self):
        while True:
            line=self.f.readline()
            if not line: return "closed"
            if line[3:4]!=b"-": return line[:3].decode()
    def cmd(self,c): self.c.sendall(c); return self.reply()
    def begin(self,n,data=True):
        if self.banner!="220": return f"banner:{self.banner}"
        steps=[b"EHLO cap.example.net\r\n",b"MAIL FROM:<s@example.net>\r\n",f"RCPT TO:<{n}@one.test>\r\n".encode()]+([b"DATA\r\n"] if data else [])
        for c in steps:
            got=self.cmd(c)
            if got not in ("250","354"): return f"{c.split()[0].decode()}:{got}"
        return "ok"
    def close(self):
        try: self.cmd(b"QUIT\r\n")
        except OSError: pass
        self.c.close()
def smtp(n,size):
    s=Smtp(); st=s.begin(n)
    if st=="ok": s.c.sendall(eml(size)); st=s.cmd(b".\r\n")
    s.close(); return st
def bdat(n,size):
    s=Smtp(); st=s.begin(n,data=False)
    if st=="ok": m=eml(size); s.c.sendall(f"BDAT {len(m)} LAST\r\n".encode()); st=s.cmd(m)
    s.close(); return st
def append(n,size,non_sync=False):
    c=ssl._create_unverified_context().wrap_socket(socket.create_connection(("stalwart",993),timeout=120)); f=c.makefile("rb"); f.readline()
    def tagged(tag):
        while True:
            line=f.readline()
            if not line or line.startswith(tag+b" ") or line.startswith(b"+"): return line.strip()
    c.sendall(f"a LOGIN {n}@one.test {PW}\r\n".encode())
    if not tagged(b"a").startswith(b"a OK"): c.close(); return "LOGIN failed"
    m=eml(size)
    if non_sync:
        c.sendall(f"b APPEND INBOX {{{len(m)}+}}\r\n".encode()+m+b"\r\n"); got=tagged(b"b")
    else:
        c.sendall(f"b APPEND INBOX {{{len(m)}}}\r\n".encode()); got=tagged(b"b")
        if got.startswith(b"+"): c.sendall(m+b"\r\n"); got=tagged(b"b")
    c.close(); return got.decode(errors="replace")[:120]
class HeldMessage(threading.Thread):
    # An SMTP message of 12 MiB that sends 6 MiB (past the 5 MiB mark), then waits for `go` before the rest.
    def __init__(self,n,go): super().__init__(); self.n=n; self.go=go; self.code=None
    def run(self):
        s=Smtp(); st=s.begin(self.n)
        if st!="ok": self.code=st; return
        m=eml(12*MiB); s.c.sendall(m[:6*MiB]); self.go.wait(); s.c.sendall(m[6*MiB:]); self.code=s.cmd(b".\r\n"); s.close()
go=threading.Event(); held=[HeldMessage(NAMES[0],go),HeldMessage(NAMES[1],go)]; [h.start() for h in held]
time.sleep(5)   # both messages are past 5 MiB on the server: both slots are held
st=smtp(NAMES[2],8*MiB)
check(st=="452", "with 2 large messages in flight, a third by SMTP DATA is refused with 452 (the sender retries)", st)
st=bdat(NAMES[3],8*MiB)
check(st=="452", "and one by SMTP BDAT", st)
got=append(NAMES[4],8*MiB)
check(got.startswith("b NO [UNAVAILABLE]"), "and an IMAP APPEND, before its literal is sent", got)
got=append(NAMES[5],8*MiB,non_sync=True)
check(got.startswith("b NO [UNAVAILABLE]"), "and an IMAP APPEND with a LITERAL+ literal, read and dropped", got)
# The burst the cap must never touch: ordinary messages up to 4.5 MiB, two senders at once.
small={}
def burst(i):
    small[i]=[smtp(NAMES[6+i],sz) for sz in (64*1024,1*MiB,3*MiB,9*MiB//2)]
ts=[threading.Thread(target=burst,args=(i,)) for i in range(2)]; [t.start() for t in ts]; [t.join() for t in ts]
codes=sorted(c for v in small.values() for c in v)
check(codes==["250"]*8, "while the cap is full, a burst of 8 ordinary messages (64 KiB to 4.5 MiB) is all accepted", codes)
got=append(NAMES[6],1*MiB)
check(got.startswith("b OK"), "and an ordinary IMAP APPEND too", got)
go.set(); [h.join() for h in held]
check([h.code for h in held]==["250","250"], "the two held messages are accepted", [h.code for h in held])
st=smtp(NAMES[2],8*MiB)
check(st=="250", "once they are, the refused SMTP message is accepted on retry", st)
got=append(NAMES[4],8*MiB)
check(got.startswith("b OK"), "and the refused IMAP APPEND", got)
sys.exit(1 if fails else 0)
PY
