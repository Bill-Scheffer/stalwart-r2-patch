#!/usr/bin/env bash
# End-to-end: the large request bodies the server holds at once stay within STALWART_MAX_LARGE_UPLOAD_MIB, and the
# large messages within STALWART_MAX_LARGE_MESSAGE_MIB, in bytes, across all accounts and senders.
# usage: e2e-upload-cap.sh <stalwart image>
#
# Each account is bounded upstream (4 requests at once, a pending-upload quota), but nothing bounds the sum: at a 2 GiB
# limit, ~70 parallel 25 MiB uploads from different accounts OOM-kill the process, and every upload and session on it
# is lost (measured on the -nologo1 image, MAI-1000). Patch 0010 counts a body once it passes 1 MiB and refuses one
# past the budget, retryably: WebDAV 429 with Retry-After, JMAP 429. Here the budget is 30 MiB: two 14 MiB uploads are
# held open at 13 MiB each (both fit when they finish), a third of 8 MiB (WebDAV and JMAP, other accounts) is refused while they are, a small
# body is not, a 25 MiB body alone still meets its size limit (413) before the budget, and once they finish
# the slots are back: the same pattern holds a second time, after a too-large body that was refused mid-way too.
# A refused body is read to its end and dropped, so the client gets the 429, not a reset connection.
#
# Messages: a 25 MiB message costs about 160 MiB while SMTP holds it, before authentication, bounded only per sender
# IP, and about 80 MiB by IMAP APPEND (measured, MAI-1000). Patch 0010 counts one's bytes once it passes 5 MiB, so
# ordinary mail is never counted. Here that budget is 110 MiB: two 52 MiB SMTP messages are held open at 50 MiB, a
# third of 16 MiB (DATA and BDAT) gets 452 after its body is read and dropped, an IMAP APPEND gets NO [UNAVAILABLE]
# (synchronizing literal: before it is sent; LITERAL+: after), a burst of ordinary messages up to 4.5 MiB is all
# accepted while the budget is full, and once it is free a single 100 MiB message is accepted.
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
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -e STALWART_MAX_LARGE_UPLOAD_MIB=30 -e STALWART_MAX_LARGE_MESSAGE_MIB=110 \
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
    # A WebDAV PUT of 14 MiB that sends 13 MiB of it, then waits for `go` before the rest.
    def __init__(self,n,go): super().__init__(); self.n=n; self.go=go; self.status=None
    def run(self):
        c=http.client.HTTPConnection("stalwart",8080,timeout=120)
        c.putrequest("PUT",f"/dav/file/{self.n}%40one.test/held.bin")
        c.putheader("Authorization",AU[self.n]); c.putheader("Content-Type","application/octet-stream"); c.putheader("Content-Length",str(14*MiB)); c.endheaders()
        c.send(os.urandom(13*MiB)); self.go.wait(); c.send(os.urandom(MiB))
        self.status=c.getresponse().status
def round_(tag,a,b,x,y,z):
    go=threading.Event(); hs=[Held(a,go),Held(b,go)]; [h.start() for h in hs]
    time.sleep(3)   # both bodies are at 13 MiB on the server: 26 of the 30 MiB are held
    # 8 MiB: the refusal comes at 4 MiB, and the client must still READ it after sending the rest. A server that
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
    # An SMTP message of 52 MiB that sends 50 MiB of it, then waits for `go` before the rest.
    def __init__(self,n,go): super().__init__(); self.n=n; self.go=go; self.code=None; self.sent=threading.Event()
    def run(self):
        s=Smtp(); st=s.begin(self.n)
        if st!="ok": self.code=st; self.sent.set(); return
        m=eml(52*MiB); s.c.sendall(m[:50*MiB]); self.sent.set(); self.go.wait(); s.c.sendall(m[50*MiB:]); self.code=s.cmd(b".\r\n"); s.close()
go=threading.Event(); held=[HeldMessage(NAMES[0],go),HeldMessage(NAMES[1],go)]; [h.start() for h in held]
[h.sent.wait() for h in held]; time.sleep(3)   # both messages are at 50 MiB on the server: 100 of the 110 MiB held
st=smtp(NAMES[2],16*MiB)
check(st=="452", "with 2 large messages in flight, a third by SMTP DATA is refused with 452 (the sender retries)", st)
st=bdat(NAMES[3],16*MiB)
check(st=="452", "and one by SMTP BDAT", st)
got=append(NAMES[4],16*MiB)
check(got.startswith("b NO [UNAVAILABLE]"), "and an IMAP APPEND, before its literal is sent", got)
got=append(NAMES[5],16*MiB,non_sync=True)
check(got.startswith("b NO [UNAVAILABLE]"), "and an IMAP APPEND with a LITERAL+ literal, read and dropped", got)
# A refusal ends the transaction: the same session's next MAIL is a fresh one, not "503 Multiple MAIL commands".
s=Smtp(); st=s.begin(NAMES[2])
if st=="ok": s.c.sendall(eml(16*MiB)); st=s.cmd(b".\r\n")
nxt=s.cmd(b"MAIL FROM:<s@example.net>\r\n") if st=="452" else "-"; s.close()
check(st=="452" and nxt=="250", "after a 452, the same session starts a new message", f"{st} then {nxt}")
# Pipelined BDAT chunks after a refused one are refused too (RFC 3030), so no message is delivered from the rest.
s=Smtp(); st=s.begin(NAMES[3],data=False); codes=[]
if st=="ok":
    a,b,c=os.urandom(3*MiB),os.urandom(9*MiB),os.urandom(MiB)
    s.c.sendall(f"BDAT {len(a)}\r\n".encode()+a+f"BDAT {len(b)}\r\n".encode()+b+f"BDAT {len(c)} LAST\r\n".encode()+c)
    codes=[s.reply() for _ in range(3)]
s.close()
check(len(codes)==3 and codes[1]=="452" and codes[2]!="250", "a pipelined BDAT after a refused chunk is refused too", codes)
# A MULTIAPPEND refused as busy mid-way: the rest of its line is read as data, never run as a command.
c=ssl._create_unverified_context().wrap_socket(socket.create_connection(("stalwart",993),timeout=120)); f=c.makefile("rb"); f.readline()
c.sendall(f"a LOGIN {NAMES[5]}@one.test {PW}\r\n".encode())
while not (l:=f.readline()).startswith(b"a "): pass
one,big=eml(MiB),eml(16*MiB); tail=b"Subject: x\r\n\r\nzz9 NOOP\r\n"
c.sendall(f"b APPEND INBOX {{{len(one)}+}}\r\n".encode()+one+f" {{{len(big)}+}}\r\n".encode()+big+f" {{{len(tail)}+}}\r\n".encode()+tail+b"\r\nc NOOP\r\n")
seen=[]
while not (l:=f.readline()).startswith(b"c ") and l: seen.append(l.strip())
c.close()
tagged=[x.decode(errors="replace")[:60] for x in seen if not x.startswith(b"*")]
check(len(tagged)==1 and tagged[0].startswith("b NO [UNAVAILABLE]"), "a MULTIAPPEND refused mid-way runs none of the rest of its line", tagged)
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
st=smtp(NAMES[2],16*MiB)
check(st=="250", "once they are, the refused SMTP message is accepted on retry", st)
got=append(NAMES[4],16*MiB)
check(got.startswith("b OK"), "and the refused IMAP APPEND", got)
# A client that has not logged in holds no slot: two stalled pre-login literals, and a large APPEND still goes in.
stalled=[]
for _ in range(2):
    c=ssl._create_unverified_context().wrap_socket(socket.create_connection(("stalwart",993),timeout=120)); f=c.makefile("rb"); f.readline()
    c.sendall(f"p APPEND INBOX {{{8*MiB}}}\r\n".encode())
    if f.readline().startswith(b"+"): c.sendall(os.urandom(3*MiB))
    stalled.append(c)
got=append(NAMES[7],16*MiB)
check(got.startswith("b OK"), "a client that has not logged in cannot hold a large-message slot", got)
[c.close() for c in stalled]
# The budget is bytes, so one message as large as SMTP allows (100 MiB) goes in alone.
st=smtp(NAMES[8],97*MiB)
check(st=="250", "with the budget free, a single 100 MiB message is accepted", st)
# A BDAT is counted as its bytes arrive, not as declared: one that names 94 MiB and sends nothing holds none of it.
idle=Smtp(); st=idle.begin(NAMES[9],data=False)
if st=="ok": idle.c.sendall(b"BDAT 99000000\r\n")
time.sleep(2)
st2=smtp(NAMES[10],97*MiB)
check(st=="ok" and st2=="250", "a BDAT that declares 94 MiB and sends nothing does not hold the budget", f"{st} / {st2}")
idle.c.close()
sys.exit(1 if fails else 0)
PY
