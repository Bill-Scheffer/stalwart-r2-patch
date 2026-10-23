#!/usr/bin/env bash
# End-to-end: a logged-in client that stops sending holds none of 0010's budgets beyond the bytes it sent, and an HTTP
# body that sends nothing for STALWART_BODY_IDLE_SECS is ended, with what it held given back.
# usage: e2e-stalled-bodies.sh <stalwart image>
#
# 0010 (-bodycap1) claimed message budget at an IMAP literal's {n}, before the server sent "+" and before any byte
# arrived, so a client that declared a literal and sent nothing held its whole size until the IMAP timeout (30 min).
# IMAP's request limit is 50 MiB by default, so one client held up to ~50 MiB and four held production's 200 MiB.
# Patch 0016 counts a literal's bytes as they arrive; one that would not fit now is still refused before "+", and one
# that runs out of budget partway is read to its end and dropped, then answered NO [UNAVAILABLE], and the session
# goes on; one that stops partway is ended after STALWART_BODY_IDLE_SECS, as an HTTP body is, not IMAP's 30 minutes.
# Here the message budget is 110 MiB: two clients declare 48 MiB literals and send nothing (96 MiB on -bodycap1), and
# a 52 MiB message and a 40 MiB APPEND are accepted meanwhile.
#
# HTTP: upstream reads a body with no timeout, so an upload that stops sending held its share of the upload budget
# for as long as the connection stayed open. 0016 ends a request whose body sends nothing for
# STALWART_BODY_IDLE_SECS (here 5) with 408, and its slot goes back. Here the upload budget is 30 MiB: two
# WebDAV PUTs stall at 13 MiB each, are ended, and a following upload is accepted; a slow body that keeps sending is
# not ended. Against -bodycap1 the stalled-body checks FAIL (it has neither change).
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-stall-$$; C=e2e-stall-stalwart-$$; K=e2e-stall-client-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
ADMIN=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
docker network create "$NET" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -e STALWART_MAX_LARGE_UPLOAD_MIB=30 -e STALWART_MAX_LARGE_MESSAGE_MIB=110 \
  -e STALWART_BODY_IDLE_SECS=5 \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" python:3.12-alpine sleep 900 >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,http.client,json,os,select,socket,ssl,sys,threading,time,urllib.request,urllib.error
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
PW=base64.b64encode(os.urandom(18)).decode(); NAMES=[f"u{i}" for i in range(10)]
r=r1(ADM,["x:Account/set",{"accountId":A,"create":{n:{"@type":"User","name":n,"domainId":D,"credentials":{"0":{"@type":"Password","secret":PW}}} for n in NAMES}},"c"])[1]
if len(r.get("created") or {})!=len(NAMES): raise SystemExit(f"accounts not created: {r}")
AU={n:basic(f"{n}@one.test",PW) for n in NAMES}
MiB=1024*1024

def eml(size):
    # About `size` bytes of base64 lines: no line starts with ".", so it is sent as is.
    raw=os.urandom(size*3//4)
    return (b"From: s@example.net\r\nTo: x@one.test\r\nSubject: stall\r\nMIME-Version: 1.0\r\n"
            b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + b"".join(base64.b64encode(raw[i:i+57])+b"\r\n" for i in range(0,len(raw),57)))
# A fresh install throttles each sender IP to 5 new SMTP connections a second: open at most 4 a second.
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
    def begin(self,n):
        if self.banner!="220": return f"banner:{self.banner}"
        for c in [b"EHLO stall.example.net\r\n",b"MAIL FROM:<s@example.net>\r\n",f"RCPT TO:<{n}@one.test>\r\n".encode(),b"DATA\r\n"]:
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
class HeldMessage(threading.Thread):
    # An SMTP message of 42 MiB that sends 40 MiB of it, then waits for `go` before the rest.
    def __init__(self,n,go): super().__init__(); self.n=n; self.go=go; self.code=None; self.sent=threading.Event()
    def run(self):
        s=Smtp(); st=s.begin(self.n)
        if st!="ok": self.code=st; self.sent.set(); return
        m=eml(42*MiB); s.c.sendall(m[:40*MiB]); self.sent.set(); self.go.wait(); s.c.sendall(m[40*MiB:]); self.code=s.cmd(b".\r\n"); s.close()
class Imap:
    def __init__(self,n):
        self.c=ssl._create_unverified_context().wrap_socket(socket.create_connection(("stalwart",993),timeout=120))
        self.f=self.c.makefile("rb"); self.f.readline()
        self.ok=self.cmd(b"a",f"LOGIN {n}@one.test {PW}".encode()).startswith("a OK")
    def tagged(self,tag):
        while True:
            line=self.f.readline()
            if not line or line.startswith(tag+b" ") or line.startswith(b"+"): return line.strip().decode(errors="replace")[:120]
    def cmd(self,tag,c): self.c.sendall(tag+b" "+c+b"\r\n"); return self.tagged(tag)
    def declare(self,tag,size): self.c.sendall(tag+f" APPEND INBOX {{{size}}}\r\n".encode()); return self.tagged(tag)
    def append(self,tag,size):
        m=eml(size); got=self.declare(tag,len(m))
        if got.startswith("+"): self.c.sendall(m+b"\r\n"); got=self.tagged(tag)
        return got

# --- IMAP: a declared literal holds nothing until its bytes arrive -----------------------------------------------
LIT=48*MiB
stalled=[Imap(NAMES[0]),Imap(NAMES[1])]
gos=[s.declare(b"s",LIT) if s.ok else "LOGIN failed" for s in stalled]
check(all(g.startswith("+") for g in gos), "two clients each declare a 48 MiB sync literal and are told to send it", gos)
st=smtp(NAMES[2],52*MiB)
check(st=="250", "while two 48 MiB sync literals are declared and send nothing, a 52 MiB message is accepted", st)
i=Imap(NAMES[3]); got=i.append(b"b",40*MiB) if i.ok else "LOGIN failed"; i.c.close()
check(got.startswith("b OK"), "and a 40 MiB IMAP APPEND", got)
# Hold 80 of the 110 MiB, then let one stalled client send most of its literal: it runs out at about 30 MiB.
go=threading.Event(); held=[HeldMessage(NAMES[4],go),HeldMessage(NAMES[5],go)]; [h.start() for h in held]
[h.sent.wait() for h in held]; time.sleep(3)   # both messages are at 40 MiB on the server
S1=stalled[0]
S1.c.sendall(b"A"*(LIT-4*MiB)); time.sleep(3)
go.set(); [h.join() for h in held]
check([h.code for h in held]==["250","250"], "the two held messages are accepted", [h.code for h in held])
# S1 is 4 MiB short of its literal's end and S2 is still declared: if either held anything, ~100 MiB would not fit.
st=smtp(NAMES[6],97*MiB)
check(st=="250", "the literal refused partway gave back what it held at once, and the one still declared holds nothing: a 97 MiB message is accepted", st)
S1.c.sendall(b"A"*4*MiB+b"\r\n"); got=S1.tagged(b"s")
check(got.startswith("s NO [UNAVAILABLE]"), "a stalled literal sent later, while the budget is full, is refused partway and read to its end", got)
got=S1.cmd(b"t",b"NOOP")
check(got.startswith("t OK"), "and its session is still usable", got)
got=S1.append(b"u",LIT-MiB)
check(got.startswith("u OK"), "the refused APPEND is stored on retry, in the same session", got)
[s.c.close() for s in stalled]
# A literal that stops partway holds what it sent only for the idle timeout, as an HTTP body does, not IMAP's 30 min.
S3=Imap(NAMES[7]); got=S3.declare(b"s",LIT) if S3.ok else "LOGIN failed"
if got.startswith("+"):
    S3.c.sendall(b"A"*30*MiB); S3.c.settimeout(15)
    try: got=S3.f.readline().strip().decode(errors="replace")[:60]
    except OSError as e: got=type(e).__name__
check(got.startswith("* BYE"), "a literal that stops partway is ended after 5 s, with its session", got)
# Still open from this side, so only the server can have let go.
st=smtp(NAMES[8],97*MiB)
check(st=="250", "and what it held comes back: a 97 MiB message is accepted", st)
S3.c.close()
# A literal that trickles is refused once it falls below 16 KiB/s past the grace: 64 KiB, then 1 KiB every 2 s.
T=Imap(NAMES[9]); got=T.declare(b"d",6*MiB) if T.ok else "LOGIN failed"
if got.startswith("+"):
    T.c.sendall(b"A"*64*1024); sent=64*1024
    for _ in range(8): time.sleep(2); T.c.sendall(b"A"*1024); sent+=1024
    T.c.sendall(b"A"*(6*MiB-sent)+b"\r\n"); got=T.tagged(b"d")
check(got.startswith("d NO [UNAVAILABLE]"), "a literal that trickles below 16 KiB/s after the 5 s grace is refused, read to its end", got)
got=T.cmd(b"e",b"NOOP")
check(got.startswith("e OK"), "and its session is still usable after the trickle", got)
T.c.close()

# --- HTTP: a body that sends nothing for 5 s is ended, and its slot goes back ----------------------------------
def dav(n,size,name="f.bin"): return req(f"/dav/file/{n}%40one.test/{name}",AU[n],os.urandom(size),"application/octet-stream","PUT")
def jacct(n): return json.loads(req("/jmap/session",AU[n])[2])["primaryAccounts"]["urn:ietf:params:jmap:mail"]
def jup(n,size): return req(f"/jmap/upload/{jacct(n)}/",AU[n],os.urandom(size),"application/octet-stream","POST")
class Stalled(threading.Thread):
    # A 14 MiB body that sends 13 MiB, then nothing: the status the server ends it with, and after how long.
    def __init__(self,method,path,n): super().__init__(); self.a=(method,path,n); self.status=None; self.after=None
    def run(self):
        method,path,n=self.a
        c=http.client.HTTPConnection("stalwart",8080,timeout=20)
        c.putrequest(method,path); c.putheader("Authorization",AU[n]); c.putheader("Content-Type","application/octet-stream")
        c.putheader("Content-Length",str(14*MiB)); c.endheaders(); c.send(os.urandom(13*MiB)); t=time.time()
        try: self.status=c.getresponse().status
        except OSError as e: self.status=type(e).__name__
        self.after=round(time.time()-t,1); c.close()
hs=[Stalled("PUT",f"/dav/file/{n}%40one.test/stalled.bin",n) for n in NAMES[0:2]]; [h.start() for h in hs]
time.sleep(2)   # both bodies are at 13 MiB: 26 of the 30 MiB held
st,_,_=dav(NAMES[2],8*MiB)
check(st==429, "while two stalled uploads hold 26 MiB, a third is refused (the budget is held)", st)
# Past the 5 s, and before the clients' own 20 s timeout closes them: only the server can have let go.
time.sleep(7)
st,_,_=dav(NAMES[2],8*MiB)
check(st in (201,204), "and its budget comes back: a following WebDAV upload is accepted", st)
st,_,_=jup(NAMES[3],8*MiB)
check(st==200, "and a JMAP upload", st)
[h.join() for h in hs]
check([h.status for h in hs]==[408,408], "an HTTP body that sends nothing for longer than 5 s is ended", [(h.status,h.after) for h in hs])
h=Stalled("POST",f"/jmap/upload/{jacct(NAMES[4])}/",NAMES[4]); h.start(); h.join()
check(h.status==408, "a stalled JMAP upload is ended the same way", (h.status,h.after))
# A body that trickles is ended once it falls below 16 KiB/s past the grace: just over 1 MiB, then 1 KiB every 2 s.
def trickle(path,n):
    c=socket.create_connection(("stalwart",8080),timeout=10)
    c.sendall(f"PUT {path} HTTP/1.1\r\nHost: stalwart\r\nAuthorization: {AU[n]}\r\n"
              f"Content-Type: application/octet-stream\r\nContent-Length: {14*MiB}\r\n\r\n".encode())
    c.sendall(os.urandom(MiB+64*1024)); t=time.time()
    try:
        while time.time()-t<30:
            if select.select([c],[],[],2)[0]: return c.recv(64).split(b"\r\n")[0].decode(errors="replace"),round(time.time()-t)
            c.sendall(os.urandom(1024))
        return "no answer",30
    except OSError as e: return type(e).__name__,round(time.time()-t)
    finally: c.close()
got=trickle(f"/dav/file/{NAMES[6]}%40one.test/trickle.bin",NAMES[6])
# Not before ~9 s (5 s of grace, then 64 KiB of credit at 16 KiB/s): sooner would be the idle timeout, not the floor.
check(got[0].startswith("HTTP/1.1 408") and got[1]>=8, "an HTTP body that trickles below 16 KiB/s after the 5 s grace is ended with 408", got)
# Idle, not total: a body that keeps sending, a piece every 3 s, is never ended.
c=http.client.HTTPConnection("stalwart",8080,timeout=60)
c.putrequest("PUT",f"/dav/file/{NAMES[5]}%40one.test/slow.bin"); c.putheader("Authorization",AU[NAMES[5]])
c.putheader("Content-Type","application/octet-stream"); c.putheader("Content-Length",str(5*MiB)); c.endheaders()
for _ in range(5): c.send(os.urandom(MiB)); time.sleep(3)
st=c.getresponse().status; c.close()
check(st in (201,204), "a slow body that keeps sending (1 MiB every 3 s) is not ended", st)
sys.exit(1 if fails else 0)
PY
