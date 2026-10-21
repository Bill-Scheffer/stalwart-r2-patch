#!/usr/bin/env bash
# End-to-end: a bounce returns the original's headers as text/rfc822-headers, byte for byte, in 7bit (8bit for UTF-8).
# usage: e2e-dsn-headers.sh <stalwart image>
#
# Upstream returns the headers only, but labels them message/rfc822 and quoted-printable-encodes them whenever a header
# line is longer than 77 characters, which most mail has. Amazon SES parses a message/rfc822 part as a whole message and
# refuses the bounce: 554 "Unbalanced quoted string" for that shape, 554 "Missing start boundary" for the same headers in
# 7bit, when they name a multipart. It accepts text/rfc822-headers in 7bit (measured through real SES, MainThrive
# MAI-1036). Patch 0013 sends that. Here a real bounce: org submits two messages to an outside domain whose MX (a stub
# on an internal network, found through a DNS stub) refuses the recipient with 550, and Stalwart bounces each to org.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-dsn-$$; C=e2e-dsn-stalwart-$$; K=e2e-dsn-client-$$; N=e2e-dsn-dns-$$; M=e2e-dsn-mx-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data" "$W/dns"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" "$N" "$M" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
ADMIN=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
docker network create --internal "$NET" >/dev/null
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
# The outside domain's MX: refuses every recipient, permanently, so the bounce is immediate.
docker run -d --name "$M" --network "$NET" python:3.12-alpine python3 -c '
import socketserver
class S(socketserver.StreamRequestHandler):
    def handle(self):
        say = lambda s: self.wfile.write(s.encode() + b"\r\n")
        say("220 mx.two.test ESMTP")
        for line in self.rfile:
            verb = line[:4].upper()
            if verb in (b"EHLO", b"HELO"): say("250-mx.two.test"); say("250-8BITMIME"); say("250 SMTPUTF8")
            elif verb == b"RCPT": say("550 5.1.1 no such user here")
            elif verb == b"QUIT": say("221 2.0.0 bye"); return
            elif verb == b"DATA": say("554 5.5.1 no valid recipients")
            else: say("250 2.0.0 ok")
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("", 25), S).serve_forever()' >/dev/null
ip_of "$M" > "$W/dns/mx-ip"
# The DNS stub: two.test's MX is mx.two.test, at the stub MX; NXDOMAIN for anything else.
docker run -d --name "$N" --network "$NET" -v "$W/dns:/w:ro" python:3.12-alpine python3 -c '
import socket, socketserver, struct, threading
def enc(name): return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
DOMAIN, MX = enc("two.test"), enc("mx.two.test")
def answer(q):
    end = 12
    while q[end]: end += q[end] + 1
    qname, qtype = q[12:end + 1].lower(), struct.unpack(">H", q[end + 1:end + 3])[0]
    rr = b""
    if qtype == 15 and qname == DOMAIN:
        rr = struct.pack(">HHHIHH", 0xC00C, 15, 1, 60, len(MX) + 2, 10) + MX
    elif qtype == 1 and qname == MX:
        rr = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(open("/w/mx-ip").read().strip())
    # QR, RD and RA; NXDOMAIN unless the name is one of these (then an empty answer for any other type).
    flags = 0x8180 if qname in (DOMAIN, MX) else 0x8183
    return q[:2] + struct.pack(">HHHHH", flags, 1, 1 if rr else 0, 0, 0) + q[12:end + 5] + rr
class T(socketserver.BaseRequestHandler):
    def handle(self):
        f = self.request.makefile("rb")
        while (h := f.read(2)) and len(h) == 2:
            r = answer(f.read(struct.unpack(">H", h)[0])); self.request.sendall(struct.pack(">H", len(r)) + r)
socketserver.ThreadingTCPServer.allow_reuse_address = True
threading.Thread(target=socketserver.ThreadingTCPServer(("", 53), T).serve_forever, daemon=True).start()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("", 53))
while True:
    q, a = u.recvfrom(4096)
    try: u.sendto(answer(q), a)
    except Exception: pass' >/dev/null
echo "nameserver $(ip_of "$N")" > "$W/resolv.conf"
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/resolv.conf:/etc/resolv.conf:ro" \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" python:3.12-alpine sleep 900 >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,json,os,secrets,sys,time,urllib.request,urllib.error
B="http://stalwart:8080"; fails=[]
for _ in range(90):
    try: urllib.request.urlopen(B+"/healthz/ready",timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit("stalwart never became ready")
# The verdict line is fixed text, so build.yml can name it; what was seen goes on the next line.
def check(ok,msg,got=""): print(("PASS " if ok else "FAIL ")+msg); got!="" and print(f"     got: {got}"); ok or fails.append(msg)
basic=lambda u,p: "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission","urn:stalwart:jmap"]
def req(path,auth,raw=None,ctype="application/json"):
    h={"Authorization":auth}
    if raw is not None: h["Content-Type"]=ctype
    try:
        with urllib.request.urlopen(urllib.request.Request(B+path,data=raw,headers=h),timeout=30) as x: return x.status,x.read()
    except urllib.error.HTTPError as e: return e.code,e.read()
def r1(auth,call): return json.loads(req("/jmap/",auth,json.dumps({"using":U,"methodCalls":[call]}).encode())[1])["methodResponses"][0]
ADM=basic("admin",os.environ["ADMIN"]); A=json.loads(req("/jmap/session",ADM)[1])["primaryAccounts"]["urn:stalwart:jmap"]
D=r1(ADM,["x:Domain/set",{"accountId":A,"create":{"d":{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}}},"d"])[1]["created"]["d"]["id"]
PW=secrets.token_urlsafe(16)
r1(ADM,["x:Account/set",{"accountId":A,"create":{"c":{"@type":"User","name":"org","domainId":D,"credentials":{"0":{"@type":"Password","secret":PW}}}}},"c"])
ORG=basic("org@one.test",PW); ACC=json.loads(req("/jmap/session",ORG)[1])["primaryAccounts"]["urn:ietf:params:jmap:mail"]
drafts=[m["id"] for m in r1(ORG,["Mailbox/get",{"accountId":ACC},"m"])[1]["list"] if m.get("role")=="drafts"][0]
ident=r1(ORG,["Identity/set",{"accountId":ACC,"create":{"i":{"name":"Org","email":"org@one.test"}}},"i"])[1]["created"]["i"]["id"]
# Two originals: ASCII, with a header line past 77 characters (upstream quoted-printable-encodes the part then) and a
# multipart Content-Type (SES then needs a boundary the part lacks); and one whose Subject is raw UTF-8.
LONG="X-Long: "+"-".join(f"word{i}" for i in range(30))
def original(tag,subject):
    return ("From: Org <org@one.test>\r\nTo: <nobody@two.test>\r\n"+f"Subject: {subject}\r\n"
            +"Date: Tue, 21 Oct 2026 12:00:00 +0000\r\n"+f"Message-ID: <e2e-dsn-{tag}@one.test>\r\n"
            +LONG+"\r\nMIME-Version: 1.0\r\n"+'Content-Type: multipart/alternative; boundary="=_e2e"\r\n\r\n'
            +'--=_e2e\r\nContent-Type: text/plain; charset="utf-8"\r\n\r\nhello\r\n--=_e2e--\r\n').encode()
SENT={"ascii":original("ascii","an outside recipient that does not exist"),"utf8":original("utf8","Grüße, ein Empfänger, den es nicht gibt")}
for tag,raw in SENT.items():
    s,b=req(f"/jmap/upload/{ACC}/",ORG,raw,"message/rfc822")
    blob=json.loads(b)["blobId"]
    r=r1(ORG,["Email/import",{"accountId":ACC,"emails":{"e":{"blobId":blob,"mailboxIds":{drafts:True},"keywords":{"$draft":True}}}},"e"])[1]
    eid=(r.get("created") or {}).get("e",{}).get("id")
    r=r1(ORG,["EmailSubmission/set",{"accountId":ACC,"create":{"s":{"identityId":ident,"emailId":eid,
        "envelope":{"mailFrom":{"email":"org@one.test"},"rcptTo":[{"email":"nobody@two.test"}]}}}},"s"])[1]
    check("s" in (r.get("created") or {}), f"setup: the {tag} original is submitted to nobody@two.test", r.get("notCreated",""))
def bounces():
    found={}
    for i in r1(ORG,["Email/query",{"accountId":ACC},"q"])[1].get("ids",[]):
        g=r1(ORG,["Email/get",{"accountId":ACC,"ids":[i],"properties":["blobId"]},"g"])[1]["list"][0]
        raw=req(f"/jmap/download/{ACC}/{g['blobId']}/m",ORG)[1]
        if b"multipart/report" not in raw.split(b"\r\n\r\n",1)[0]: continue
        for tag in SENT:
            if f"<e2e-dsn-{tag}@one.test>".encode() in raw or f"e2e-dsn-{tag}@one.test".encode() in raw.replace(b"=\r\n",b""): found[tag]=raw
    return found
got={}
for _ in range(36):
    got=bounces()
    if len(got)==len(SENT): break
    time.sleep(5)
def third_part(raw):
    # The raw bytes of the report's third part: its own headers, then its body, exactly as sent.
    head,body=raw.split(b"\r\n\r\n",1)
    b=head.split(b'boundary="',1)[1].split(b'"',1)[0]
    parts=body.split(b"--"+b)[1:-1]
    p=parts[2] if len(parts)>2 else b""
    h,_,bd=p.lstrip(b"\r\n").partition(b"\r\n\r\n")
    return h.decode(errors="replace"),bd
for tag,sent in SENT.items():
    raw=got.get(tag)
    check(raw is not None, f"setup: the {tag} original bounces back to org")
    if raw is None: continue
    h,body=third_part(raw)
    ctype=h.split("Content-Type:",1)[-1].split(";")[0].split("\r\n")[0].strip().lower()
    cte=h.split("Content-Transfer-Encoding:",1)[-1].split("\r\n")[0].strip().lower() if "Content-Transfer-Encoding:" in h else ""
    headers=sent.split(b"\r\n\r\n",1)[0]
    # A control: whatever the encoding, the part carries the original's Message-ID (upstream's too, once decoded).
    decoded=body.replace(b"=\r\n",b"").replace(b"=3D",b"=")
    check(f"<e2e-dsn-{tag}@one.test>".encode() in decoded, f"control: the {tag} bounce's third part carries the original's Message-ID")
    want="8bit" if tag=="utf8" else "7bit"
    check(ctype=="text/rfc822-headers", f"the {tag} bounce returns the headers as text/rfc822-headers, not message/rfc822", ctype)
    check(cte==want and headers in body, f"the {tag} bounce returns every header byte for byte, in {want}", cte)
print("RESULT", "fail" if fails else "pass", len(fails)); sys.exit(1 if fails else 0)
PY
