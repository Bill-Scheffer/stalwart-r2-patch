#!/usr/bin/env bash
# End-to-end: the inbound spam filter analyses a bounded start of each message's text, so what it costs is bounded,
# and ordinary mail scores exactly as before.
# usage: e2e-spam-text-cap.sh <stalwart image>
#
# Every word and every space of a text part becomes a 224-byte token, held until the message is scored, so the filter
# cost ~40 times the text: a 10 MiB text/plain message by SMTP took ~430 MiB, against ~30 MiB by IMAP APPEND, which
# does not filter (measured on -bodycap1, MAI-1077). Patch 0011 analyses the first 512 KiB of each part's text, plain
# or extracted from HTML, and 1 MiB per message, and reads up to 4 MiB of HTML markup. Here:
# - an 8 MiB text/plain message on port 25 costs under 150 MiB of anonymous memory while it is received, filtered and
#   delivered (sampled from the container's own cgroup);
# - a URL past the first 512 KiB of a part, and one at the start of a third part past the first 1 MiB of the message,
#   are not analysed, while the same URL early in a large part, or in a second part, still is;
# - a control set, ordinary mail (a large plain-and-HTML newsletter among it) and spam whose signal sits early in a
#   large body, scores exactly as -bodycap1 scored it: the same verdict, score and tags (measured with this script).
# The scores come from Stalwart's spam rules, which a server downloads at startup (production takes upstream's latest
# release): here a pinned release, checked by hash and served on an internal network, with a DNS stub that answers
# NXDOMAIN to all but the sender's own names, so no score depends on the runner's network or resolver. Pyzor, a network
# lookup, is off.
# Against -bodycap1 the memory check and the two past-the-bound checks FAIL, and the control set passes. Against a
# build that cut HTML on its markup, the newsletter scored PARTS_DIFFER (+1.0) and the control set FAILED.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-text-$$; C=e2e-text-stalwart-$$; K=e2e-text-client-$$; N=e2e-text-dns-$$; R=e2e-text-rules-$$
RULES=https://github.com/stalwartlabs/spam-filter/releases/download/v3.0.2/spam-filter-rules.json.gz
RULES_SHA256=1d3a66f6fa9a32f711c5b3a73853663eff27c994a46e8f6a0db64a9b2a580f52
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data" "$W/rules" "$W/dns"; chmod -R 777 "$W"
curl -fsSL "$RULES" -o "$W/rules/spam-filter-rules.json.gz"
echo "$RULES_SHA256  $W/rules/spam-filter-rules.json.gz" | sha256sum -c --quiet - || { echo "FAIL the pinned spam rules changed"; exit 1; }
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" "$N" "$R" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
ADMIN=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
docker network create --internal "$NET" >/dev/null
# The DNS stub: the client's reverse name, and mail.example.com and example.com, so the sender resolves as an ordinary
# sending server does, and NXDOMAIN for anything else.
docker run -d --name "$N" --network "$NET" -v "$W/dns:/w:ro" python:3.12-alpine python3 -c '
import socket, socketserver, struct, threading
def enc(name): return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
NAME = enc("mail.example.com"); HOSTS = (NAME, enc("example.com"))
def answer(q):
    end = 12
    while q[end]: end += q[end] + 1
    qname, qtype = q[12:end + 1].lower(), struct.unpack(">H", q[end + 1:end + 3])[0]
    try: ip = open("/w/client-ip").read().strip()
    except OSError: ip = "0.0.0.0"
    rr = b""
    if qtype == 12 and qname == enc(".".join(ip.split(".")[::-1]) + ".in-addr.arpa"):
        rr = struct.pack(">HHHIH", 0xC00C, 12, 1, 60, len(NAME)) + NAME
    elif qtype == 1 and qname in HOSTS:
        rr = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    # QR, RD and RA, and NXDOMAIN unless the name is one of these.
    flags = 0x8180 if rr or qname in HOSTS else 0x8183
    return q[:2] + struct.pack(">HHHHH", flags, 1, 1 if rr else 0, 0, 0) + q[12:end + 5] + rr
class T(socketserver.BaseRequestHandler):
    def handle(self):
        f = self.request.makefile("rb")
        while (h := f.read(2)) and len(h) == 2:
            r = answer(f.read(struct.unpack(">H", h)[0])); self.request.sendall(struct.pack(">H", len(r)) + r)
# TCP too: the resolver retries over TCP when a UDP answer fails (tcpOnError).
socketserver.ThreadingTCPServer.allow_reuse_address = True
threading.Thread(target=socketserver.ThreadingTCPServer(("", 53), T).serve_forever, daemon=True).start()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("", 53))
while True:
    q, a = u.recvfrom(4096)
    try: u.sendto(answer(q), a)
    except Exception: pass' >/dev/null
docker run -d --name "$R" --network "$NET" -v "$W/rules:/r:ro" python:3.12-alpine \
  python3 -m http.server 8000 -d /r >/dev/null
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
# Stalwart resolves through the stub alone, so it reaches the rules server by address.
echo "nameserver $(ip_of "$N")" > "$W/resolv.conf"
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test --memory 1g --memory-swap 1g \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/resolv.conf:/etc/resolv.conf:ro" \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
ID=$(docker inspect -f '{{.Id}}' "$C"); CG=
for d in "/sys/fs/cgroup/system.slice/docker-$ID.scope" "/sys/fs/cgroup/docker/$ID"; do [ -r "$d/memory.stat" ] && CG=$d && break; done
[ -n "$CG" ] || { echo "FAIL no cgroup v2 memory.stat for the container: the memory check cannot measure"; exit 1; }
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" -e RULES_AT="$(ip_of "$R"):8000" -v "$CG:/cg:ro" python:3.12-alpine sleep 900 >/dev/null
ip_of "$K" > "$W/dns/client-ip"
docker exec -i "$K" python3 - <<'PY'
import base64,email.utils,json,os,random,socket,threading,time,urllib.request
B="http://stalwart:8080"; fails=[]
for _ in range(90):
    try: urllib.request.urlopen(B+"/healthz/ready",timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit("stalwart never became ready")
# The verdict line is fixed text, so build.yml can name it; what was seen goes on the next line.
def check(ok,msg,got=""): print(("PASS " if ok else "FAIL ")+msg); got!="" and print(f"     got: {got}"); ok or fails.append(msg)
basic=lambda u,p: "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:stalwart:jmap"]
def req(path,auth,raw=None):
    h={"Authorization":auth,"Content-Type":"application/json"}
    with urllib.request.urlopen(urllib.request.Request(B+path,data=raw,headers=h),timeout=60) as x: return x.read()
def calls(auth,cs): return json.loads(req("/jmap/",auth,json.dumps({"using":U,"methodCalls":cs}).encode()))["methodResponses"]
ADM=basic("admin",os.environ["ADMIN"]); A=json.loads(req("/jmap/session",ADM))["primaryAccounts"]["urn:stalwart:jmap"]
D=calls(ADM,[["x:Domain/set",{"accountId":A,"create":{"d":{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}}},"d"]])[0][1]["created"]["d"]["id"]
PW=base64.b64encode(os.urandom(18)).decode()
r=calls(ADM,[["x:Account/set",{"accountId":A,"create":{"u":{"@type":"User","name":"u0","domainId":D,"credentials":{"0":{"@type":"Password","secret":PW}}}}},"c"]])[0][1]
if len(r.get("created") or {})!=1: raise SystemExit(f"account not created: {r}")
# The pinned rules, in place of the release a server would download. Pyzor is a network lookup, so it is off (and its
# host, which the reload resolves, is local).
r=calls(ADM,[["x:SpamPyzor/set",{"accountId":A,"update":{"singleton":{"enable":False,"host":"127.0.0.1"}}},"p"],
             ["x:SpamSettings/set",{"accountId":A,"update":{"singleton":{"spamFilterRulesUrl":f"http://{os.environ['RULES_AT']}/spam-filter-rules.json.gz"}}},"s"],
             ["x:Action/set",{"accountId":A,"create":{"a":{"@type":"ReloadSettings"}}},"a"],
             ["x:Task/set",{"accountId":A,"create":{"t":{"@type":"SpamFilterMaintenance","maintenanceType":"updateRules"}}},"t"]])
if any("singleton" not in (x[1].get("updated") or {}) for x in r[:2]) or "a" not in (r[2][1].get("created") or {}) or "t" not in (r[3][1].get("created") or {}): raise SystemExit(f"rules not requested: {r}")
for _ in range(120):
    if calls(ADM,[["x:SpamTag/query",{"accountId":A,"calculateTotal":True},"q"]])[0][1].get("total"): break
    time.sleep(0.5)
else:
    t=calls(ADM,[["x:Task/get",{"accountId":A,"ids":[r[3][1]["created"]["t"]["id"]]},"g"]])[0][1]["list"]
    raise SystemExit(f"the spam rules never loaded: {t}")
AU=basic("u0@one.test",PW); J=json.loads(req("/jmap/session",AU))["primaryAccounts"]["urn:ietf:params:jmap:mail"]
KiB=1024; MiB=1024*KiB

# A fresh install throttles each sender IP to 5 new SMTP connections a second: open at most 4 a second.
OPENED=[0.0]
def smtp(msg):
    time.sleep(max(0,OPENED[0]+0.25-time.time())); OPENED[0]=time.time()
    c=socket.create_connection(("stalwart",25),timeout=120); f=c.makefile("rb")
    def rep():
        while True:
            l=f.readline()
            if not l: return "closed"
            if l[3:4]!=b"-": return l[:3].decode()
    got=rep()
    for x in [b"EHLO mail.example.com\r\n",b"MAIL FROM:<sam@example.com>\r\n",b"RCPT TO:<u0@one.test>\r\n",b"DATA\r\n"]:
        if got not in ("220","250","354"): break
        c.sendall(x); got=rep()
    if got=="354": c.sendall(msg+b"\r\n.\r\n"); got=rep()
    try: c.sendall(b"QUIT\r\n")
    except OSError: pass
    c.close(); return got
def delivered(subject):
    # The message once it is in a mailbox, with what the spam filter wrote on it.
    for _ in range(240):
        r=calls(AU,[["Email/query",{"accountId":J,"filter":{"subject":subject}},"q"],["Email/get",{"accountId":J,"#ids":{"resultOf":"q","name":"Email/query","path":"/ids"},
            "properties":["subject","header:X-Spam-Score:asText","header:X-Spam-Result:asText"]},"g"]])
        hit=[e for e in r[1][1]["list"] if e["subject"]==subject]
        if hit: return hit[0]
        time.sleep(0.25)
    raise SystemExit(f"{subject!r} was never delivered")
def tags(e): return set(t.split(" ")[0] for t in (e.get("header:X-Spam-Result:asText") or "").split(", ") if t)
def msg(subject,ctype,body):
    return (f"From: Sam Lee <sam@example.com>\r\nTo: u0@one.test\r\nSubject: {subject}\r\nDate: {email.utils.formatdate()}\r\n"
            f"Message-ID: <{subject.replace(' ','.')}@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: {ctype}\r\n\r\n").encode()+body
PROSE=(b"Thanks for sending the minutes over. I read through the notes from Tuesday and agree with the plan to move\r\n"
       b"the review to the first week of next month, once the quarterly numbers are in and everyone has had time.\r\n")
def prose(size): return PROSE*(size//len(PROSE)+1)
URL=b"Claim your prize now at http://192.0.2.10/claim?id=1 before it expires!!!\r\n"
def mixed(*parts):
    return b"".join(b"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"+p+b"\r\n" for p in parts)+b"--b--\r\n"
def alternative(plain,html):
    return (b"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"+plain+b"\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            +html+b"\r\n--b--\r\n")
def html_of(text): return b"<html><body><p>"+text.replace(b"\r\n",b"</p>\r\n<p>")+b"</p></body></html>"

# 1. Memory. One small message first, so what the first delivery allocates once is not counted.
smtp(msg("warm up","text/plain; charset=utf-8",PROSE)); delivered("warm up"); time.sleep(2)
def anon(): return int(next(l.split()[1] for l in open("/cg/memory.stat") if l.startswith("anon ")))
base=anon(); peak=[base]; done=threading.Event()
def sample():
    while not done.is_set(): peak[0]=max(peak[0],anon()); time.sleep(0.02)
t=threading.Thread(target=sample); t.start()
ascii_line=b"abcdefghij "*7+b"\r\n"
st=smtp(msg("eight mib of text","text/plain; charset=utf-8",ascii_line*(8*MiB//len(ascii_line))))
delivered("eight mib of text"); time.sleep(1); done.set(); t.join()
cost=(peak[0]-base)//MiB
check(st=="250","an 8 MiB text/plain message on port 25 is accepted",st)
check(cost<150,"and receiving, filtering and delivering it costs under 150 MiB, not ~40 times its text",f"{cost} MiB")

# 2. The bound itself: past it nothing is analysed, before it everything still is.
cases={
  "url past the part bound": ("text/plain; charset=utf-8",prose(600*KiB)+URL,False,
      "a URL past the first 512 KiB of a text part is not analysed"),
  "url early in a large part": ("text/plain; charset=utf-8",URL+prose(2*MiB),True,
      "the same URL at the start of a 2 MiB part still is"),
  "url in a third part": ("multipart/mixed; boundary=b",mixed(prose(600*KiB),prose(600*KiB),URL+prose(KiB)),False,
      "a URL at the start of a third text part, past the first 1 MiB of the message, is not analysed"),
  "url in a second part": ("multipart/mixed; boundary=b",mixed(prose(600*KiB),URL+prose(KiB)),True,
      "and one at the start of the second part still is"),
}
for subject,(ctype,body,_,_) in cases.items(): smtp(msg(subject,ctype,body))
for subject,(_,_,want,label) in cases.items():
    got=tags(delivered(subject)); check(("SUSPICIOUS_URL" in got)==want,label,sorted(got))

# 3. The control set: what -bodycap1 wrote, exactly (score and tags), measured with this script.
def newsletter():
    words=(b"garden spring roses planting soil compost seeds water sunlight weeds harvest tomato herbs basil mint "
           b"travel flights hotel beach passport museum train coast island hiking trail map journey ferry harbour "
           b"kitchen recipe flour butter oven bread pastry sugar lemon ginger soup noodle spice pepper garlic "
           b"finance savings budget pension mortgage interest account rates invest shares bonds income taxes credit").split()
    plain=html=b""
    for i in range(40):
        w=words[i*3%len(words):][:15] or words[:15]; r=random.Random(i)
        text=b" ".join(b" ".join(r.choice(w) for _ in range(12))+b"." for _ in range(80))
        url=b"https://shop.news%d.example/section" % i
        plain+=text+b"\r\nMore: "+url+b"\r\n\r\n"
        html+=(b"<table role=\"presentation\" width=\"100%\"><tr><td style=\"padding:8px 16px;color:#333333;font-family:Arial,"
               b"Helvetica,sans-serif;font-size:15px;line-height:1.5\">"+text.replace(b". ",b".</td></tr>\r\n<tr><td style=\"padding:8px "
               b"16px;color:#333333;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5\">")
               +b"</td></tr><tr><td>More: <a href=\""+url+b"\">"+url+b"</a></td></tr></table>\r\n")
    return plain,b"<html><body>"+html+b"</body></html>"
HAM=('ham, score=3.20',
     'ARC_NA (0.00), DKIM2_NA (0.00), DKIM_NA (0.00), FROM_EQ_ENV_FROM (0.00), FROM_HAS_DN (0.00), MID_RHS_MATCH_ENV_FROM (0.00), RCPT_COUNT_ONE (0.00), SPF_NA (0.00), TO_DN_NONE (0.00), TO_MATCH_ENVRCPT_ALL (0.00), RCVD_COUNT_ZERO (0.10), RCVD_NO_TLS_LAST (0.10), AUTH_NA (1.00), DMARC_NA (1.00), MID_RHS_MATCH_FROM (1.00)')
CONTROLS={
  "lunch on friday": ("text/plain; charset=utf-8",b"Hi,\r\n\r\nAre we still on for lunch on Friday? I can book a table for noon.\r\n\r\nSam\r\n",
    HAM),
  "minutes from tuesday": ("multipart/alternative; boundary=b",alternative(PROSE*3,html_of(PROSE*3)),
    ('ham, score=3.20',
      'ARC_NA (0.00), DKIM2_NA (0.00), DKIM_NA (0.00), FROM_EQ_ENV_FROM (0.00), FROM_HAS_DN (0.00), HTML_SHORT_1 (0.00), MID_RHS_MATCH_ENV_FROM (0.00), RCPT_COUNT_ONE (0.00), SPF_NA (0.00), TO_DN_NONE (0.00), TO_MATCH_ENVRCPT_ALL (0.00), RCVD_COUNT_ZERO (0.10), RCVD_NO_TLS_LAST (0.10), AUTH_NA (1.00), DMARC_NA (1.00), MID_RHS_MATCH_FROM (1.00)')),
  "the full report": ("text/plain; charset=utf-8",prose(2*MiB),
    HAM),
  "the full report as html": ("multipart/alternative; boundary=b",alternative(prose(700*KiB),html_of(prose(700*KiB))),
    HAM),
  "you won": ("text/plain; charset=utf-8",URL,
    ('spam, score=8.20',
      'ARC_NA (0.00), DKIM2_NA (0.00), DKIM_NA (0.00), FROM_EQ_ENV_FROM (0.00), FROM_HAS_DN (0.00), MID_RHS_MATCH_ENV_FROM (0.00), RCPT_COUNT_ONE (0.00), SPF_NA (0.00), TO_DN_NONE (0.00), TO_MATCH_ENVRCPT_ALL (0.00), RCVD_COUNT_ZERO (0.10), RCVD_NO_TLS_LAST (0.10), AUTH_NA (1.00), DMARC_NA (1.00), MID_RHS_MATCH_FROM (1.00), SUSPICIOUS_URL (5.00)')),
  "you won big": ("text/plain; charset=utf-8",URL+prose(2*MiB),
    ('spam, score=8.20',
      'ARC_NA (0.00), DKIM2_NA (0.00), DKIM_NA (0.00), FROM_EQ_ENV_FROM (0.00), FROM_HAS_DN (0.00), MID_RHS_MATCH_ENV_FROM (0.00), RCPT_COUNT_ONE (0.00), SPF_NA (0.00), TO_DN_NONE (0.00), TO_MATCH_ENVRCPT_ALL (0.00), RCVD_COUNT_ZERO (0.10), RCVD_NO_TLS_LAST (0.10), AUTH_NA (1.00), DMARC_NA (1.00), MID_RHS_MATCH_FROM (1.00), SUSPICIOUS_URL (5.00)')),
  "your invoice": ("text/plain; charset=utf-8",b"Your invoice: http://cdn.example.org/wp-content/uploads/invoice.php or http://inv0ice.onion/pay\r\n"
      +prose(2*MiB),
    ('ham, score=3.30',
      'ARC_NA (0.00), DKIM2_NA (0.00), DKIM_NA (0.00), FROM_EQ_ENV_FROM (0.00), FROM_HAS_DN (0.00), HAS_ONION_URI (0.00), MID_RHS_MATCH_ENV_FROM (0.00), RCPT_COUNT_ONE (0.00), SPF_NA (0.00), TO_DN_NONE (0.00), TO_MATCH_ENVRCPT_ALL (0.00), WP_COMPROMISED (0.00), HAS_ANON_DOMAIN (0.10), RCVD_COUNT_ZERO (0.10), RCVD_NO_TLS_LAST (0.10), AUTH_NA (1.00), DMARC_NA (1.00), MID_RHS_MATCH_FROM (1.00)')),
  # Unclosed HTML that was not cut still scores as unbalanced: only a part the filter cut has its closing tags restored.
  "a note in unclosed html": ("text/html; charset=utf-8",b"<html><body><p>See you at noon on Friday, the usual place.</p>\r\n",
    ('ham, score=3.90',
      'ARC_NA (0.00), DKIM2_NA (0.00), DKIM_NA (0.00), FROM_EQ_ENV_FROM (0.00), FROM_HAS_DN (0.00), HTML_SHORT_1 (0.00), MID_RHS_MATCH_ENV_FROM (0.00), RCPT_COUNT_ONE (0.00), SPF_NA (0.00), TO_DN_NONE (0.00), TO_MATCH_ENVRCPT_ALL (0.00), RCVD_COUNT_ZERO (0.10), RCVD_NO_TLS_LAST (0.10), MIME_HTML_ONLY (0.20), HTML_UNBALANCED_TAG (0.50), AUTH_NA (1.00), DMARC_NA (1.00), MID_RHS_MATCH_FROM (1.00)')),
  "verify your account": ("text/html; charset=utf-8",b"<html><body><p>Your account is suspended. <a href=\"http://192.0.2.10/login\">https://www.paypal.com/signin</a></p>\r\n"
      +html_of(prose(2*MiB))[len(b"<html><body>"):],
    ('spam, score=13.90',
      'ARC_NA (0.00), DKIM2_NA (0.00), DKIM_NA (0.00), FROM_EQ_ENV_FROM (0.00), FROM_HAS_DN (0.00), MID_RHS_MATCH_ENV_FROM (0.00), RCPT_COUNT_ONE (0.00), SPF_NA (0.00), TO_DN_NONE (0.00), TO_MATCH_ENVRCPT_ALL (0.00), RCVD_COUNT_ZERO (0.10), RCVD_NO_TLS_LAST (0.10), MIME_HTML_ONLY (0.20), HTTP_TO_HTTPS (0.50), AUTH_NA (1.00), DMARC_NA (1.00), HTTP_TO_IP (1.00), MID_RHS_MATCH_FROM (1.00), PHISHING (4.00), SUSPICIOUS_URL (5.00)')),
  # A large newsletter, plain and HTML: the topic and the linked sites change through it, and the HTML is markup-heavy.
  # Cut on the HTML's markup instead of its text, the two alternatives would differ (PARTS_DIFFER, URI_COUNT_ODD).
  "the weekly newsletter": ("multipart/alternative; boundary=b",alternative(*newsletter()),
    HAM),
}
results=[]
for subject,(ctype,body,_) in CONTROLS.items(): smtp(msg(subject,ctype,body))
for subject,(_,_,want) in CONTROLS.items():
    e=delivered(subject); got=(e.get("header:X-Spam-Score:asText"),e.get("header:X-Spam-Result:asText")); results.append(got==want)
    check(got==want,f"control {subject!r} scores as it did before the patch",json.dumps(got))
check(all(results),"the control set scores as it did before the patch",f"{results.count(True)} of {len(results)}")
print(f"{len(fails)} failed" if fails else "all passed")
raise SystemExit(1 if fails else 0)
PY
