#!/usr/bin/env bash
# End-to-end: the screening hook is passed the server's headers, and a junk verdict is acted on only by an account that opted in.
# usage: e2e-spam-screen.sh <stalwart image>
#
# Patch 0018 (MainThrive MAI-1072, design record MAIL_SPAM_STRATEGY_DESIGN_RECORD.md § 5.2) fills the MTA hook's serverHeaders from
# the DATA header buffer, and at delivery, for mail the spam filter scored, sets the percentage of an account with a `spam-screen`
# lookup row to 100 when the TOPMOST X-MainThrive-Screen is exactly `v=1; verdict=junk`. Here a stub answers as mail-screen does:
# by the subject, it deletes every sender copy (index 1, N times) and inserts its own at the top, or it answers a bare accept, as
# the service does when it does not run or skips. Accounts: scr (a row, no script), nor (no row), srl (a row and a webmail folder
# rule), lvl (a row and a Lenient level), fwd (no row, forwards a copy to scr). Scores come from the pinned spam rules on an
# internal network with a DNS stub, as in e2e-spam-level.sh: "low" is 4.20 and "high" 6.20, either side of Normal's line.
# Against the image before 0018, the serverHeaders checks, every check that a junk verdict is acted on and the failed lookup's log
# check FAIL. Everything a verdict must not do passes there, because that image reads none.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-screen-$$; C=e2e-screen-stalwart-$$; K=e2e-screen-client-$$; N=e2e-screen-dns-$$; R=e2e-screen-rules-$$; H=e2e-screen-hook-$$
RULES=https://github.com/stalwartlabs/spam-filter/releases/download/v3.0.2/spam-filter-rules.json.gz
RULES_SHA256=1d3a66f6fa9a32f711c5b3a73853663eff27c994a46e8f6a0db64a9b2a580f52
# In no body but the test's: a log that carried message content would carry this.
MARKER=screen-body-marker-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data" "$W/rules" "$W/dns" "$W/hook"; chmod -R 777 "$W"
curl -fsSL "$RULES" -o "$W/rules/spam-filter-rules.json.gz"
echo "$RULES_SHA256  $W/rules/spam-filter-rules.json.gz" | sha256sum -c --quiet - || { echo "FAIL the pinned spam rules changed"; exit 1; }
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" "$N" "$R" "$H" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
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
    flags = 0x8180 if rr or qname in HOSTS else 0x8183
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
docker run -d --name "$R" --network "$NET" -v "$W/rules:/r:ro" python:3.12-alpine \
  python3 -m http.server 8000 -d /r >/dev/null
# The hook, answering as mail-screen does (apps/api/src/mail-screen/app.ts), by the subject. It keeps each request's headers.
docker run -d --name "$H" --network "$NET" -v "$W/hook:/hook" python:3.12-alpine python3 -c '
import http.server, json
NAME = "X-MainThrive-Screen"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        q = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        m = q["message"]; subject = next((v.strip() for k, v in m["headers"] if k.lower() == "subject"), "")
        open("/hook/requests.jsonl", "a").write(json.dumps({"subject": subject, "serverHeaders": m.get("serverHeaders"), "headers": m["headers"]}) + "\n")
        verdict = "junk" if "says-junk" in subject else "pass" if "says-pass" in subject else None
        mods = []
        if verdict:
            forged = sum(k.strip().lower() == NAME.lower() for k, _ in m["headers"])
            mods = [{"type": "deleteHeader", "index": 1, "name": NAME}] * forged + [{"type": "insertHeader", "index": 0, "name": NAME, "value": f"v=1; verdict={verdict}"}]
        r = json.dumps({"action": "accept", "modifications": mods}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(r))); self.end_headers(); self.wfile.write(r)
http.server.ThreadingHTTPServer(("", 8000), H).serve_forever()' >/dev/null
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
echo "nameserver $(ip_of "$N")" > "$W/resolv.conf"
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test --memory 1g --memory-swap 1g \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/resolv.conf:/etc/resolv.conf:ro" \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" -e MARKER="$MARKER" -e RULES_AT="$(ip_of "$R"):8000" -e HOOK_AT="$(ip_of "$H"):8000" -v "$W/hook:/hook:ro" python:3.12-alpine sleep 900 >/dev/null
ip_of "$K" > "$W/dns/client-ip"
set +e
docker exec -i "$K" python3 - <<'PY'
import base64,email.utils,json,os,socket,time,urllib.request
B="http://stalwart:8080"; fails=[]
for _ in range(90):
    try: urllib.request.urlopen(B+"/healthz/ready",timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit("stalwart never became ready")
# The verdict line is fixed text, so build.yml can name it; what was seen goes on the next line.
def check(ok,msg,got=""): print(("PASS " if ok else "FAIL ")+msg); got!="" and print(f"     got: {got}"); ok or fails.append(msg)
basic=lambda u,p: "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission","urn:ietf:params:jmap:sieve","urn:stalwart:jmap"]
def req(path,auth,raw=None,ctype="application/json"):
    with urllib.request.urlopen(urllib.request.Request(B+path,data=raw,headers={"Authorization":auth,"Content-Type":ctype}),timeout=60) as x: return x.read()
def calls(auth,cs): return json.loads(req("/jmap/",auth,json.dumps({"using":U,"methodCalls":cs}).encode()))["methodResponses"]
def one(auth,name,args): return calls(auth,[[name,args,"x"]])[0][1]
ADM=basic("admin",os.environ["ADMIN"]); A=json.loads(req("/jmap/session",ADM))["primaryAccounts"]["urn:stalwart:jmap"]
def xset(obj,**kw): return one(ADM,f"x:{obj}/set",{"accountId":A,**kw})
def created(r):
    c=(r.get("created") or {}).get("n")
    if not c: raise SystemExit(f"not created: {r}")
    return c["id"]
def action(kind): created(xset("Action",create={"n":{"@type":kind}})); time.sleep(1)
D=created(xset("Domain",create={"n":{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}}))
xset("SpamPyzor",update={"singleton":{"enable":False,"host":"127.0.0.1"}})
xset("SpamSettings",update={"singleton":{"spamFilterRulesUrl":f"http://{os.environ['RULES_AT']}/spam-filter-rules.json.gz"}})
created(xset("Tracer",create={"n":{"@type":"Stdout","enable":True,"level":"info","ansi":False,"multiline":False,"buffered":False,"lossy":False}}))
# The hook as the design record writes it (§ 5.2): the spam filter's own expression, failing open. By IP, since this server's
# resolver is the DNS stub.
created(xset("MtaHook",create={"n":{"url":f"http://{os.environ['HOOK_AT']}/hook","enable":{"match":{},"else":"is_empty(authenticated_as) && local_port != 2525"},"tempFailOnError":False,"timeout":3000,"stages":{"data":True}}}))
action("ReloadSettings")
TASK=created(xset("Task",create={"n":{"@type":"SpamFilterMaintenance","maintenanceType":"updateRules"}}))
for _ in range(120):
    t=one(ADM,"x:Task/get",{"accountId":A,"ids":[TASK]})
    if TASK in t.get("notFound",[]): break
    time.sleep(0.5)
else: raise SystemExit(f"the spam rules never loaded: {t['list']}")

# A webmail rule as Bulwark writes it (apps/api/src/email/bulwark-sieve.ts renders the same guard).
RULE=b"""require ["fileinto", "relational", "comparator-i;ascii-numeric", "spamtestplus"];
# Rule: Invoices
if allof(header :contains "subject" "Invoice", not spamtest :percent :value "ge" :comparator "i;ascii-numeric" "50") {
    fileinto "Invoices";
}
"""
FORWARD=b'require ["copy"];\r\nredirect :copy "scr@one.test";\r\n'
SCRIPTS={"srl":RULE,"fwd":FORWARD}
PW,ID,AU,J,ROWS={},{},{},{},[]
def row(ns,key,value): ROWS.append(created(xset("MemoryLookupKeyValue",create={"n":{"namespace":ns,"key":key,"value":value,"isGlobPattern":False}})))
for name in ("scr","nor","srl","lvl","fwd"):
    PW[name]=base64.b64encode(os.urandom(18)).decode()
    ID[name]=created(xset("Account",create={"n":{"@type":"User","name":name,"domainId":D,"credentials":{"0":{"@type":"Password","secret":PW[name]}}}}))
    AU[name]=basic(f"{name}@one.test",PW[name]); J[name]=json.loads(req("/jmap/session",AU[name]))["primaryAccounts"]["urn:ietf:params:jmap:mail"]
    if name in SCRIPTS:
        if name=="srl": one(AU[name],"Mailbox/set",{"accountId":J[name],"create":{"m":{"name":"Invoices"}}})
        blob=json.loads(req(f"/jmap/upload/{J[name]}/",AU[name],SCRIPTS[name],"application/sieve"))["blobId"]
        r=one(AU[name],"SieveScript/set",{"accountId":J[name],"create":{"s":{"name":"webmail","blobId":blob}},"onSuccessActivateScript":"#s"})
        if not r.get("created"): raise SystemExit(f"{name}'s script not created: {r}")
    # Keyed by the account's id, as the API keys spam-level (email_mailboxes.provider_mailbox_id).
    if name in ("scr","srl","lvl"): row("spam-screen",ID[name],"1")
row("spam-level",ID["lvl"],"70")
action("ReloadLookupStores")

OPENED=[0.0]
def smtp(rcpts,msg):
    # A fresh install throttles each sender IP to 5 new SMTP connections a second: open at most 3 a second.
    time.sleep(max(0,OPENED[0]+0.34-time.time())); OPENED[0]=time.time()
    c=socket.create_connection(("stalwart",25),timeout=120); f=c.makefile("rb")
    def rep():
        while True:
            l=f.readline()
            if not l: return "closed"
            if l[3:4]!=b"-": return l[:3].decode()
    got=rep()
    for x in [b"EHLO mail.example.com\r\n",b"MAIL FROM:<sam@example.com>\r\n",*[f"RCPT TO:<{r}@one.test>\r\n".encode() for r in rcpts],b"DATA\r\n"]:
        if got not in ("220","250","354"): break
        c.sendall(x); got=rep()
    if got=="354": c.sendall(msg+b"\r\n.\r\n"); got=rep()
    try: c.sendall(b"QUIT\r\n")
    except OSError: pass
    c.close(); return got
# Ordinary mail scores 3.20 here. "low" has no Date header, MISSING_DATE (+1.0): 4.20. "high" has a Date and a subject in
# capitals, SUBJ_ALL_CAPS (+3.0): 6.20 (measured for e2e-spam-level.sh).
BODY=f"Hi,\r\n\r\nAre we still on for lunch on Friday? {os.environ['MARKER']}\r\n\r\nSam\r\n".encode()
def send(rcpts,subject,forged=(),high=False):
    if high: subject=subject.upper()
    date=f"Date: {email.utils.formatdate()}\r\n" if high else ""
    extra="".join(f"{h}\r\n" for h in forged)
    m=(f"{extra}From: Sam <sam@example.com>\r\nTo: {rcpts[0]}@one.test\r\nSubject: {subject}\r\n{date}"
       f"Message-ID: <{subject.replace(' ','.')}@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").encode()+BODY
    st=smtp(rcpts,m)
    if st!="250": raise SystemExit(f"{subject}: SMTP answered {st}")
    return subject
FOLDERS={}
def folders(name):
    if name not in FOLDERS:
        r=one(AU[name],"Mailbox/get",{"accountId":J[name],"properties":["name","role"]})
        FOLDERS[name]={m["id"]:(m.get("role") or m["name"]).lower() for m in r["list"]}
    return FOLDERS[name]
def delivered(name,subj,tries=240):
    for _ in range(tries):
        r=calls(AU[name],[["Email/query",{"accountId":J[name],"filter":{"subject":subj}},"q"],["Email/get",{"accountId":J[name],"#ids":{"resultOf":"q","name":"Email/query","path":"/ids"},
            "properties":["subject","mailboxIds","header:X-Spam-Status:asText","header:X-Spam-Score:asText","header:X-MainThrive-Screen:asText:all"]},"g"]])
        hit=[e for e in r[1][1]["list"] if e["subject"]==subj]
        if hit:
            e=hit[0]; return {"folder":",".join(sorted(folders(name)[m] for m in e["mailboxIds"])),"status":e.get("header:X-Spam-Status:asText"),
                               "score":e.get("header:X-Spam-Score:asText"),"verdicts":e.get("header:X-MainThrive-Screen:asText:all") or []}
        time.sleep(0.25)
    return None
JUNK={"folder":"junk","status":"Yes"}; INBOX={"folder":"inbox","status":"No"}; RULED={"folder":"invoices","status":"No"}
def at(name,subj,want,label,verdicts=None):
    e=delivered(name,subj)
    ok=e is not None and {k:e[k] for k in want}==want and (verdicts is None or e["verdicts"]==verdicts)
    check(ok,label,e)
J1,P1=["v=1; verdict=junk"],["v=1; verdict=pass"]
FJ,FP="X-MainThrive-Screen: v=1; verdict=junk","X-MainThrive-Screen: v=1; verdict=pass"

# What the hook is passed.
s=send(["nor"],"plain first")
delivered("nor",s)
hooked=[json.loads(l) for l in open("/hook/requests.jsonl")]
req0=next((h for h in hooked if h["subject"]==s),None)
if req0 is None: raise SystemExit("the hook was never called")
sh={k.lower():v for k,v in (req0["serverHeaders"] or [])}
check("dmarc=" in sh.get("authentication-results",""),"the hook is passed Authentication-Results",sh.get("authentication-results"))
check("example.com" in sh.get("received-spf",""),"the hook is passed Received-SPF",sh.get("received-spf"))
check(bool(sh.get("x-spam-result","").strip()),"the hook is passed X-Spam-Result")
check(sh.get("x-spam-score","").strip().startswith("ham, score="),"the hook is passed X-Spam-Score",sh.get("x-spam-score"))
own={k.lower() for k,_ in req0["headers"]}
check(not own&{"authentication-results","received-spf","x-spam-result","x-spam-score"},"control: the message's own headers carry none of them",sorted(own))
check(delivered("nor",s)["score"] and 4.0<=float(delivered("nor",s)["score"].split("score=")[1])<5.0,"setup: a low message scores from 4.0 to 5.0",delivered("nor",s)["score"])

# A verdict is acted on only by the account that opted in.
s=send(["scr","nor"],"says-junk both")
at("scr",s,JUNK,"a junk verdict: the spam-screen account's copy goes to Junk, Yes",J1)
at("nor",s,INBOX,"control: a junk verdict: the account with no row keeps its copy in the Inbox, No",J1)
s=send(["scr","nor"],"says-pass both")
at("scr",s,INBOX,"control: a pass verdict: the spam-screen account's copy stays in the Inbox, No",P1)
at("nor",s,INBOX,"control: a pass verdict: the account with no row keeps its copy in the Inbox, No",P1)
# The service runs: every sender copy deleted, whichever way they point.
s=send(["scr"],"says-junk forged pass twice",forged=[FP,FP])
at("scr",s,JUNK,"the service's junk over two forged passes: Junk, Yes, one verdict stored",J1)
s=send(["scr"],"says-pass forged junk twice",forged=[FJ,FJ])
at("scr",s,INBOX,"control: the service's pass over two forged junks: Inbox, No, one verdict stored",P1)

# The service does not run: what the sender wrote stays, and only the topmost counts.
s=send(["scr"],"silent forged pass high",forged=[FP],high=True)
at("scr",s,JUNK,"control: a forged pass changes nothing: a high message still goes to Junk, Yes")
s=send(["scr"],"silent forged pass low",forged=[FP])
at("scr",s,INBOX,"control: a forged pass changes nothing: a low message stays in the Inbox, No")
s=send(["nor"],"silent forged junk no row",forged=[FJ])
at("nor",s,INBOX,"control: a forged junk to an account with no row: Inbox, No")
s=send(["scr"],"silent pass above junk",forged=[FP,FJ])
at("scr",s,INBOX,"control: pass above junk: only the topmost counts: Inbox, No")
s=send(["scr"],"silent junk above pass",forged=[FJ,FP])
at("scr",s,JUNK,"junk above pass: only the topmost counts: Junk, Yes")
s=send(["scr"],"silent lower case folded",forged=["x-mainthrive-screen: v=1;\r\n verdict=junk"])
at("scr",s,JUNK,"the header's name in any case, its value folded: Junk, Yes")
for label,value in (("no version","verdict=junk"),("another version","v=2; verdict=junk"),("capitals","v=1; verdict=JUNK"),("a third tag","v=1; verdict=junk; x=y"),("a longer word","v=1; verdict=junky"),("empty","")):
    s=send(["scr"],f"silent unread {label}",forged=[f"X-MainThrive-Screen: {value}"])
    at("scr",s,INBOX,f"control: a verdict that cannot be read ({label}) leaves Stalwart's decision: Inbox, No")
# Every reader of the percentage agrees.
s=send(["srl"],"says-junk Invoice")
at("srl",s,JUNK,"a junk verdict with a webmail folder rule: Junk, Yes, and the rule does not run")
s=send(["srl"],"says-pass Invoice")
at("srl",s,RULED,"control: a pass verdict with a webmail folder rule: the rule files it, No")
s=send(["lvl"],"says-pass lenient",high=True)
at("lvl",s,INBOX,"control: a pass verdict at Lenient: a high message stays in the Inbox, No (the level still applies)")
s=send(["lvl"],"says-junk lenient",high=True)
at("lvl",s,JUNK,"a junk verdict at Lenient: the same high message goes to Junk, Yes")

# Mail the spam filter did not score. A forward of a screened message, delivered here, carries the old verdict.
s=send(["fwd"],"says-junk forwarded")
at("fwd",s,INBOX,"control: the forwarding account (no row) keeps its copy in the Inbox, No",J1)
e=delivered("scr",s)
check(e is not None and e["verdicts"]==J1,"control: the forwarded copy reached the spam-screen account still carrying the old verdict",e)
check(e is not None and e["folder"]=="inbox","a forward carrying an old junk verdict is ignored: the copy stays in the Inbox",e)
# A signed-in user's own message is not scored either.
MU=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"]
ident=[i for i in one(AU["nor"],"Identity/get",{"accountId":J["nor"]})["list"] if i["email"]=="nor@one.test"][0]["id"]
drafts=[m for m in one(AU["nor"],"Mailbox/get",{"accountId":J["nor"]})["list"] if m.get("role")=="drafts"][0]["id"]
sub="signed-in with a typed verdict"
r=calls(AU["nor"],[["Email/set",{"accountId":J["nor"],"create":{"e":{"mailboxIds":{drafts:True},"from":[{"email":"nor@one.test"}],"to":[{"email":"scr@one.test"}],"subject":sub,"header:X-MainThrive-Screen:asText":"v=1; verdict=junk","bodyValues":{"b":{"value":"Hi"}},"textBody":[{"partId":"b","type":"text/plain"}]}}},"e"],
    ["EmailSubmission/set",{"accountId":J["nor"],"create":{"s":{"emailId":"#e","identityId":ident}}},"s"]])
if not (r[1][1].get("created") or {}).get("s"): raise SystemExit(f"the submission failed: {r}")
e=delivered("scr",sub)
check(e is not None and e["verdicts"]==J1,"control: a signed-in user's message reached the spam-screen account carrying a typed verdict",e)
check(e is not None and e["folder"]=="inbox","a typed verdict on a signed-in user's message is ignored: Inbox",e)

# The store unavailable: every row gone, and the namespace a Redis store nobody listens on.
for r_ in ROWS: xset("MemoryLookupKeyValue",destroy=[r_])
r=xset("StoreLookup",create={"n":{"namespace":"spam-screen","store":{"@type":"Redis","url":"redis://127.0.0.1:1"}}})
if not r.get("created"): raise SystemExit(f"the unreachable lookup store was not created: {r}")
action("ReloadLookupStores")
t0=time.time(); s=send(["scr"],"says-junk unavailable")
e=delivered("scr",s,tries=120); took=round(time.time()-t0,1)
check(e is not None and took<30,"with the lookup store unavailable, the message is delivered at once, not deferred",f"{took} s, {e}")
check(e is not None and {k:e[k] for k in INBOX}==INBOX,"control: and as not opted in, despite the junk verdict: Inbox, No",e)
raise SystemExit(1 if fails else 0)
PY
rc=$?
set -e
# What the patch logs (Stalwart's own log, the container's stdout), each an exact count.
LOG=$(docker logs "$C" 2>&1)
fails=0
logcount() { # <want> <label> <fixed text>...: the log lines carrying every text, counted
  local want=$1 label=$2 lines=$LOG got; shift 2
  for t in "$@"; do lines=$(grep -F -- "$t" <<<"$lines" || true); done
  got=$(grep -c . <<<"$lines" || true)
  if [ "$got" -eq "$want" ]; then echo "PASS $label"; else echo "FAIL $label"; echo "     got: $got line(s)"; fails=$((fails+1)); fi
}
logcount 1 "the failed lookup is logged, once" "Spam screening lookup failed, delivering as not opted in." "scr@one.test"
logcount 0 "control: the message's body is never logged" "$MARKER"
# So a log that records nothing cannot read as "nothing was logged".
if grep -qF "(message-ingest." <<<"$LOG"; then echo "PASS control: Stalwart's log records deliveries"; else echo "FAIL control: Stalwart's log records deliveries"; fails=$((fails+1)); fi
[ "$rc" -eq 0 ] && [ "$fails" -eq 0 ] && { echo "all passed"; exit 0; }
echo "failed (client exit $rc, $fails log check(s))"; exit 1
