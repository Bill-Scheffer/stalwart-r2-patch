#!/usr/bin/env bash
# End-to-end: an account's spam level moves its Junk line, and a level that cannot be read delivers at Normal.
# usage: e2e-spam-level.sh <stalwart image>
#
# Patch 0015 reads one optional `spam-level` lookup row per recipient account at delivery, keyed by the account's id,
# whose value is the line L (1 to 99), and rescales the recipient's spam percentage so that L maps to 50 (MainThrive
# MAI-1070, design record MAIL_SPAM_STRATEGY_DESIGN_RECORD.md § 3.2). Here two scored messages, "low" (4.20, 42%) and
# "high" (6.20, 62%), both Invoice mail, go to each of:
# - s40 (Strict, 40), n50 (no row, Normal) and l70 (Lenient, 70), each with a webmail folder rule: Invoice mail is filed
#   into Invoices, guarded as webmail guards it (`not spamtest :percent ge 50`), so the rule runs only on what that
#   mailbox's level calls ham, and spam goes to Junk;
# - p40 and p70, the same levels with no Sieve script, so delivery's other reader (is_spam()) is covered too;
# - b0, b100 and btxt, whose rows are not a line (0, 100, "strict"): each must deliver at Normal, and the value is logged.
# Then every row is removed and the namespace is a Redis lookup store nobody listens on: a message to s40 must be
# delivered at once, at Normal, not deferred, and the failed lookup logged.
# The scores come from the pinned spam rules on an internal network with a DNS stub, as in e2e-spam-text-cap.sh.
# Against the image before 0015 the Strict and Lenient checks and the two log checks FAIL; Normal, the bad values and
# the unavailable store pass, because that image reads no level at all.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-level-$$; C=e2e-level-stalwart-$$; K=e2e-level-client-$$; N=e2e-level-dns-$$; R=e2e-level-rules-$$
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
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
echo "nameserver $(ip_of "$N")" > "$W/resolv.conf"
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test --memory 1g --memory-swap 1g \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/resolv.conf:/etc/resolv.conf:ro" \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" -e RULES_AT="$(ip_of "$R"):8000" python:3.12-alpine sleep 900 >/dev/null
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
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:sieve","urn:stalwart:jmap"]
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
# The pinned rules, in place of the release a server would download; Pyzor, a network lookup, off.
xset("SpamPyzor",update={"singleton":{"enable":False,"host":"127.0.0.1"}})
xset("SpamSettings",update={"singleton":{"spamFilterRulesUrl":f"http://{os.environ['RULES_AT']}/spam-filter-rules.json.gz"}})
# The log on stdout, as production's plan sets it (stalwart-plan.yaml, Tracer): a fresh server logs nothing there.
created(xset("Tracer",create={"n":{"@type":"Stdout","enable":True,"level":"info","ansi":False,"multiline":False,"buffered":False,"lossy":False}}))
action("ReloadSettings")
TASK=created(xset("Task",create={"n":{"@type":"SpamFilterMaintenance","maintenanceType":"updateRules"}}))
for _ in range(120):
    t=one(ADM,"x:Task/get",{"accountId":A,"ids":[TASK]})
    if TASK in t.get("notFound",[]): break
    time.sleep(0.5)
else: raise SystemExit(f"the spam rules never loaded: {t['list']}")

# The accounts. A webmail rule as Bulwark writes it (apps/api/src/email/bulwark-sieve.ts renders the same guard).
RULE=b'''require ["fileinto", "relational", "comparator-i;ascii-numeric", "spamtestplus"];
# Rule: Invoices
if allof(header :contains "subject" "Invoice", not spamtest :percent :value "ge" :comparator "i;ascii-numeric" "50") {
    fileinto "Invoices";
}
'''
LEVELS={"s40":"40","n50":None,"l70":"70","p40":"40","p70":"70","b0":"0","b100":"100","btxt":"strict"}
SCRIPTED={"s40","n50","l70","b0","b100","btxt"}
PW,ID,AU,J,ROWS={},{},{},{},[]
for name,level in LEVELS.items():
    PW[name]=base64.b64encode(os.urandom(18)).decode()
    ID[name]=created(xset("Account",create={"n":{"@type":"User","name":name,"domainId":D,"credentials":{"0":{"@type":"Password","secret":PW[name]}}}}))
    AU[name]=basic(f"{name}@one.test",PW[name]); J[name]=json.loads(req("/jmap/session",AU[name]))["primaryAccounts"]["urn:ietf:params:jmap:mail"]
    if name in SCRIPTED:
        one(AU[name],"Mailbox/set",{"accountId":J[name],"create":{"m":{"name":"Invoices"}}})
        blob=json.loads(req(f"/jmap/upload/{J[name]}/",AU[name],RULE,"application/sieve"))["blobId"]
        r=one(AU[name],"SieveScript/set",{"accountId":J[name],"create":{"s":{"name":"webmail","blobId":blob}},"onSuccessActivateScript":"#s"})
        if not r.get("created"): raise SystemExit(f"{name}'s rule not created: {r}")
    # The row is keyed by the account's id, as the API keys it (email_mailboxes.provider_mailbox_id).
    if level is not None:
        ROWS.append(created(xset("MemoryLookupKeyValue",create={"n":{"namespace":"spam-level","key":ID[name],"value":level,"isGlobPattern":False}})))
action("ReloadLookupStores")
print(f"     account ids: {ID}")

OPENED=[0.0]
def smtp(to,msg):
    # A fresh install throttles each sender IP to 5 new SMTP connections a second: open at most 3 a second.
    time.sleep(max(0,OPENED[0]+0.34-time.time())); OPENED[0]=time.time()
    c=socket.create_connection(("stalwart",25),timeout=120); f=c.makefile("rb")
    def rep():
        while True:
            l=f.readline()
            if not l: return "closed"
            if l[3:4]!=b"-": return l[:3].decode()
    got=rep()
    for x in [b"EHLO mail.example.com\r\n",b"MAIL FROM:<sam@example.com>\r\n",f"RCPT TO:<{to}>\r\n".encode(),b"DATA\r\n"]:
        if got not in ("220","250","354"): break
        c.sendall(x); got=rep()
    if got=="354": c.sendall(msg+b"\r\n.\r\n"); got=rep()
    try: c.sendall(b"QUIT\r\n")
    except OSError: pass
    c.close(); return got
# Ordinary mail scores 3.20 here (AUTH_NA, DMARC_NA, MID_RHS_MATCH_FROM, RCVD_*). "low" has no Date header,
# MISSING_DATE (+1.0): 4.20. "high" has a Date and a subject in capitals, SUBJ_ALL_CAPS (+3.0): 6.20 (measured).
BODY=b"Hi,\r\n\r\nAre we still on for lunch on Friday? I can book a table for noon.\r\n\r\nSam\r\n"
def msg(to,subject):
    date="" if subject.startswith("Invoice low") else f"Date: {email.utils.formatdate()}\r\n"
    return (f"From: Sam <sam@example.com>\r\nTo: {to}\r\nSubject: {subject}\r\n{date}"
            f"Message-ID: <{subject.replace(' ','.')}@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").encode()+BODY
def subject(name,kind): return "INVOICE HIGH" if kind=="high" else "Invoice low"
FOLDERS={}
def folders(name):
    if name not in FOLDERS:
        r=one(AU[name],"Mailbox/get",{"accountId":J[name],"properties":["name","role"]})
        FOLDERS[name]={m["id"]:(m.get("role") or m["name"]).lower() for m in r["list"]}
    return FOLDERS[name]
def delivered(name,subj,tries=240):
    for _ in range(tries):
        r=calls(AU[name],[["Email/query",{"accountId":J[name],"filter":{"subject":subj}},"q"],["Email/get",{"accountId":J[name],"#ids":{"resultOf":"q","name":"Email/query","path":"/ids"},
            "properties":["subject","mailboxIds","header:X-Spam-Status:asText","header:X-Spam-Score:asText"]},"g"]])
        hit=[e for e in r[1][1]["list"] if e["subject"]==subj]
        if hit:
            e=hit[0]; return {"folder":",".join(sorted(folders(name)[m] for m in e["mailboxIds"])),"status":e.get("header:X-Spam-Status:asText"),
                               "score":e.get("header:X-Spam-Score:asText")}
        time.sleep(0.25)
    return None

for name in LEVELS:
    for kind in ("low","high"):
        st=smtp(f"{name}@one.test",msg(f"{name}@one.test",subject(name,kind)))
        if st!="250": raise SystemExit(f"{name} {kind}: SMTP answered {st}")
got={(n,k):delivered(n,subject(n,k)) for n in LEVELS for k in ("low","high")}
def score(e):
    try: return float((e or {}).get("score","").split("score=")[1])
    except (IndexError,ValueError): return None
lows=[score(got[(n,"low")]) for n in LEVELS]; highs=[score(got[(n,"high")]) for n in LEVELS]
check(all(s is not None and 4.0<=s<5.0 for s in lows),"setup: every low message scores from 4.0 to 5.0, between Strict's line and Normal's",lows)
check(all(s is not None and 5.0<=s<7.0 for s in highs),"setup: every high message scores from 5.0 to 7.0, between Normal's line and Lenient's",highs)
JUNK={"folder":"junk","status":"Yes"}
RULED={"folder":"invoices","status":"No"}
INBOX={"folder":"inbox","status":"No"}
def at(name,kind,want,label):
    e=got[(name,kind)]; check(e is not None and {k:e[k] for k in want}==want,label,e)
at("s40","low",JUNK,"Strict (40): the low message goes to Junk, Yes, and the folder rule does not run")
at("s40","high",JUNK,"control: Strict (40): the high message goes to Junk, Yes")
at("n50","low",RULED,"control: Normal (no row): the low message is filed by the rule, No")
at("n50","high",JUNK,"control: Normal (no row): the high message goes to Junk, Yes")
at("l70","low",RULED,"control: Lenient (70): the low message is filed by the rule, No")
at("l70","high",RULED,"Lenient (70): the high message is filed by the rule, No, not Junk")
at("p40","low",JUNK,"Strict (40) with no script: the low message goes to Junk, Yes")
at("p40","high",JUNK,"control: Strict (40) with no script: the high message goes to Junk, Yes")
at("p70","low",INBOX,"control: Lenient (70) with no script: the low message stays in the Inbox, No")
at("p70","high",INBOX,"Lenient (70) with no script: the high message stays in the Inbox, No, not Junk")
for n in ("b0","b100","btxt"):
    at(n,"low",RULED,f"a row that is not a line ({LEVELS[n]}) delivers at Normal: the low message is filed by the rule, No")
    at(n,"high",JUNK,f"a row that is not a line ({LEVELS[n]}) delivers at Normal: the high message goes to Junk, Yes")

# The store unavailable: every row gone, and the namespace a Redis store nobody listens on.
for row in ROWS: xset("MemoryLookupKeyValue",destroy=[row])
r=xset("StoreLookup",create={"n":{"namespace":"spam-level","store":{"@type":"Redis","url":"redis://127.0.0.1:1"}}})
if not r.get("created"): raise SystemExit(f"the unreachable lookup store was not created: {r}")
action("ReloadLookupStores")
t0=time.time(); st=smtp("s40@one.test",msg("s40@one.test","Invoice low unavailable"))
e=delivered("s40","Invoice low unavailable",tries=120); took=round(time.time()-t0,1)
check(st=="250" and e is not None and took<30,"with the lookup store unavailable, the message is delivered at once, not deferred",f"smtp {st}, {took} s, {e}")
check(e is not None and {k:e[k] for k in RULED}==RULED,"control: and at Normal: the low message is filed by the rule, No",e)
raise SystemExit(1 if fails else 0)
PY
rc=$?
set -e
# What the patch logs (Stalwart's own log, the container's stdout): the failed lookup, and the value that is not a line,
# each an exact count: one message met the unreachable store, and three bad rows each met two messages.
LOG=$(docker logs "$C" 2>&1)
fails=0
logcount() { # <want> <label> <fixed text>...: the log lines carrying every text, counted
  local want=$1 label=$2 lines=$LOG got; shift 2
  for t in "$@"; do lines=$(grep -F -- "$t" <<<"$lines" || true); done
  got=$(grep -c . <<<"$lines" || true)
  if [ "$got" -eq "$want" ]; then echo "PASS $label"; else echo "FAIL $label"; echo "     got: $got line(s)"; fails=$((fails+1)); fi
}
# The 17 deliveries above, so a log that records nothing cannot read as "nothing was logged".
logcount 17 "control: Stalwart's log records every delivery" "(message-ingest."
logcount 1 "the failed lookup is logged" "Spam level lookup failed, delivering at Normal." "s40@one.test"
logcount 6 "a row that is not a line is logged" "(store.data-corruption)" "Spam level is not a number from 1 to 99, delivering at Normal."
[ "$rc" -eq 0 ] && [ "$fails" -eq 0 ] && { echo "all passed"; exit 0; }
echo "failed (client exit $rc, $fails log check(s))"; exit 1
