#!/usr/bin/env bash
# End-to-end: no Stalwart logo on a calendar invitation, a reminder, or the guest RSVP page.
# usage: e2e-no-logo.sh <stalwart image>
#
# Upstream v0.16.25 (Community) attaches its built-in logo (DEFAULT_LOGO_BASE64) as an inline image part to every
# invitation and reminder, references it as cid:logo… from the compiled-in templates, and draws its SVG logo on
# the RSVP page (measured). Patch 0009 removes all three. The invitation and reminder are real ones: org invites
# att by CalDAV PUT with an EMAIL alarm, and both arrive as mail on the same server.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-logo-$$; C=e2e-logo-stalwart-$$; K=e2e-logo-client-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
ADMIN=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
docker network create "$NET" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" python:3.12-alpine sleep 900 >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,datetime,email,gzip,json,os,secrets,sys,time,uuid,urllib.request,urllib.error
B="http://stalwart:8080"; fails=[]
for _ in range(90):
    try: urllib.request.urlopen(B+"/healthz/ready",timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit("stalwart never became ready")
def check(ok,msg): print(("PASS " if ok else "FAIL ")+msg); ok or fails.append(msg)
basic=lambda u,p: "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:stalwart:jmap"]
def req(path,auth,raw=None,ctype="application/json",method=None):
    h={"Authorization":auth}
    if raw is not None: h["Content-Type"]=ctype
    try:
        with urllib.request.urlopen(urllib.request.Request(B+path,data=raw,headers=h,method=method),timeout=30) as x: return x.status,x.read()
    except urllib.error.HTTPError as e: return e.code,e.read()
def r1(auth,call): return json.loads(req("/jmap/",auth,json.dumps({"using":U,"methodCalls":[call]}).encode())[1])["methodResponses"][0]
ADM=basic("admin",os.environ["ADMIN"]); A=json.loads(req("/jmap/session",ADM)[1])["primaryAccounts"]["urn:stalwart:jmap"]
D=r1(ADM,["x:Domain/set",{"accountId":A,"create":{"d":{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}}},"d"])[1]["created"]["d"]["id"]
PW={}
for n in ("org","att"):
    PW[n]=secrets.token_urlsafe(16)
    r1(ADM,["x:Account/set",{"accountId":A,"create":{"c":{"@type":"User","name":n,"domainId":D,"credentials":{"0":{"@type":"Password","secret":PW[n]}}}}},"c"])
au=lambda n: basic(f"{n}@one.test",PW[n])
mid=lambda n: json.loads(req("/jmap/session",au(n))[1])["primaryAccounts"]["urn:ietf:params:jmap:mail"]
# Reminders fire at most once an hour by default; this one fires 90 s before an event two minutes out.
r=r1(ADM,["x:CalendarAlarm/set",{"accountId":A,"update":{"singleton":{"minTriggerInterval":1000}}},"u"])
check("singleton" in (r[1].get("updated") or {}), "setup: the reminder interval is lowered")
now=datetime.datetime.now(datetime.UTC); f=lambda d: (now+d).strftime("%Y%m%dT%H%M%SZ")
ics=(f"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//e2e//EN\r\nBEGIN:VEVENT\r\nUID:{uuid.uuid4()}\r\nDTSTAMP:{f(datetime.timedelta())}\r\n"
     f"DTSTART:{f(datetime.timedelta(minutes=2))}\r\nDTEND:{f(datetime.timedelta(minutes=32))}\r\nSUMMARY:e2e meeting\r\n"
     "ORGANIZER:mailto:org@one.test\r\nATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:att@one.test\r\n"
     "BEGIN:VALARM\r\nACTION:EMAIL\r\nTRIGGER:-PT1M30S\r\nSUMMARY:soon\r\nDESCRIPTION:soon\r\nATTENDEE:mailto:org@one.test\r\nEND:VALARM\r\n"
     "END:VEVENT\r\nEND:VCALENDAR\r\n").encode()
s,_=req("/dav/cal/org%40one.test/default/e1.ics",au("org"),raw=ics,ctype="text/calendar",method="PUT")
check(s==201, f"setup: org creates the event inviting att, with an email reminder ({s})")
MID={n:mid(n) for n in PW}
def mail(n,prefix):
    a,acc=au(n),MID[n]
    for i in r1(a,["Email/query",{"accountId":acc},"q"])[1].get("ids",[]):
        g=r1(a,["Email/get",{"accountId":acc,"ids":[i],"properties":["subject","blobId"]},"g"])[1]["list"][0]
        if g["subject"].startswith(prefix): return req(f"/jmap/download/{acc}/{g['blobId']}/m",a)[1]
inv=rem=None
for _ in range(60):
    inv=inv or mail("att","Invitation:"); rem=rem or mail("org","Notification:")
    if inv and rem: break
    time.sleep(5)
for what,raw in (("the invitation",inv),("the reminder",rem)):
    check(raw is not None, f"setup: {what} arrives as mail")
    if raw is None: continue
    types=[p.get_content_type() for p in email.message_from_bytes(raw).walk()]
    check(not any(t.startswith("image/") for t in types), f"{what} carries no image part ({types})")
    check(b"cid:logo" not in raw, f"{what} references no cid:logo")
    check("text/html" in types, f"{what} still has its HTML body")
check(inv is not None and "text/calendar" in [p.get_content_type() for p in email.message_from_bytes(inv).walk()], "the invitation still carries its text/calendar part")
s,b=req("/calendar/rsvp",au("org"))
try: page=gzip.decompress(b).decode()
except OSError: page=b.decode(errors="replace")
check(s==200 and "logo-wrap" in page, f"setup: the RSVP page is served ({s})")
check('class="default-logo"' not in page and "680.5 252.1" not in page, "the RSVP page carries no Stalwart logo SVG")
print("RESULT", "fail" if fails else "pass", len(fails)); sys.exit(1 if fails else 0)
PY
