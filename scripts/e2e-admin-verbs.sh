#!/usr/bin/env bash
# End-to-end: admin verbs on another account without mail reach, and no account takeover through
# a narrow key. usage: e2e-admin-verbs.sh <stalwart image>
#
# Production-shaped: an untenanted Admin `mailadmin` owns an API key limited to exactly the API's
# permission list (e2e-admin-verbs.perms, 264 permissions, no `impersonate`). 0007: account writes (and group joins) beyond the
# key's grant are refused, ordinary ones still pass. 0008: Sieve, out-of-office, identity and app-password issue
# pass on a customer's mailbox, and nothing here may read mail through JMAP or a blob download. (An issued app
# password reads all of the mailbox's mail over IMAP, as a password reset does; a Sieve redirect copies future mail.)
# Every allowed row has a refused twin.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
HERE=$(cd "$(dirname "$0")" && pwd)
NET=e2e-verbs-$$; C=e2e-verbs-stalwart-$$; K=e2e-verbs-client-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
ADMIN=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
docker network create "$NET" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.ops.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" \
  -v "$HERE/e2e-admin-verbs.perms:/perms.txt:ro" python:3.12-alpine sleep 900 >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,json,os,secrets,smtplib,ssl,sys,time,uuid,imaplib,urllib.request,urllib.error
B="http://stalwart:8080"; fails=[]
for _ in range(90):
    try: urllib.request.urlopen(B+"/healthz/ready",timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit("stalwart never became ready")
def check(ok,msg): print(("PASS " if ok else "FAIL ")+msg); ok or fails.append(msg)
basic=lambda u,p: "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:stalwart:jmap","urn:ietf:params:jmap:sieve",
   "urn:ietf:params:jmap:vacationresponse","urn:ietf:params:jmap:submission","urn:ietf:params:jmap:blob"]
def req(path,auth,body=None,raw=None,ctype="application/json"):
    data=raw if raw is not None else (None if body is None else json.dumps(body).encode())
    h={"Authorization":auth}
    if data is not None: h["Content-Type"]=ctype
    try:
        with urllib.request.urlopen(urllib.request.Request(B+path,data=data,headers=h),timeout=30) as x:
            b=x.read(); return x.status,b
    except urllib.error.HTTPError as e: return e.code,e.read()
def session(auth):
    s,b=req("/jmap/session",auth); return s,(json.loads(b) if s==200 else None)
def r1(auth,call):
    s,b=req("/jmap/",auth,{"using":U,"methodCalls":[call]})
    return json.loads(b)["methodResponses"][0] if s==200 else ["HTTP",{"status":s}]
def ok(r,name): return r[0]==name
def created(r,k):
    c=(r[1].get("created") or {}).get(k)
    if not c: raise SystemExit(f"setup failed: {json.dumps(r)[:300]}")
    return c
def upload(auth,acc,data,ctype="application/sieve"):
    s,b=req(f"/jmap/upload/{acc}/",auth,raw=data,ctype=ctype)
    if s not in (200,201): raise SystemExit(f"upload failed {s} {b[:200]}")
    return json.loads(b)["blobId"]

# Setup, as the recovery admin.
ADM=basic("admin",os.environ["ADMIN"]); A=session(ADM)[1]["primaryAccounts"]["urn:stalwart:jmap"]
T1=created(r1(ADM,["x:Tenant/set",{"accountId":A,"create":{"t":{"name":"one"}}},"t"]),"t")["id"]
T2=created(r1(ADM,["x:Tenant/set",{"accountId":A,"create":{"t":{"name":"two"}}},"t"]),"t")["id"]
def dom(n,t=None):
    v={"name":n,"dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}
    if t: v["memberTenantId"]=t
    return created(r1(ADM,["x:Domain/set",{"accountId":A,"create":{"d":v}},"d"]),"d")["id"]
DOPS,D1,D2=dom("ops.test"),dom("one.test",T1),dom("two.test",T2)
PW={}; ID={}
def user(n,d,t=None,admin=False):
    pw=secrets.token_urlsafe(16); v={"@type":"User","name":n,"domainId":d,"credentials":{"0":{"@type":"Password","secret":pw}}}
    if t: v["memberTenantId"]=t
    if admin: v["roles"]={"@type":"Admin"}
    ID[n]=created(r1(ADM,["x:Account/set",{"accountId":A,"create":{"c":v}},"c"]),"c")["id"]; PW[n]=pw
    return basic(f"{n}@{ {DOPS:'ops.test',D1:'one.test',D2:'two.test'}[d] }",pw)
MA=user("mailadmin",DOPS,admin=True); OA=user("opsadm",DOPS,admin=True)
AL=user("alice",D1,T1); CA=user("carol",D1,T1); BO=user("bob",D2,T2); TA=user("tadm",D1,T1,admin=True)
mail_id=lambda auth: session(auth)[1]["primaryAccounts"]["urn:ietf:params:jmap:mail"]
MAA=session(MA)[1]["primaryAccounts"]["urn:stalwart:jmap"]
ALICE,BOB,OPS=mail_id(AL),mail_id(BO),mail_id(OA)
TAA=session(TA)[1]["primaryAccounts"]["urn:stalwart:jmap"]
r1(ADM,["x:Account/set",{"accountId":A,"update":{ID["mailadmin"]:{"quotas":{"maxApiKeys":100}}}},"u"])

# Each mailbox's own script, made by its owner: alice forwards everything to carol; opsadm has one too.
def own_script(auth,acc,name,text,active):
    bid=upload(auth,acc,text.encode())
    a={"onSuccessActivateScript":"#s"} if active else {}
    return created(r1(auth,["SieveScript/set",dict({"accountId":acc,"create":{"s":{"name":name,"blobId":bid}}},**a),"s"]),"s")["id"]
FWD=own_script(AL,ALICE,"forward",'require ["copy"];\r\nredirect :copy "carol@one.test";\r\n',True)  # webmail's shape
SPARE=own_script(AL,ALICE,"spare",'keep;\n',False)
own_script(OA,OPS,"ops",'keep;\n',True)
# opsadm enrols TOTP, as production's Admins do: a password alone no longer opens a session.
sec=base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
r1(OA,["x:AccountPassword/set",{"accountId":session(OA)[1]["primaryAccounts"]["urn:stalwart:jmap"],"update":{"singleton":{
    "currentSecret":PW["opsadm"],"otpAuth":{"otpUrl":f"otpauth://totp/S:opsadm?secret={sec}&issuer=S"}}}},"u"])
check(session(OA)[0]==402, "setup: opsadm's password alone no longer opens a session (TOTP enrolled)")

ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
def send(subject,to="alice@one.test"):
    with smtplib.SMTP_SSL("stalwart",465,context=ctx,timeout=30) as m:
        m.login("bob@two.test",PW["bob"])
        m.sendmail("bob@two.test",[to],f"From: bob@two.test\r\nTo: {to}\r\nSubject: {subject}\r\nMessage-ID: <{uuid.uuid4()}@t>\r\n\r\nbody\r\n")
def has(auth,acc,subject):
    # Subjects read back directly, not through a full-text filter: indexing is asynchronous, so a
    # filtered query can miss a message that has arrived (and a "no copy" row would pass for that).
    ids=r1(auth,["Email/query",{"accountId":acc},"q"])[1].get("ids") or []
    got=r1(auth,["Email/get",{"accountId":acc,"ids":ids,"properties":["subject"]},"g"])[1].get("list") or [] if ids else []
    return any(m.get("subject")==subject for m in got)
def wait_for(auth,acc,subject,secs=30):
    for _ in range(secs):
        if has(auth,acc,subject): return True
        time.sleep(1)
    return False
CAROL=mail_id(CA)
send("before")
check(wait_for(AL,ALICE,"before"), "setup: alice receives mail")
check(wait_for(CA,CAROL,"before"), "setup: alice's forward delivers a copy to carol (the control the forward proof needs)")

# The keys. Each is a Replace key, so it holds exactly its list.
perms=[l.strip() for l in open("/perms.txt") if l.strip()]
assert "impersonate" not in perms and "sysAccountUpdate" in perms
def key(owner,owner_acc,lst):
    c=created(r1(owner,["x:ApiKey/set",{"accountId":owner_acc,"create":{"k":{"description":"e2e",
        "permissions":{"@type":"Replace","permissions":{p:True for p in lst}}}}},"k"]),"k")
    return "Bearer "+c["secret"]
K=key(MA,MAA,perms)                                                  # the API's key
KN=key(MA,MAA,[p for p in perms if p!="sysAccountUpdate"])           # the same, without sysAccountUpdate
KA=session(K)[1]["primaryAccounts"]["urn:stalwart:jmap"]
# A tenanted caller cannot hold sysAccountUpdate on this (unlicensed) build: effective_permissions caps
# every tenanted account at the user set. So 0008's tenant clause cannot be reached here; it is there
# for a licensed deployment, and this row says so rather than leaving it unexercised and unstated.
r=r1(TA,["x:ApiKey/set",{"accountId":TAA,"create":{"k":{"description":"e2e","permissions":{"@type":"Replace","permissions":{"authenticate":True,"sysAccountUpdate":True}}}}},"k"])
check(not (r[1].get("created") or {}).get("k"), "a tenant Admin cannot mint a key holding sysAccountUpdate (unlicensed: tenanted accounts hold the user set)")

# 0007: no takeover through the key, and ordinary account writes still pass.
def pwcred(i):
    g=r1(ADM,["x:Account/get",{"accountId":A,"ids":[i],"properties":["credentials"]},"g"])
    return [k for k,v in g[1]["list"][0]["credentials"].items() if v["@type"]=="Password"][0]
def reset(auth,acc,i,totp=False):
    ck=pwcred(i); u={f"credentials/{ck}/secret":secrets.token_urlsafe(16)}
    if totp: u[f"credentials/{ck}/otpAuth"]=None
    r=r1(auth,["x:Account/set",{"accountId":acc,"update":{i:u}},"u"])
    return i in (r[1].get("updated") or {}), r
G7="This account's permissions exceed yours."
by0007=lambda r,kind,i: ((r[1].get(kind) or {}).get(i) or {}).get("description")==G7
up,r=reset(K,KA,ID["opsadm"],True); check(not up and by0007(r,"notUpdated",ID["opsadm"]), f"0007: the key cannot reset a TOTP Admin's password and TOTP ({json.dumps(r)[:140]})")
up,r=reset(K,KA,ID["mailadmin"]); check(not up and by0007(r,"notUpdated",ID["mailadmin"]), f"0007: the key cannot reset its own owner mailadmin's password ({json.dumps(r)[:140]})")
check(session(MA)[0]==200, "0007: mailadmin's password is unchanged")
# Each destructive row gets its own Admin, so one row's success on an unpatched image cannot make
# a later row pass for the wrong reason.
user("yan",DOPS,admin=True); user("zed",DOPS,admin=True)
r=r1(K,["x:Account/set",{"accountId":KA,"update":{ID["yan"]:{"description":"x"}}},"u"])
check(ID["yan"] not in (r[1].get("updated") or {}) and by0007(r,"notUpdated",ID["yan"]), "0007: the key cannot make ANY change to an Admin (a description)")
r=r1(K,["x:Account/set",{"accountId":KA,"destroy":[ID["zed"]]},"d"])
check(ID["zed"] not in (r[1].get("destroyed") or []) and by0007(r,"notDestroyed",ID["zed"]), "0007: the key cannot destroy an Admin")
user("dave",D1,T1); user("erin",D2,T2)
up,_=reset(K,KA,ID["dave"]); check(up, "0007: the key still resets a User's password")
r=r1(K,["x:Account/set",{"accountId":KA,"destroy":[ID["erin"]]},"d"])
check(ID["erin"] in (r[1].get("destroyed") or []), "0007: the key still destroys a User")
up,_=reset(ADM,A,ID["yan"]); check(up, "0007: a full Admin still resets an Admin (the control that has to say yes)")
# 0007, groups: joining a group needs the caller's grant to cover the group's permissions; leaving one does not.
def group(n,perms=None):
    v={"@type":"Group","name":n,"domainId":DOPS}
    if perms: v["permissions"]={"@type":"Merge","enabledPermissions":{p:True for p in perms}}
    ID[n]=created(r1(ADM,["x:Account/set",{"accountId":A,"create":{"g":v}},"g"]),"g")["id"]
group("privg",["impersonate"]); group("plaing"); user("gus",DOPS)
GG="This group's permissions exceed yours."
join=lambda auth,acc,i,g,on=True: r1(auth,["x:Account/set",{"accountId":acc,"update":{i:{f"memberGroupIds/{g}":on}}},"u"])
r=join(K,KA,ID["gus"],ID["privg"])
check(ID["gus"] not in (r[1].get("updated") or {}) and ((r[1].get("notUpdated") or {}).get(ID["gus"]) or {}).get("description")==GG, f"0007: the key cannot add a User to a group holding a permission it lacks ({json.dumps(r)[:140]})")
r=r1(K,["x:Account/set",{"accountId":KA,"create":{"c":{"@type":"User","name":"hal","domainId":DOPS,"memberGroupIds":{ID["privg"]:True}}}},"c"])
check(not (r[1].get("created") or {}).get("c") and ((r[1].get("notCreated") or {}).get("c") or {}).get("description")==GG, f"0007: the key cannot create a User inside that group ({json.dumps(r)[:140]})")
r=join(K,KA,ID["gus"],ID["plaing"]); check(ID["gus"] in (r[1].get("updated") or {}), f"0007: the key still adds a User to a group within its grant ({json.dumps(r)[:140]})")
r=join(ADM,A,ID["gus"],ID["privg"]); check(ID["gus"] in (r[1].get("updated") or {}), "0007: a full Admin still adds a User to that group (the control that has to say yes)")
r=join(K,KA,ID["gus"],ID["privg"],None); check(ID["gus"] in (r[1].get("updated") or {}), f"0007: the key still removes a member from that group ({json.dumps(r)[:140]})")

# 0008: the nine verbs, on alice, through the key; each refused for the refusal targets.
refused=lambda r: r[0]=="error" and r[1].get("type")=="forbidden"
# (The key's own owner is not a target here: a key is one of mailadmin's credentials, so upstream
# already lets it act on mailadmin's own Sieve and identities. 0007's rows cover the owner.)
TARGETS=[("an Admin (opsadm)",K,OPS),("alice without sysAccountUpdate",KN,ALICE)]
def both(name,call_for):
    r=r1(K,call_for(ALICE)); check(ok(r,call_for(ALICE)[0]), f"0008 {name}: allowed on alice ({json.dumps(r)[:120]})")
    for what,auth,acc in TARGETS:
        rr=r1(auth,call_for(acc)); check(refused(rr), f"0008 {name}: refused on {what} ({json.dumps(rr)[:100]})")
    return r
# 1. list scripts and see which is active
both("SieveScript/query",lambda a:["SieveScript/query",{"accountId":a},"q"])
g=both("SieveScript/get",lambda a:["SieveScript/get",{"accountId":a},"g"])
scripts={s["id"]:s for s in g[1].get("list",[])}
check(scripts.get(FWD,{}).get("isActive") is True, "0008 SieveScript/get: shows alice's forward as the active script")
r=r1(K,["SieveScript/query",{"accountId":BOB},"q"]); check(ok(r,"SieveScript/query"), "0008 SieveScript/query: the untenanted key reaches bob in tenant two too (any tenant)")
# 4. read the forward's content: SieveScript-linked blobs only
FB=scripts.get(FWD,{}).get("blobId","none")
s,b=req(f"/jmap/download/{ALICE}/{FB}/f",K)
check(s==200 and b"carol@one.test" in b, f"0008 download: the key reads alice's forward script ({s})")
ob=r1(ADM,["SieveScript/get",{"accountId":OPS},"g"])[1]["list"][0]["blobId"]
s,_=req(f"/jmap/download/{OPS}/{ob}/f",K); check(s==404, f"0008 download: refused for an Admin's script ({s})")
s,_=req(f"/jmap/download/{ALICE}/{FB}/f",KN); check(s==404, f"0008 download: refused without sysAccountUpdate ({s})")
# mail reach, still refused
m=r1(AL,["Email/query",{"accountId":ALICE},"q"])[1]["ids"][0]
mb=r1(AL,["Email/get",{"accountId":ALICE,"ids":[m],"properties":["blobId"]},"g"])[1]["list"][0]["blobId"]
r=r1(K,["Email/get",{"accountId":ALICE,"ids":[m]},"g"]); check(refused(r), "mail reach: Email/get on alice refused")
r=r1(K,["Email/query",{"accountId":ALICE},"q"]); check(refused(r), "mail reach: Email/query on alice refused")
r=r1(K,["Blob/get",{"accountId":ALICE,"ids":[mb]},"b"]); check(refused(r), "mail reach: Blob/get on alice's mail blob refused")
r=r1(K,["Blob/get",{"accountId":MAA,"ids":[mb]},"b"]); check(r[0]=="Blob/get" and mb in (r[1].get("notFound") or []), f"mail reach: Blob/get of alice's mail blob from the key's own account: notFound ({json.dumps(r)[:100]})")
s,_=req(f"/jmap/download/{ALICE}/{mb}/m",K); check(s==404, f"mail reach: /jmap/download of alice's mail blob refused ({s})")
# 5. edit a script: the key uploads to its OWN account, validates and sets it on alice's
nb=upload(K,MAA,b'keep;\r\n')
r=r1(K,["SieveScript/validate",{"accountId":ALICE,"blobId":nb},"v"]); check(ok(r,"SieveScript/validate") and not r[1].get("error"), f"0008 SieveScript/validate: allowed on alice ({json.dumps(r)[:100]})")
for what,auth,acc in TARGETS:
    r=r1(auth,["SieveScript/validate",{"accountId":acc,"blobId":nb},"v"]); check(refused(r), f"0008 SieveScript/validate: refused on {what}")
r=r1(K,["SieveScript/set",{"accountId":ALICE,"update":{SPARE:{"blobId":nb}}},"u"]); check(SPARE in (r[1].get("updated") or {}), "0008 SieveScript/set update: alice's spare script takes the key's upload")
ab=upload(AL,ALICE,b'keep;\n')    # an upload ALICE made: the key may not use it
r=r1(K,["SieveScript/validate",{"accountId":ALICE,"blobId":ab},"v"]); check((r[1].get("error") or {}).get("type")=="blobNotFound", "0008: the key cannot read back an upload it did not make (alice's own)")
# 2 and 3. switch the forward off, then delete a script (the active one cannot be deleted)
r=r1(K,["SieveScript/set",{"accountId":ALICE,"destroy":[FWD]},"d"]); check(FWD in (r[1].get("notDestroyed") or {}), "0008 SieveScript/set destroy: the ACTIVE forward cannot be deleted (upstream's rule)")
both("SieveScript/set deactivate",lambda a:["SieveScript/set",{"accountId":a,"onSuccessDeactivateScript":True},"s"])
g=r1(K,["SieveScript/get",{"accountId":ALICE},"g"]); check("list" in g[1] and not any(s["isActive"] for s in g[1]["list"]), "0008: alice has no active script now")
send("after")
check(wait_for(AL,ALICE,"after"), "forward proof: alice still receives mail")
# A sentinel sent straight to carol after "after": once it is in, anything the forward sent would be too.
send("sentinel","carol@one.test"); check(wait_for(CA,CAROL,"sentinel"), "forward proof: carol receives the sentinel sent after it")
time.sleep(5); check(not has(CA,CAROL,"after"), "forward proof: carol got NO copy: the forward stopped")
r=r1(K,["SieveScript/set",{"accountId":ALICE,"onSuccessActivateScript":SPARE},"s"]); check(ok(r,"SieveScript/set") and not r[1].get("notUpdated"), "0008 SieveScript/set activate: allowed on alice")
r=r1(K,["SieveScript/set",{"accountId":ALICE,"onSuccessDeactivateScript":True},"s"])
r=r1(K,["SieveScript/set",{"accountId":ALICE,"destroy":[FWD]},"d"]); check(FWD in (r[1].get("destroyed") or []), "0008 SieveScript/set destroy: the deactivated forward is deleted")
r=r1(K,["SieveScript/set",{"accountId":OPS,"destroy":[]},"d"]); check(refused(r), "0008 SieveScript/set: refused on an Admin (opsadm)")
# 6. out-of-office
both("VacationResponse/get",lambda a:["VacationResponse/get",{"accountId":a,"ids":["singleton"]},"g"])
both("VacationResponse/set",lambda a:["VacationResponse/set",{"accountId":a,"update":{"singleton":{"isEnabled":True,"subject":"Away","textBody":"Back soon"}}},"s"])
g=r1(AL,["VacationResponse/get",{"accountId":ALICE,"ids":["singleton"]},"g"]); check(g[1]["list"][0].get("subject")=="Away", "0008 VacationResponse/set: alice reads the out-of-office the key set")
# 9. identities
g=both("Identity/get",lambda a:["Identity/get",{"accountId":a},"g"])
iid=(g[1].get("list") or [{"id":"none"}])[0]["id"]
r=r1(K,["Identity/set",{"accountId":ALICE,"update":{iid:{"name":"Alice Example"}}},"u"]); check(iid in (r[1].get("updated") or {}), "0008 Identity/set: allowed on alice")
for what,auth,acc in TARGETS:
    r=r1(auth,["Identity/set",{"accountId":acc,"update":{"x":{"name":"x"}}},"u"]); check(refused(r), f"0008 Identity/set: refused on {what}")
# 7 and 8. issue an app password: Replace within the key's grants; the import shape works over IMAP
# allowedIps: the private ranges a docker network lives in (Stalwart refuses 0.0.0.0/0 as a key).
IPS={n:True for n in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")}; exp=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(time.time()+3600))
ap=lambda a,p:["x:AppPassword/set",{"accountId":a,"create":{"p":{"description":"import","permissions":p,"allowedIps":IPS,"expiresAt":exp}}},"p"]
IMAPP={"@type":"Replace","permissions":{p:True for p in ["authenticate","imapAuthenticate","imapSelect","imapExamine","imapList","imapAppend","imapCreate","imapStatus","imapFetch"]}}
r=r1(K,ap(ALICE,IMAPP)); c=(r[1].get("created") or {}).get("p"); check(bool(c), "0008 x:AppPassword/set create: the import credential is issued on alice"+("" if c else f" ({json.dumps(r)[:200]})"))  # never print the secret
if c:
    M=imaplib.IMAP4_SSL("stalwart",993,ssl_context=ctx); t,_=M.login("alice@one.test",c["secret"])
    check(t=="OK" and M.select("INBOX")[0]=="OK", "0008: alice's IMAP opens with it (the import worker's path)"); M.logout()
r=r1(K,ap(ALICE,{"@type":"Inherit"})); check(r[0]=="x:AppPassword/set" and "grant" in ((r[1].get("notCreated") or {}).get("p") or {}).get("description",""), f"0008 x:AppPassword/set: Inherit is refused by the grant rule ({json.dumps(r)[:200]})")
for what,auth,acc in TARGETS:
    r=r1(auth,ap(acc,IMAPP)); check(refused(r), f"0008 x:AppPassword/set create: refused on {what}")
if c:
    r=r1(K,["x:AppPassword/set",{"accountId":ALICE,"destroy":[c["id"]]},"d"]); check(refused(r), "0008 x:AppPassword/set destroy on alice: still refused (only issuing passes)")
    r=r1(K,["x:AppPassword/get",{"accountId":ALICE},"g"]); check(refused(r), "0008 x:AppPassword/get on alice: still refused")
# Only issuing an app password opened: an API key on alice, and a create carrying an update, stay walled.
r=r1(K,["x:ApiKey/set",{"accountId":ALICE,"create":{"k":{"description":"x","permissions":{"@type":"Replace","permissions":{"authenticate":True}}}}},"k"])
check(refused(r), "0008: x:ApiKey/set create on alice is still refused (only app passwords opened)")
r=r1(K,["x:AppPassword/set",{"accountId":ALICE,"create":{"p":{"description":"x","permissions":IMAPP,"allowedIps":IPS}},"update":{"zz":{"description":"x"}}},"p"])
check(refused(r), "0008: x:AppPassword/set with a create AND an update is refused whole")
# A third account's mail blob cannot be read through a Sieve verb on alice.
cm=r1(CA,["Email/query",{"accountId":CAROL},"q"])[1]["ids"][0]
cb=r1(CA,["Email/get",{"accountId":CAROL,"ids":[cm],"properties":["blobId"]},"g"])[1]["list"][0]["blobId"]
r=r1(K,["SieveScript/validate",{"accountId":ALICE,"blobId":cb},"v"]); check((r[1].get("error") or {}).get("type")=="blobNotFound", f"mail reach: SieveScript/validate on alice cannot read carol's mail blob ({json.dumps(r)[:120]})")
# Still refused, as upstream: settings, and minting a wider key
r=r1(K,["x:Security/set",{"accountId":KA,"update":{"singleton":{"authBanPeriod":86400000}}},"u"]); check(not (r[1].get("updated") or {}), "the key still cannot change server settings")
r=r1(K,["x:ApiKey/set",{"accountId":MAA,"create":{"k":{"description":"wider","permissions":{"@type":"Inherit"}}}},"k"]); check(not (r[1].get("created") or {}).get("k"), "the key still cannot mint an Inherit key on its owner")
print("RESULT", "fail" if fails else "pass", len(fails)); sys.exit(1 if fails else 0)
PY
