#!/usr/bin/env bash
# End-to-end: a key that manages the mail queue cannot read the mail in it (patch 0019).
# usage: e2e-queued-mail.sh <stalwart image>
#
# MainThrive's mail-ops key holds sysQueuedMessageQuery, sysQueuedMessageGet and sysQueuedMessageUpdate, which is what
# holding and releasing one sender's queue needs: the metadata. On 0.16 that read no message. Upstream v1.1.1 lets
# sysQueuedMessageGet alone download a queued message's contents (BlobClass::Queued), so the key read every queued
# outbound email (measured, MAI-1441). 0019 asks for fetchAnyBlob too, as reading any other account's mail does.
# Every refusal has a control that has to say yes: the same download as an admin, and the same key reading the queue.
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
NET=e2e-queue-$$; C=e2e-queue-stalwart-$$; K=e2e-queue-client-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
ADMIN=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)
docker network create "$NET" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" python:3.12-alpine sleep 600 >/dev/null
docker exec -i "$K" python3 - <<'PY'
import base64,json,os,time,urllib.request,urllib.error
B="http://stalwart:8080"; fails=[]
for _ in range(90):
    try: urllib.request.urlopen(B+"/healthz/ready",timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit("stalwart never became ready")
def check(ok,msg,got=""): print(("PASS " if ok else "FAIL ")+msg); got!="" and print(f"     got: {got}"); ok or fails.append(msg)
basic=lambda u,p: "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:stalwart:jmap","urn:ietf:params:jmap:submission","urn:ietf:params:jmap:blob"]
def req(path,auth,body=None):
    data=None if body is None else json.dumps(body).encode()
    h={"Authorization":auth}; data is not None and h.update({"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(urllib.request.Request(B+path,data=data,headers=h),timeout=30) as x: return x.status,x.read()
    except urllib.error.HTTPError as e: return e.code,e.read()
def calls(auth,c):
    s,b=req("/jmap/",auth,{"using":U,"methodCalls":c}); return json.loads(b)["methodResponses"] if s==200 else [["HTTP",{"status":s},""]]
def made(r,k):
    c=(r[1].get("created") or {}).get(k)
    if not c: raise SystemExit(f"setup failed: {json.dumps(r)[:300]}")
    return c
ADM=basic("admin",os.environ["ADMIN"])
A=json.loads(req("/jmap/session",ADM)[1])["primaryAccounts"]["urn:stalwart:jmap"]
PW=base64.b64encode(os.urandom(18)).decode()
D=made(calls(ADM,[["x:Domain/set",{"accountId":A,"create":{"d":{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}}},"d"]])[0],"d")["id"]
OPS=made(calls(ADM,[["x:Account/set",{"accountId":A,"create":{"o":{"@type":"User","name":"ops","domainId":D,"roles":{"@type":"Admin"},
  "credentials":{"0":{"@type":"Password","secret":PW}}}}},"o"]])[0],"o")["id"]
made(calls(ADM,[["x:Account/set",{"accountId":A,"create":{"a":{"@type":"User","name":"alice","domainId":D,"credentials":{"0":{"@type":"Password","secret":PW}}}}},"a"]])[0],"a")
# Outbound mail goes to a relay that refuses (127.0.0.1:9), so it stays queued, deferred.
r=calls(ADM,[["x:MtaRoute/set",{"accountId":A,"create":{"r":{"@type":"Relay","name":"nowhere","host":"127.0.0.1","port":9,"protocol":"smtp","implicitTls":False}}},"r"],
             ["x:MtaOutboundStrategy/set",{"accountId":A,"update":{"singleton":{"route":{"match":{"0":{"if":"is_local_domain(rcpt_domain)","then":"'local'"}},"else":"'nowhere'"}}}},"o"],
             ["x:Action/set",{"accountId":A,"create":{"x":{"@type":"ReloadSettings"}}},"x"]])
if "created" not in r[0][1] or "updated" not in r[1][1]: raise SystemExit(f"setup failed: {json.dumps(r)[:300]}")
# The mail-ops shape: a key owned by an Admin, holding the queue's three permissions and nothing that reads mail.
OA=basic("ops@one.test",PW); OAA=json.loads(req("/jmap/session",OA)[1])["primaryAccounts"]["urn:stalwart:jmap"]
# MainThrive's mail-ops key's exact set (apps/api/test/stalwart-int/mail-ops-permissions.txt).
perms={p:True for p in ["authenticate","sysQueuedMessageQuery","sysQueuedMessageGet","sysQueuedMessageUpdate",
                        "sysBlockedIpQuery","sysBlockedIpDestroy","sysActionCreate","actionReloadBlockedIps"]}
key=made(calls(OA,[["x:ApiKey/set",{"accountId":OAA,"create":{"k":{"description":"queue","permissions":{"@type":"Replace","permissions":perms}}}},"k"]])[0],"k")["secret"]
K="Bearer "+key
# Alice sends one message out, which the dead relay leaves in the queue.
AL=basic("alice@one.test",PW); s=json.loads(req("/jmap/session",AL)[1]); acc=s["primaryAccounts"]["urn:ietf:params:jmap:mail"]
mb=calls(AL,[["Mailbox/get",{"accountId":acc,"properties":["role"]},"m"]])[0][1]["list"]; drafts=next(m["id"] for m in mb if m.get("role")=="drafts")
ident=calls(AL,[["Identity/get",{"accountId":acc},"i"]])[0][1]["list"][0]["id"]
r=calls(AL,[["Email/set",{"accountId":acc,"create":{"e":{"mailboxIds":{drafts:True},"from":[{"email":"alice@one.test"}],"to":[{"email":"x@outside.test"}],"subject":"queued","textBody":[{"partId":"1"}],"bodyValues":{"1":{"value":"SECRET-BODY-0019"}}}}},"e"],
            ["EmailSubmission/set",{"accountId":acc,"create":{"s":{"emailId":"#e","identityId":ident,"envelope":{"mailFrom":{"email":"alice@one.test"},"rcptTo":[{"email":"x@outside.test"}]}}}},"s"]])
if not (r[1][1].get("created") or {}).get("s"): raise SystemExit(f"setup failed: {json.dumps(r)[:300]}")
qs=[]
for _ in range(60):
    r=calls(ADM,[["x:QueuedMessage/query",{"accountId":A},"q"],["x:QueuedMessage/get",{"accountId":A,"#ids":{"resultOf":"q","name":"x:QueuedMessage/query","path":"/ids"},"properties":["blobId","returnPath"]},"g"]])
    qs=[m for m in r[1][1].get("list",[]) if m.get("returnPath")=="alice@one.test" and m.get("blobId")]
    if qs: break
    time.sleep(1)
if not qs: raise SystemExit("setup failed: the message never reached the queue")
blob=qs[0]["blobId"]
st,body=req(f"/jmap/download/{A}/{blob}/m",ADM)
check(st==200 and b"SECRET-BODY-0019" in body, "control: an admin downloads the queued message's contents", st)
r=calls(K,[["x:QueuedMessage/query",{"accountId":OAA},"q"]])[0]
check(r[0]=="x:QueuedMessage/query" and len(r[1].get("ids") or [])>=1, "control: the queue key reads the queue", json.dumps(r)[:200])
st,body=req(f"/jmap/download/{A}/{blob}/m",K)
check(st!=200 and b"SECRET-BODY-0019" not in body, "the queue key cannot download a queued message's contents", st)
r=calls(K,[["Blob/get",{"accountId":OAA,"ids":[blob],"properties":["data:asText"]},"b"]])[0]
check(blob in (r[1].get("notFound") or []) or r[0]=="error", "nor read them through Blob/get", json.dumps(r)[:160])
print(f"{len(fails)} failure(s)"); raise SystemExit(1 if fails else 0)
PY
