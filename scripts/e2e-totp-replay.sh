#!/usr/bin/env bash
# End-to-end: a two-step (TOTP) code is accepted once (patch 0012).
# usage: e2e-totp-replay.sh <stalwart image>
#
# Upstream checks the code against the account's otpauth URL and keeps no record of it, so the same six digits sign
# in again, and confirm a password change, until their window closes (~60-90 s; measured on production's image,
# MAI-989 and MAI-997). RFC 6238 § 5.2 says a verifier must not accept the second attempt. A code reaches Stalwart in
# two places: a sign-in through /api/auth (the OAuth login every two-step client uses) and the password / two-step
# change (x:AccountPassword/set). IMAP, SMTP and JMAP Basic carry no code, so a two-step account cannot sign in there
# with its password at all, only with an app password; the controls below hold that, on both images.
#
# Every check runs twice: with the in-memory store in the data store (RocksDB), then with it in Valkey, as production
# runs it (both nodes share it, and Valkey's SET NX is what makes the mark atomic across them).
set -euo pipefail
IMG=${1:?usage: $0 <stalwart image>}
CLI=stalwartlabs/cli:1.0.13
VALKEY=valkey/valkey:8.1-alpine
NET=e2e-totp-$$; C=e2e-totp-stalwart-$$; K=e2e-totp-client-$$; V=e2e-totp-valkey-$$
W=$(mktemp -d); mkdir -p "$W/etc" "$W/data"; chmod -R 777 "$W"
echo '{"@type":"RocksDb","path":"/var/lib/stalwart/"}' > "$W/etc/config.json"
cleanup() { set +e; docker rm -f "$C" "$K" "$V" >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT
pw() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }
ADMIN=$(pw)
docker network create "$NET" >/dev/null
docker run -d --name "$V" --network "$NET" --network-alias valkey "$VALKEY" >/dev/null
docker run -d --name "$C" --network "$NET" --network-alias stalwart --hostname mail.one.test --memory 1g \
  -e STALWART_RECOVERY_ADMIN="admin:$ADMIN" \
  -v "$W/etc:/etc/stalwart" -v "$W/data:/var/lib/stalwart" "$IMG" >/dev/null
cli() { docker run --rm --network "$NET" -e STALWART_URL=http://stalwart:8080 -e STALWART_USER=admin -e STALWART_PASSWORD="$ADMIN" "$CLI" --no-color "$@"; }
docker run -d --name "$K" --network "$NET" -e ADMIN="$ADMIN" python:3.12-alpine sleep 900 >/dev/null
ready() {
docker exec "$K" python3 -c "
import time,urllib.request
for _ in range(90):
    try: urllib.request.urlopen('http://stalwart:8080/healthz/ready',timeout=2); break
    except Exception: time.sleep(1)
else: raise SystemExit('stalwart never became ready')"
}
ready
id_of() { awk '/Created/ {print $3}'; }
D1=$(cli create Domain --json '{"name":"one.test","dkimManagement":{"@type":"Manual"},"dnsManagement":{"@type":"Manual"}}' | id_of)
mkuser() {
  local p; p=$(pw)
  cli create Account/User --json "{\"name\":\"$1\",\"domainId\":\"$D1\",\"credentials\":{\"0\":{\"@type\":\"Password\",\"secret\":\"$p\"}}}" >/dev/null
  printf '%s' "$p"
}

# One run of every check, as USER with password PW. Prints PASS/FAIL lines; exits 1 on any FAIL.
checks() {
docker exec -i -e USER="$1@one.test" -e PW="$2" -e STORE="$3" "$K" python3 - <<'PY'
import base64,hashlib,hmac,imaplib,json,os,secrets,ssl,struct,time,urllib.error,urllib.parse,urllib.request
B="http://stalwart:8080"; USER=os.environ["USER"]; pw=os.environ["PW"]; STORE=os.environ["STORE"]
fails=[]
def check(ok,msg): print(("PASS " if ok else "FAIL ")+msg); ok or fails.append(msg)
def req(path,body=None,auth=None,form=False):
    h={}
    if auth: h["Authorization"]=auth
    if body is not None: h["Content-Type"]="application/x-www-form-urlencoded" if form else "application/json"
    data=None if body is None else (urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode())
    try:
        with urllib.request.urlopen(urllib.request.Request(B+path,data=data,headers=h),timeout=30) as r: return r.status,json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try: return e.code,json.loads(e.read())
        except Exception: return e.code,None
def basic(u,p): return "Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()
U=["urn:ietf:params:jmap:core","urn:stalwart:jmap"]
def jmap(auth,calls):
    s,b=req("/jmap/",{"using":U,"methodCalls":calls},auth); return s,b
def pwset(auth,patch):
    s,ses=req("/jmap/session",auth=auth); aid=ses["primaryAccounts"]["urn:stalwart:jmap"]
    s,b=jmap(auth,[["x:AccountPassword/set",{"accountId":aid,"update":{"singleton":patch}},"0"]])
    r=b["methodResponses"][0][1]
    if "singleton" in (r.get("updated") or {}): return "updated"
    return ((r.get("notUpdated") or {}).get("singleton") or {}).get("description") or json.dumps(r)[:200]
def totp(seed,t=None):
    k=base64.b32decode(seed); c=int((t or time.time())//30)
    h=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest(); o=h[-1]&15
    return "%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000)
def fresh(seed):
    # The start of the next 30 s window: a code no earlier check has used.
    time.sleep(30-time.time()%30+1); return totp(seed)
def signin(secret,code):
    # /api/auth as a two-step client signs in: an authorization code for a PKCE token exchange.
    v=secrets.token_urlsafe(48); ch=base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    ru="https://webmail.example/oauth/callback"
    s,b=req("/api/auth",{"type":"authCode","accountName":USER,"accountSecret":secret,"mfaToken":code,
        "clientId":"e2e","redirectUri":ru,"codeChallenge":ch,"codeChallengeMethod":"S256"})
    if not (isinstance(b,dict) and b.get("type")=="authenticated"): return None
    s,t=req("/auth/token",{"grant_type":"authorization_code","code":b["client_code"],"client_id":"e2e","redirect_uri":ru,"code_verifier":v},form=True)
    return "Bearer "+t["access_token"] if s==200 else None
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
def imap(user,secret):
    try:
        M=imaplib.IMAP4_SSL("stalwart",993,ssl_context=ctx,timeout=10); M.login(user,secret); M.logout(); return "ok"
    except imaplib.IMAP4.error: return "refused"

# Two-step on, as webmail turns it on (Settings → Security).
seed=base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
url=f"otpauth://totp/E2E:{USER}?secret={seed}&issuer=E2E"
assert pwset(basic(USER,pw),{"currentSecret":pw,"otpAuth":{"otpUrl":url,"otpCode":totp(seed)}})=="updated", "enrol"
print(f"-- in-memory store: {STORE}")

# Controls: where no code travels, the password alone never signs in; an app password does.
check(imap(USER,pw)=="refused", f"[{STORE}] control: IMAP LOGIN with the password alone is refused for a two-step account")
st=req("/jmap/session",auth=basic(USER,pw))[0]
check(st!=200, f"[{STORE}] control: JMAP Basic with the password alone opens no session for a two-step account (HTTP {st})")
code=fresh(seed); tok=signin(pw,code)
check(tok is not None, f"[{STORE}] a two-step sign-in through /api/auth with a fresh code succeeds")
s,ses=req("/jmap/session",auth=tok); aid=ses["primaryAccounts"]["urn:stalwart:jmap"]
s,b=jmap(tok,[["x:AppPassword/set",{"accountId":aid,"create":{"a":{"description":"e2e"}}},"a"]])
app=((b["methodResponses"][0][1].get("created") or {}).get("a") or {}).get("secret")
check(bool(app) and imap(USER,app)=="ok", f"[{STORE}] control: an app password signs in to IMAP")

# 1. The same code twice in one window.
check(signin(pw,code) is None, "the same code a second time, in the same window, is refused")
check(signin(pw,"%06d"%((int(code)+1)%1000000)) is None, f"[{STORE}] control: a wrong code is refused")
check(signin(pw,fresh(seed)) is not None, f"[{STORE}] the next window's code still signs in")

# 2. A code that confirmed a password change.
new=secrets.token_urlsafe(16); c2=fresh(seed)
check(pwset(tok,{"currentSecret":pw,"secret":new,"otpAuth/otpCode":c2})=="updated", f"[{STORE}] a password change confirmed with a fresh code succeeds")
pw=new
check(signin(pw,c2) is None, "a code that confirmed a password change does not sign in again")

# 3. A code already used does not confirm a change; one spent on a REFUSED change is not spent.
c3=fresh(seed); tok=signin(pw,c3)
check(tok is not None, f"[{STORE}] sign-in with the new password and a fresh code")
new=secrets.token_urlsafe(16)
reused=pwset(tok,{"currentSecret":pw,"secret":new,"otpAuth/otpCode":c3})
check(reused!="updated", "a code already used does not confirm a password change")
if reused=="updated":
    # Without the patch the change went through and revoked the token: carry on as the account now is.
    pw=new; tok=signin(pw,fresh(seed))
c4=fresh(seed)
check(pwset(tok,{"currentSecret":pw,"secret":"short","otpAuth/otpCode":c4})!="updated", f"[{STORE}] control: a too-short new password is refused")
new=secrets.token_urlsafe(16)
check(pwset(tok,{"currentSecret":pw,"secret":new,"otpAuth/otpCode":c4})=="updated",
      f"[{STORE}] the code that the refused change carried still confirms the next change")
print(f"{len(fails)} failure(s)"); raise SystemExit(1 if fails else 0)
PY
}

rc=0
checks alice "$(mkuser alice)" rocksdb || rc=1
# The same checks with the in-memory store in Valkey, as production runs it. A restart applies the store change.
docker exec -i "$K" python3 - <<'PY'
import base64,json,os,urllib.request
B="http://stalwart:8080"; h={"Authorization":"Basic "+base64.b64encode(f"admin:{os.environ['ADMIN']}".encode()).decode(),"Content-Type":"application/json"}
aid=json.load(urllib.request.urlopen(urllib.request.Request(B+"/jmap/session",headers=h)))["primaryAccounts"]["urn:stalwart:jmap"]
r=json.load(urllib.request.urlopen(urllib.request.Request(B+"/jmap/",headers=h,data=json.dumps({"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
  "methodCalls":[["x:InMemoryStore/set",{"accountId":aid,"update":{"singleton":{"@type":"Redis","url":"redis://valkey:6379"}}},"s"]]}).encode())))
assert "singleton" in (r["methodResponses"][0][1].get("updated") or {}), r
PY
docker restart "$C" >/dev/null; ready
checks bob "$(mkuser bob)" valkey || rc=1
# And it took: the same failed sign-in answers "failure" with Valkey up, and cannot answer that with it paused (the
# auth-failure counter lives in the in-memory store).
probe() { docker exec "$K" python3 -c "
import json,urllib.request,urllib.error
r=urllib.request.Request('http://stalwart:8080/api/auth',data=json.dumps({'type':'authCode','accountName':'nobody@one.test','accountSecret':'x','clientId':'e2e','redirectUri':'https://webmail.example/cb'}).encode(),headers={'Content-Type':'application/json'})
try: print(json.load(urllib.request.urlopen(r,timeout=30)).get('type'))
except urllib.error.HTTPError as e: print(e.code)
except Exception as e: print(type(e).__name__)"; }
up=$(probe); docker pause "$V" >/dev/null; paused=$(probe); docker unpause "$V" >/dev/null
if [ "$up" = failure ] && [ "$paused" != failure ]; then echo "PASS [valkey] control: the in-memory store is Valkey (a failed sign-in: $up, with Valkey paused: $paused)"
else echo "FAIL [valkey] control: the in-memory store is Valkey (a failed sign-in: $up, with Valkey paused: $paused)"; rc=1; fi
exit $rc
