#!/usr/bin/env bash
# End-to-end: a bounce returns the original's headers as text/rfc822-headers, byte for byte, in 7bit (8bit for UTF-8),
# past the first 4096 bytes and up to a 64 KiB cap.
# usage: e2e-dsn-headers.sh <stalwart image>
#
# Upstream returns the headers only, but labels them message/rfc822 and quoted-printable-encodes them whenever a header
# line is longer than 77 characters, which most mail has. Amazon SES parses a message/rfc822 part as a whole message and
# refuses the bounce: 554 "Unbalanced quoted string" for that shape, 554 "Missing start boundary" for the same headers in
# 7bit, when they name a multipart. It accepts text/rfc822-headers in 7bit (measured through real SES, MainThrive
# MAI-1036). Patch 0013 sends that, and 0014 reads up to 64 KiB of headers, not 4096 bytes (MAI-1131). Here a real
# bounce: org submits eight messages to an outside domain whose MX (a stub
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
import base64,email,json,os,quopri,random,re,secrets,sys,time,urllib.request,urllib.error
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
# Four originals: ASCII, with a header line past 77 characters (upstream quoted-printable-encodes the part then) and a
# multipart Content-Type (SES then needs a boundary the part lacks); one whose Subject is raw UTF-8; one with a header
# line past 998 octets, which neither 7bit nor 8bit may carry, so mail-builder encodes it; and one with a lone CR, which
# 7bit may not carry either and which mail-builder passes through as 7bit (upstream's bounce does, measured), so 0013
# ends it as a line.
LONG="X-Long: "+"-".join(f"word{i}" for i in range(30))
LONGLINE="X-Very-Long: "+"y"*1000
LONECR="X-Odd: a lone\rCR"
BODY=('Content-Type: multipart/alternative; boundary="=_e2e"\r\n\r\n'
      +'--=_e2e\r\nContent-Type: text/plain; charset="utf-8"\r\n\r\nhello\r\n--=_e2e--\r\n')
def original(tag,subject,extra=LONG):
    return ("From: Org <org@one.test>\r\nTo: <nobody@two.test>\r\n"+f"Subject: {subject}\r\n"
            +"Date: Tue, 21 Oct 2026 12:00:00 +0000\r\n"+f"Message-ID: <e2e-dsn-{tag}@one.test>\r\n"
            +extra+"\r\nMIME-Version: 1.0\r\n"+BODY).encode()
SENT={"ascii":original("ascii","an outside recipient that does not exist"),"utf8":original("utf8","Grüße, ein Empfänger, den es nicht gibt"),
      "longline":original("longline","a header line past 998 octets",LONGLINE),"lonecr":original("lonecr","a lone CR",LONECR)}
# Three more for the 4096-byte read upstream stopped at (MAI-1131); "latin1", below, is the fourth.
# "gmail" is the shape of the real message that bounced to Spam (MainThrive MAI-1127 step 4, 6167 B): our own trace headers,
# then Gmail's Received, ARC and DKIM blocks, then From, Subject and Message-ID. Same headers, order and sizes; the
# signatures are random and the addresses are this test's. "big" is 5 KiB of plain headers before them. "huge" is past
# 0014's 64 KiB cap, so its identifying headers come first: its part must stop at the cap, on a whole line.
# The first two cannot be matched to their bounce by Message-ID on an image that cuts it off, so their first header (our
# Received) carries a trace id too.
R=random.Random(1131)
def b64(n): return base64.b64encode(R.randbytes(n)).decode()
def fold(name,value):
    out,line=[],name+":"
    for word in value.split(" "):
        if len(line)+1+len(word)>78 and line.strip() and not line.endswith(":"): out.append(line); line=" "
        line+=(" " if line!=" " else "")+word
    return "\r\n".join(out+[line])+"\r\n"
def chunks(s,n=72): return " ".join(s[i:i+n] for i in range(0,len(s),n))
def identifying(tag,subject):
    return ("MIME-Version: 1.0\r\nFrom: Org <org@one.test>\r\nDate: Tue, 21 Oct 2026 21:08:06 +0000\r\n"
            +fold("X-Gm-Features",b64(96))+f"Message-ID: <e2e-dsn-{tag}@one.test>\r\nSubject: {subject}\r\n"
            +"To: <nobody@two.test>\r\n")
def trace(tag):
    return (fold("Received","from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mail.mainthrive.com"
                 f" (Stalwart) with ESMTPS id trace-{tag}-id; Tue, 21 Oct 2026 21:08:15 +0000")
        +fold("Authentication-Results","mail.mainthrive.com; dkim=pass header.d=gmail.com header.s=20230601 header.b="+b64(6)
              +"; spf=pass (mail.mainthrive.com: domain of sender@gmail.com designates 209.85.128.41 as permitted sender)"
              " smtp.mailfrom=sender@gmail.com; dmarc=pass header.from=gmail.com policy.dmarc=none; arc=pass"
              " (i=1, d=google.com, s=arc-20240605) header.d=google.com")
        +fold("Received-SPF","pass (mail.mainthrive.com: domain of sender@gmail.com designates 209.85.128.41 as permitted"
              " sender) receiver=mail.mainthrive.com; client-ip=209.85.128.41; envelope-from=\"sender@gmail.com\";"
              " helo=mail-wm1-f41.google.com;")
        +fold("X-Spam-Result",", ".join(f"{n} ({v})" for n,v in [("ARC_SIGNED","0.00"),("DKIM_ALLOW","-0.20"),
              ("DMARC_POLICY_ALLOW","-0.20"),("SPF_ALLOW","-0.20"),("FREEMAIL_FROM","0.00"),("FREEMAIL_ENVFROM","0.00"),
              ("RCVD_COUNT_ONE","0.00"),("RCVD_TLS_LAST","0.00"),("MIME_GOOD","-0.10"),("FROM_HAS_DN","0.00"),
              ("TO_DN_NONE","0.00"),("RCPT_COUNT_ONE","0.00"),("ARC_ALLOW","-1.00"),("RCVD_VIA_SMTP_AUTH","0.00"),
              ("DWL_DNSWL_NONE","0.00"),("TO_MATCH_ENVRCPT_ALL","0.00"),("FROM_EQ_ENVFROM","0.00"),("MID_RHS_MATCH_FROM","0.00")]))
        +"X-Spam-Score: -1.9\r\nReturn-Path: <sender@gmail.com>\r\n")
def gmail():
    h=("to:subject:message-id:date:from:mime-version:from:to:cc:subject:date:message-id:reply-to")
    return (trace("gmail")
        +fold("Received","by mail-wm1-f41.google.com with SMTP id 5b1f17b1804b1-47117f92e32so41755e9.1 for"
              " <test@pilot.mainthrive.com>; Tue, 21 Oct 2026 14:08:07 -0700 (PDT)")
        +fold("ARC-Seal","i=1; a=rsa-sha256; t=1792616887; cv=none; d=google.com; s=arc-20240605; b="+chunks(b64(256)))
        +fold("ARC-Message-Signature","i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;"
              " h=to:subject:message-id:date:from:mime-version:dkim-signature; bh="+b64(32)+"; fh="+b64(32)+"; b="+chunks(b64(256)))
        +fold("ARC-Authentication-Results","i=1; mx.google.com; dkim=pass header.i=@gmail.com header.s=20230601 header.b="
              +b64(6)+"; spf=pass (google.com: domain of sender@gmail.com designates 209.85.220.41 as permitted sender)"
              " smtp.mailfrom=sender@gmail.com; dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;"
              " dara=pass header.i=@pilot.mainthrive.com")
        +fold("DKIM-Signature","v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; t=1792616886;"
              " x=1793221686; darn=pilot.mainthrive.com; h="+h+"; bh="+b64(32)+"; b="+chunks(b64(256)))
        +fold("X-Google-DKIM-Signature","v=1; a=rsa-sha256; c=relaxed/relaxed; d=1e100.net; s=20230601; t=1792616886;"
              " x=1793221686; h=x-gm-message-state:"+h+"; bh="+b64(32)+"; b="+chunks(b64(256)))
        +fold("X-Gm-Message-State",b64(90))+fold("X-Gm-Gg",chunks(b64(420)))+fold("X-Google-Smtp-Source",b64(90))
        +fold("X-Received","by 2002:a05:600c:3b15:b0:471:15c0:9e4b with SMTP id 5b1f17b1804b1-47117f92e2fmr6372845e9.27.1792616886742;"
              " Tue, 21 Oct 2026 14:08:06 -0700 (PDT)")
        +identifying("gmail","a full-size Gmail original"))
SENT["gmail"]=(gmail()+BODY).encode()
SENT["big"]=(trace("big")+"".join(f"X-Pad-{i:02d}: "+"p"*90+"\r\n" for i in range(50))
             +identifying("big","more than 4 KiB of headers before this one")+BODY).encode()
PAD=lambda i: f"X-Pad-{i:04d}: "+"z"*900
SENT["huge"]=(identifying("huge","headers past the 64 KiB cap")+"".join(PAD(i)+"\r\n" for i in range(80))+BODY).encode()
DEEP=("gmail","big")
IDS=(b"From",b"Subject",b"Message-ID")
def header_line(headers,name): return re.search(rb"^"+name+rb":.*$",headers,re.M)
# "latin1" carries a header byte that is not UTF-8, which upstream turned into an EMPTY part (String::from_utf8, or nothing).
# 0014 replaces the byte and returns the rest. An empty part carries no id to match its bounce by, so it goes to its own
# recipient, which the bounce's delivery-status names.
SENT["latin1"]=original("latin1","a header byte that is not UTF-8","X-Legacy: cafe").replace(b"X-Legacy: cafe",b"X-Legacy: caf\xe9")
RCPT=lambda tag: f"nobody-{tag}@two.test" if tag=="latin1" else "nobody@two.test"
for tag in DEEP:
    hb=SENT[tag].split(b"\r\n\r\n",1)[0]
    check(all(header_line(hb,n).start()>4096 for n in IDS),
          f"setup: the {tag} original's From, Subject and Message-ID start past byte 4096 of its headers", len(hb))
for tag,raw in SENT.items():
    _,b=req(f"/jmap/upload/{ACC}/",ORG,raw,"message/rfc822")
    blob=json.loads(b)["blobId"]
    r=r1(ORG,["Email/import",{"accountId":ACC,"emails":{"e":{"blobId":blob,"mailboxIds":{drafts:True},"keywords":{"$draft":True}}}},"e"])[1]
    eid=(r.get("created") or {}).get("e",{}).get("id")
    r=r1(ORG,["EmailSubmission/set",{"accountId":ACC,"create":{"s":{"identityId":ident,"emailId":eid,
        "envelope":{"mailFrom":{"email":"org@one.test"},"rcptTo":[{"email":RCPT(tag)}]}}}},"s"])[1]
    check("s" in (r.get("created") or {}), f"setup: the {tag} original is submitted to {RCPT(tag)}", r.get("notCreated",""))
def bounces():
    found={}
    for i in r1(ORG,["Email/query",{"accountId":ACC},"q"])[1].get("ids",[]):
        g=r1(ORG,["Email/get",{"accountId":ACC,"ids":[i],"properties":["blobId"]},"g"])[1]["list"][0]
        raw=req(f"/jmap/download/{ACC}/{g['blobId']}/m",ORG)[1]
        if b"multipart/report" not in raw.split(b"\r\n\r\n",1)[0]: continue
        flat=raw.replace(b"=\r\n",b"")
        for tag in SENT:
            ids=(f"e2e-dsn-{tag}@one.test",f"trace-{tag}-id")+((RCPT(tag),) if tag=="latin1" else ())
            if any(i.encode() in flat for i in ids): found[tag]=raw
    return found
got={}
for _ in range(36):
    got=bounces()
    if len(got)==len(SENT): break
    time.sleep(5)
def third_part(raw):
    # The raw body of the report's third part, exactly as sent (the email package would decode it).
    head,body=raw.split(b"\r\n\r\n",1)
    b=head.split(b'boundary="',1)[1].split(b'"',1)[0]
    parts=body.split(b"--"+b)[1:-1]
    p=parts[2] if len(parts)>2 else b""
    return p.lstrip(b"\r\n").partition(b"\r\n\r\n")[2]
for tag,sent in SENT.items():
    raw=got.get(tag)
    check(raw is not None, f"setup: the {tag} original bounces back to org")
    if raw is None: continue
    body=third_part(raw)
    parts=email.message_from_bytes(raw).get_payload()
    part=parts[2] if len(parts)>2 else email.message.Message()
    ctype,cte=part.get_content_type(),(part.get("Content-Transfer-Encoding") or "").lower()
    headers=sent.split(b"\r\n\r\n",1)[0]
    # A control: whatever the encoding, the part carries the original's Message-ID once decoded (upstream's too: the email
    # package does not decode a message/* part, so its quoted-printable is decoded here).
    decoded=quopri.decodestring(body) if part.get_content_maintype()=="message" else (part.get_payload(decode=True) or b"")
    if tag in DEEP:
        # The control for these two is the trace id, which is in the first 4096 bytes on any image.
        check(f"trace-{tag}-id".encode() in decoded, f"control: the {tag} bounce's third part starts with the original's first header")
        ids=[header_line(headers,n).group(0).rstrip(b"\r") for n in IDS]
        check(all(i in decoded for i in ids), f"the {tag} bounce returns the original's From, Subject and Message-ID", len(decoded))
    elif tag=="latin1":
        # Upstream empties this part, so the control is the bounce's report naming this original's own recipient.
        check(RCPT(tag).encode() in raw, f"control: the {tag} bounce reports its own recipient")
    else:
        check(f"<e2e-dsn-{tag}@one.test>".encode() in decoded, f"control: the {tag} bounce's third part carries the original's Message-ID")
    check(ctype=="text/rfc822-headers", f"the {tag} bounce returns the headers as text/rfc822-headers, not message/rfc822", ctype)
    if tag=="longline":
        check(cte in ("quoted-printable","base64") and b"y"*1000 in decoded, "the longline bounce leaves a line past 998 octets to mail-builder's encoding, and decodes to it", cte)
    elif tag=="huge":
        # Cut at the cap, on a whole line: 60 KiB < part <= 64 KiB, ending in CRLF after a whole pad line.
        # The block without the CRLFs that end it and precede the boundary; with its own final CRLF it fits the cap.
        block=body.rstrip(b"\r\n")
        whole=re.fullmatch(rb"X-Pad-\d{4}: z{900}",block.rsplit(b"\r\n",1)[-1]) is not None
        last=block.rsplit(b"\r\n",1)[-1]
        check(cte=="7bit" and 60*1024<len(block)+2<=64*1024 and whole,
              "the huge bounce returns its headers up to the 64 KiB cap, cut at a whole line", f"{cte} {len(body)} B, last line {last[:24]!r}")
    elif tag=="latin1":
        ids=[header_line(headers,n).group(0).rstrip(b"\r") for n in IDS]
        check(cte=="8bit" and all(i in body for i in ids) and b"X-Legacy: caf\xef\xbf\xbd\r\n" in body,
              "the latin1 bounce returns its headers, the byte that is not UTF-8 replaced, in 8bit", f"{cte} {len(body)} B")
    elif tag=="lonecr":
        paired=body.count(b"\r")==body.count(b"\r\n")==body.count(b"\n")
        check(cte=="7bit" and paired and b"X-Odd: a lone\r\nCR\r\n" in body, "the lonecr bounce ends a lone CR as a line: every CR and LF in its 7bit part is a CRLF", cte)
    else:
        want="8bit" if tag=="utf8" else "7bit"
        check(cte==want and headers in body, f"the {tag} bounce returns every header byte for byte, in {want}", cte)
print("RESULT", "fail" if fails else "pass", len(fails)); sys.exit(1 if fails else 0)
PY
