#!/bin/sh
# End-to-end smoke test: starts pds on a temp DB, exercises every XRPC route.
set -eu
PORT=${PORT:-2599}
DB=$(mktemp -d)/t.sqlite
PDS_PORT=$PORT PDS_DB=$DB PDS_JWT_SECRET=test PDS_ADMIN_PASSWORD=adminpw PDS_APPVIEW_URL=http://127.0.0.1:9 ./pds 2>"$DB.log" &
PID=$!
trap 'kill $PID' EXIT
for _ in $(seq 50); do curl -s localhost:$PORT >/dev/null && break; sleep 0.1; done
U=http://localhost:$PORT/xrpc
fail() { echo "FAIL: $*"; exit 1; }
get() { curl -s "$U/$1"; }
post() { curl -s -X POST -H 'Content-Type: application/json' ${TOK:+-H "Authorization: Bearer $TOK"} -d "$2" "$U/$1"; }
field() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"; }

get _health | grep -q version || fail health
get com.atproto.server.describeServer | grep -q '".localhost"' || fail describeServer

# signup needs an invite code minted by the admin
get com.atproto.server.describeServer | grep -q '"inviteCodeRequired":true' || fail invite-flag
post com.atproto.server.createAccount '{"handle":"alice.localhost","password":"pw"}' | grep -q InvalidInviteCode || fail no-invite
post com.atproto.server.createInviteCode '{"useCount":1}' | grep -q AuthenticationRequired || fail invite-noadmin
curl -s -X POST -u admin:wrong -H 'Content-Type: application/json' -d '{"useCount":1}' "$U/com.atproto.server.createInviteCode" | grep -q AuthenticationRequired || fail invite-badadmin
CODE=$(curl -s -X POST -u admin:adminpw -H 'Content-Type: application/json' -d '{"useCount":1}' "$U/com.atproto.server.createInviteCode" | field code)
case $CODE in localhost-*) ;; *) fail "createInviteCode $CODE";; esac
R=$(post com.atproto.server.createAccount "{\"handle\":\"Alice.localhost\",\"password\":\"pw\",\"email\":\"a@x.io\",\"inviteCode\":\"$CODE\"}")
DID=$(echo "$R" | field did); TOK=$(echo "$R" | field accessJwt); REF=$(echo "$R" | field refreshJwt)
case $DID in did:plc:*) ;; *) fail "createAccount $R";; esac
post com.atproto.server.createAccount '{"handle":"alice.localhost","password":"x"}' | grep -q HandleNotAvailable || fail dup handle
post com.atproto.server.createAccount '{"handle":"bob.evil.com","password":"x"}' | grep -q InvalidHandle || fail bad handle
post com.atproto.server.createAccount "{\"handle\":\"bob.localhost\",\"password\":\"x\",\"inviteCode\":\"$CODE\"}" | grep -q InvalidInviteCode || fail invite-reuse

TOK= post com.atproto.server.createSession '{"identifier":"a@x.io","password":"pw"}' | grep -q accessJwt || fail login
TOK= post com.atproto.server.createSession '{"identifier":"alice.localhost","password":"no"}' | grep -q AuthenticationRequired || fail badpw
curl -s -H "Authorization: Bearer $TOK" "$U/com.atproto.server.getSession" | grep -q alice.localhost || fail getSession
curl -s -H "Authorization: Bearer $REF" "$U/com.atproto.server.getSession" | grep -q AuthenticationRequired || fail refresh-as-access
TOK=$REF post com.atproto.server.refreshSession '' | grep -q accessJwt || fail refreshSession
curl -s -H "Authorization: Bearer ${TOK%?}x" "$U/com.atproto.server.getSession" | grep -q AuthenticationRequired || fail tampered
get "com.atproto.identity.resolveHandle?handle=alice.localhost" | grep -q "$DID" || fail resolveHandle
curl -s -H "Host: alice.localhost" "http://localhost:$PORT/.well-known/atproto-did" | grep -q "$DID" || fail well-known

# CID must match independent dag-cbor encoding: {"$type":"app.bsky.feed.post","createdAt":"...","text":"hi"}
REC='{"text":"hi","createdAt":"2024-01-01T00:00:00Z"}'
R=$(post com.atproto.repo.createRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.feed.post\",\"record\":$REC}")
CID=$(echo "$R" | field cid); URI=$(echo "$R" | field uri)
[ "$CID" = bafyreidwroesxuw5qzp4pdvvpbxv4bjuvhubqz4zfz3de6pi3a5c5rryum ] || fail "cid $R"
RK=${URI##*/}
get "com.atproto.repo.getRecord?repo=alice.localhost&collection=app.bsky.feed.post&rkey=$RK" | grep -q '"text":"hi"' || fail getRecord
post com.atproto.repo.createRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.feed.post\",\"record\":{\"n\":1.5}}" | grep -q InvalidRecord || fail float
post com.atproto.repo.createRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.feed.post\",\"record\":{\"\$type\":\"x.y.z\"}}" | grep -q InvalidRecord || fail type
TOK= post com.atproto.repo.createRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.feed.post\",\"record\":{}}" | grep -q AuthenticationRequired || fail noauth

post com.atproto.repo.putRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.actor.profile\",\"rkey\":\"self\",\"record\":{\"displayName\":\"A\"},\"swapRecord\":null}" | grep -q cid || fail put
post com.atproto.repo.putRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.actor.profile\",\"rkey\":\"self\",\"record\":{},\"swapRecord\":\"bafywrong\"}" | grep -q InvalidSwap || fail swap
for i in 1 2 3; do post com.atproto.repo.createRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.feed.like\",\"record\":{\"i\":$i}}" >/dev/null; done
L=$(get "com.atproto.repo.listRecords?repo=$DID&collection=app.bsky.feed.like&limit=2")
echo "$L" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert [r["value"]["i"] for r in d["records"]]==[3,2] and d["cursor"]' || fail "list $L"
C=$(echo "$L" | field cursor)
get "com.atproto.repo.listRecords?repo=$DID&collection=app.bsky.feed.like&cursor=$C" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert [r["value"]["i"] for r in d["records"]]==[1] and "cursor" not in d' || fail page2
get "com.atproto.repo.describeRepo?repo=$DID" | grep -q '"app.bsky.feed.like","app.bsky.feed.post"' || fail describeRepo
post com.atproto.repo.deleteRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.feed.post\",\"rkey\":\"$RK\"}" | grep -q commit || fail delete
get "com.atproto.repo.getRecord?repo=$DID&collection=app.bsky.feed.post&rkey=$RK" | grep -q RecordNotFound || fail gone
# sync: every write moves the signed head; getRepo serves it as a CAR
H=$(get "com.atproto.sync.getLatestCommit?did=$DID" | field cid)
case $H in bafyrei*) ;; *) fail "getLatestCommit $H";; esac
W=$(post com.atproto.repo.createRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.feed.post\",\"record\":{\"text\":\"x\"}}")
H2=$(get "com.atproto.sync.getLatestCommit?did=$DID" | field cid)
[ "$H2" != "$H" ] && echo "$W" | grep -q "\"cid\":\"$H2\"" || fail "commit not advanced $W"
get "com.atproto.sync.listRepos" | grep -q "\"head\":\"$H2\"" || fail listRepos
curl -s -D - -o /dev/null "$U/com.atproto.sync.getRepo?did=$DID" | grep -qi 'content-type: application/vnd.ipld.car' || fail getRepo
get "com.atproto.repo.describeRepo?repo=$DID" | grep -q '"publicKeyMultibase":"zQ3s' || fail didDoc key
# blobs: raw-codec CID, bytes round-trip, served inert
BLOBF=$(dirname "$DB")/blob.bin; head -c 3000 /dev/urandom > "$BLOBF"
WANT=$(python3 -c 'import sys,hashlib,base64; d=open(sys.argv[1],"rb").read(); print("b"+base64.b32encode(bytes([1,0x55,0x12,0x20])+hashlib.sha256(d).digest()).decode().lower().rstrip("="))' "$BLOBF")
R=$(curl -s -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: image/png' --data-binary @"$BLOBF" "$U/com.atproto.repo.uploadBlob")
echo "$R" | grep -q "\"\$link\":\"$WANT\"" && echo "$R" | grep -q '"size":3000' || fail "uploadBlob $R"
curl -s -X POST -H 'Content-Type: image/png' --data-binary @"$BLOBF" "$U/com.atproto.repo.uploadBlob" | grep -q AuthenticationRequired || fail blob-noauth
curl -s "$U/com.atproto.sync.getBlob?did=$DID&cid=$WANT" | cmp -s - "$BLOBF" || fail getBlob
curl -s -D - -o /dev/null "$U/com.atproto.sync.getBlob?did=$DID&cid=$WANT" | grep -qi 'x-content-type-options: nosniff' || fail blob-headers
get "com.atproto.sync.listBlobs?did=$DID" | grep -q "$WANT" || fail listBlobs
head -c 6000000 /dev/zero | curl -s -X POST -H "Authorization: Bearer $TOK" --data-binary @- "$U/com.atproto.repo.uploadBlob" | grep -q BlobTooLarge || fail blob-limit
post com.atproto.repo.putRecord "{\"repo\":\"$DID\",\"collection\":\"app.bsky.actor.profile\",\"rkey\":\"self\",\"record\":{\"avatar\":$(echo "$R" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["blob"]))')}}" | grep -q commit || fail avatar

# preferences stay local; other app.bsky.* calls are proxied (AppView unreachable here)
post app.bsky.actor.putPreferences '{"preferences":[{"$type":"app.bsky.actor.defs#savedFeedsPrefV2","items":[]}]}' >/dev/null
curl -s -H "Authorization: Bearer $TOK" "$U/app.bsky.actor.getPreferences" | grep -q savedFeedsPrefV2 || fail prefs
curl -s -H "Authorization: Bearer $TOK" "$U/app.bsky.feed.getTimeline" | grep -q UpstreamFailure || fail proxy
curl -s -H "Authorization: Bearer $TOK" "$U/com.atproto.server.getServiceAuth?aud=did:web:x.test&lxm=a.b.c" | grep -q token || fail serviceAuth
curl -s -H "Authorization: Bearer $TOK" "$U/com.atproto.server.getServiceAuth?aud=did:web:x.test&exp=99999999999" | grep -q BadExpiration || fail serviceAuth-exp

# identity: session carries didDoc, PDS serves its did:web doc, handle changes
TOK= post com.atproto.server.createSession '{"identifier":"a@x.io","password":"pw"}' | grep -q '"didDoc":{' || fail session-didDoc
curl -s "http://localhost:$PORT/.well-known/did.json" | grep -q '"id":"did:web:localhost"' || fail did.json
post com.atproto.identity.updateHandle '{"handle":"Alice2.localhost"}' | grep -q '^{}$' || fail updateHandle
get "com.atproto.identity.resolveHandle?handle=alice2.localhost" | grep -q "$DID" || fail resolve-new-handle
post com.atproto.identity.updateHandle '{"handle":"alice.localhost"}' >/dev/null

# email: no SMTP configured, so the token shows up in the server log
mailtok() { sleep 0.2; grep -o '[A-Z2-7]\{5\}-[A-Z2-7]\{5\}' "$DB.log" | tail -1; }
curl -s -H "Authorization: Bearer $TOK" "$U/com.atproto.server.getSession" | grep -q '"emailConfirmed":false' || fail email-unconfirmed
post com.atproto.server.requestEmailConfirmation '' | grep -q '^{}$' || fail requestEmailConfirmation
ET=$(mailtok)
post com.atproto.server.confirmEmail '{"email":"a@x.io","token":"AAAAA-AAAAA"}' | grep -q InvalidToken || fail confirm-badtoken
post com.atproto.server.confirmEmail "{\"email\":\"b@x.io\",\"token\":\"$ET\"}" | grep -q InvalidEmail || fail confirm-bademail
post com.atproto.server.confirmEmail "{\"email\":\"A@x.io\",\"token\":\"$ET\"}" | grep -q '^{}$' || fail confirmEmail
post com.atproto.server.confirmEmail "{\"email\":\"a@x.io\",\"token\":\"$ET\"}" | grep -q InvalidToken || fail confirm-reuse
curl -s -H "Authorization: Bearer $TOK" "$U/com.atproto.server.getSession" | grep -q '"emailConfirmed":true' || fail email-confirmed
post com.atproto.server.updateEmail '{"email":"new@x.io"}' | grep -q TokenRequired || fail update-notoken
post com.atproto.server.requestEmailUpdate '' | grep -q '"tokenRequired":true' || fail requestEmailUpdate
post com.atproto.server.updateEmail "{\"email\":\"bad\r\nBcc: x@y\",\"token\":\"$(mailtok)\"}" | grep -q 'invalid email' || fail update-inject
post com.atproto.server.updateEmail "{\"email\":\"new@x.io\",\"token\":\"$(mailtok)\"}" | grep -q '^{}$' || fail updateEmail
curl -s -H "Authorization: Bearer $TOK" "$U/com.atproto.server.getSession" | grep -q '"email":"new@x.io","emailConfirmed":false' || fail email-updated
post com.atproto.server.requestEmailUpdate '' | grep -q '"tokenRequired":false' || fail update-unconfirmed
post com.atproto.server.updateEmail '{"email":"a@x.io"}' | grep -q '^{}$' || fail update-back
TOK= post com.atproto.server.requestEmailConfirmation '' | grep -q AuthenticationRequired || fail email-noauth

# password reset by mailed token; never reveals whether an email has an account
TOK= post com.atproto.server.requestPasswordReset '{"email":"nobody@x.io"}' | grep -q '^{}$' || fail reset-unknown
TOK= post com.atproto.server.requestPasswordReset '{"email":"A@x.io"}' | grep -q '^{}$' || fail requestPasswordReset
RT=$(mailtok)
TOK= post com.atproto.server.resetPassword '{"token":"AAAAA-AAAAA","password":"x"}' | grep -q InvalidToken || fail reset-badtoken
TOK= post com.atproto.server.resetPassword "{\"token\":\"$(echo $RT | tr A-Z a-z)\",\"password\":\"pw2\"}" | grep -q '^{}$' || fail resetPassword
TOK= post com.atproto.server.resetPassword "{\"token\":\"$RT\",\"password\":\"pw3\"}" | grep -q InvalidToken || fail reset-reuse
TOK= post com.atproto.server.createSession '{"identifier":"a@x.io","password":"pw"}' | grep -q AuthenticationRequired || fail reset-oldpw
TOK= post com.atproto.server.createSession '{"identifier":"a@x.io","password":"pw2"}' | grep -q accessJwt || fail reset-newpw

# PDS_REQUIRE_EMAIL_CONFIRMED: writes wait for a confirmed email (second server)
P2=$((PORT+1)); D2=$(mktemp -d)
PDS_PORT=$P2 PDS_DB=$D2/t.sqlite PDS_JWT_SECRET=t PDS_INVITE_REQUIRED=false PDS_REQUIRE_EMAIL_CONFIRMED=true ./pds 2>"$D2/log" &
PID2=$!; trap 'kill $PID $PID2' EXIT
for _ in $(seq 50); do curl -s localhost:$P2 >/dev/null && break; sleep 0.1; done
post2() { (U=http://localhost:$P2/xrpc; TOK=${GT:-}; post "$@"); }
R=$(post2 com.atproto.server.createAccount '{"handle":"g.localhost","password":"p","email":"g@x.io"}')
GD=$(echo "$R" | field did); GT=$(echo "$R" | field accessJwt)
W="{\"repo\":\"$GD\",\"collection\":\"app.bsky.feed.post\",\"record\":{\"text\":\"x\"}}"
post2 com.atproto.repo.createRecord "$W" | grep -q EmailNotConfirmed || fail gate-write
curl -s -X POST -H "Authorization: Bearer $GT" --data-binary x "http://localhost:$P2/xrpc/com.atproto.repo.uploadBlob" | grep -q EmailNotConfirmed || fail gate-blob
post2 com.atproto.server.requestEmailConfirmation '' >/dev/null
sleep 0.2; GE=$(grep -o '[A-Z2-7]\{5\}-[A-Z2-7]\{5\}' "$D2/log" | tail -1)
post2 com.atproto.server.confirmEmail "{\"email\":\"g@x.io\",\"token\":\"$GE\"}" | grep -q '^{}$' || fail gate-confirm
post2 com.atproto.repo.createRecord "$W" | grep -q commit || fail gate-open

# firehose handshake (RFC 6455 sample key -> known accept value)
curl -s -i --max-time 1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$U/com.atproto.sync.subscribeRepos?cursor=0" 2>/dev/null |
  grep -q 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=' || fail subscribeRepos
get com.atproto.sync.subscribeRepos | grep -q 'websocket upgrade required' || fail subscribeRepos-plain
get com.example.no.method | grep -q MethodNotImplemented || fail 501
# pdsadmin CLI against this server
adm() { PDS_ENV_FILE=/dev/null PDS_HOSTNAME=localhost PDS_PORT=$PORT PDS_ADMIN_PASSWORD=${ADMPW:-adminpw} ./pdsadmin "$@"; }
login() { TOK= post com.atproto.server.createSession "{\"identifier\":\"$1\",\"password\":\"$2\"}"; }
adm create-invite-code | grep -q '^localhost-' || fail cli-invite
ADMPW=nope adm create-invite-code 2>&1 | grep -q AuthenticationRequired || fail cli-badadmin
OUT=$(adm account create carol@x.io carol.localhost)
CDID=$(echo "$OUT" | sed -n 's/^DID      : //p'); CPW=$(echo "$OUT" | sed -n 's/^Password : //p')
login carol.localhost "$CPW" | grep -q accessJwt || fail "cli-create $OUT"
adm account list | grep -q "^carol.localhost  *carol@x.io  *$CDID" || fail cli-list
adm account list | grep -q "alice.localhost" || fail cli-list-alice
adm account takedown "$CDID" | grep -q 'taken down' || fail cli-takedown
login carol.localhost "$CPW" | grep -q AccountTakedown || fail takedown-login
get "com.atproto.sync.getRepoStatus?did=$CDID" | grep -q '"status":"takendown"' || fail takedown-status
get "com.atproto.repo.describeRepo?repo=$CDID" | grep -q RepoTakendown || fail takedown-read
adm account untakedown "$CDID" | grep -q 'untaken down' || fail cli-untakedown
login carol.localhost "$CPW" | grep -q accessJwt || fail untakedown-login
NPW=$(adm account reset-password "$CDID" | sed -n 's/^New password: //p')
login carol.localhost "$CPW" | grep -q AuthenticationRequired || fail old-password
login carol.localhost "$NPW" | grep -q accessJwt || fail new-password
echo n | adm account delete "$CDID" >/dev/null; adm account list | grep -q carol.localhost || fail delete-declined
echo y | adm account delete "$CDID" | grep -q "$CDID deleted" || fail cli-delete
adm account list | grep -q carol.localhost && fail delete-listed
get "com.atproto.repo.describeRepo?repo=$CDID" | grep -q RepoNotFound || fail delete-gone
adm help | grep -q 'reset-password <DID>' || fail cli-help
# web admin panel + the invite routes it uses
ADM="-u admin:adminpw"
curl -s -D - -o /dev/null "http://localhost:$PORT/admin" | grep -qi "content-security-policy: default-src 'none'; script-src" || fail admin-page
curl -s "http://localhost:$PORT/admin" | grep -q '<title>PDS Admin</title>' || fail admin-page-body
get com.atproto.admin.getInviteCodes | grep -q AuthenticationRequired || fail invites-noadmin
curl -s $ADM "$U/com.atproto.admin.getInviteCodes" | grep -q "\"code\":\"$CODE\",\"available\":0" || fail invites-list
C2=$(curl -s -X POST $ADM -H 'Content-Type: application/json' -d '{"useCount":5}' "$U/com.atproto.server.createInviteCode" | field code)
curl -s $ADM "$U/com.atproto.admin.getInviteCodes" | grep -q "\"code\":\"$C2\",\"available\":5" || fail invites-new
curl -s -X POST $ADM -H 'Content-Type: application/json' -d "{\"codes\":[\"$C2\"]}" "$U/com.atproto.admin.disableInviteCodes" | grep -q '^{}$' || fail invites-disable
post com.atproto.server.createAccount "{\"handle\":\"dave.localhost\",\"password\":\"x\",\"inviteCode\":\"$C2\"}" | grep -q InvalidInviteCode || fail invites-disabled

# Caddy on-demand TLS ask hook
curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/tls-check?domain=localhost" | grep -q 200 || fail tls-host
curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/tls-check?domain=Alice.localhost" | grep -q 200 || fail tls-handle
curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/tls-check?domain=evil.example" | grep -q 404 || fail tls-other

# DNS: handle DIDs published as _atproto TXT records via a mock Cloudflare API,
# which also answers DNS-over-HTTPS from the same records (third server)
P3=$((PORT+2)); MP=$((PORT+3)); D3=$(mktemp -d)
cat >"$D3/mock.py" <<'PY'
import json, sys, itertools
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
recs, hooks, ids = {}, [], itertools.count(1)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")
    def route(self, m):
        u = urlparse(self.path); qs = {k: v[0] for k, v in parse_qs(u.query).items()}; p = u.path.split("/")
        if u.path == "/_state": return self.send(200, {"records": list(recs.values()), "hooks": hooks})
        if u.path == "/_reset": recs.clear(); hooks.clear(); return self.send(200, {})
        if u.path == "/hook": hooks.append(self.body()); return self.send(200, {})
        if u.path == "/dns-query":
            ans = [{"name": r["name"], "type": 16, "data": r["content"]} for r in recs.values() if r["name"] == qs.get("name")]
            return self.send(200, {"Status": 0, "Answer": ans})
        if self.headers.get("Authorization") != "Bearer cftok":
            return self.send(403, {"success": False, "errors": [{"message": "bad token"}]})
        if u.path == "/client/v4/zones":
            return self.send(200, {"success": True, "result": [{"id": "z1"}] if qs.get("name") == "localhost" else []})
        if p[:5] != ["", "client", "v4", "zones", "z1"] or len(p) < 6 or p[5] != "dns_records":
            return self.send(404, {"success": False, "errors": [{"message": "no route"}]})
        if m == "GET":
            return self.send(200, {"success": True, "result": [r for r in recs.values() if r["name"] == qs.get("name.exact") and r["type"] == qs.get("type")]})
        if m == "POST":
            r = dict(self.body(), id="r%d" % next(ids)); recs[r["id"]] = r
            return self.send(200, {"success": True, "result": r})
        rid = p[6] if len(p) > 6 else ""
        if rid not in recs: return self.send(404, {"success": False, "errors": [{"message": "no record"}]})
        if m == "PUT": recs[rid] = dict(self.body(), id=rid); return self.send(200, {"success": True, "result": recs[rid]})
        if m == "DELETE": del recs[rid]; return self.send(200, {"success": True, "result": {"id": rid}})
    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 "$D3/mock.py" $MP & MPID=$!
PDS_PORT=$P3 PDS_DB=$D3/t.sqlite PDS_JWT_SECRET=t PDS_INVITE_REQUIRED=false PDS_ADMIN_PASSWORD=adminpw \
  PDS_DNS_PROVIDER=cloudflare PDS_CLOUDFLARE_API_TOKEN=cftok PDS_CLOUDFLARE_API_URL=http://127.0.0.1:$MP/client/v4 \
  PDS_DOH_URL=http://127.0.0.1:$MP/dns-query ./pds 2>"$D3/log" &
PID3=$!; trap 'kill $PID $PID2 $PID3 $MPID' EXIT
for _ in $(seq 50); do curl -s localhost:$P3 >/dev/null && curl -s localhost:$MP/_state >/dev/null && break; sleep 0.1; done
M=http://127.0.0.1:$MP
post3() { (U=http://localhost:$P3/xrpc; post "$@"); }
seed() { curl -s -X POST -H 'Authorization: Bearer cftok' -d "{\"type\":\"TXT\",\"name\":\"$1\",\"content\":\"\\\"$2\\\"\"}" $M/client/v4/zones/z1/dns_records >/dev/null; }
# txt NAME: the record values at NAME, sorted and comma-joined
txt() { curl -s $M/_state | python3 -c 'import json,sys; print(",".join(sorted(r["content"].strip("\"") for r in json.load(sys.stdin)["records"] if r["name"]==sys.argv[1])))' "$1"; }
waitfor() { for _ in $(seq 50); do [ "$(txt "$1")" = "$2" ] && return 0; sleep 0.1; done; fail "dns $1: want '$2' got '$(txt "$1")'"; }
seed _atproto.erin.localhost v=keep; seed _atproto.erin.localhost did=did:plc:stale
R=$(post3 com.atproto.server.createAccount '{"handle":"erin.localhost","password":"p"}')
ED=$(echo "$R" | field did); TOK=$(echo "$R" | field accessJwt)
waitfor _atproto.erin.localhost "did=$ED,v=keep"
TOK=$TOK post3 com.atproto.identity.updateHandle '{"handle":"erin2.localhost"}' | grep -q '^{}$' || fail dns-updateHandle
waitfor _atproto.erin2.localhost "did=$ED"
waitfor _atproto.erin.localhost "v=keep"
# custom domain proven by a DNS TXT record alone (DoH), then left unmanaged
TOK=$TOK post3 com.atproto.identity.updateHandle '{"handle":"erin.invalid"}' | grep -q InvalidHandle || fail dns-unproven
seed _atproto.erin.invalid "did=$ED"
TOK=$TOK post3 com.atproto.identity.updateHandle '{"handle":"erin.invalid"}' | grep -q '^{}$' || fail dns-txt-handle
waitfor _atproto.erin2.localhost ""
[ "$(txt _atproto.erin.invalid)" = "did=$ED" ] || fail dns-custom-untouched
# admin re-sync rebuilds records; deleting the account removes them
FD=$(post3 com.atproto.server.createAccount '{"handle":"fay.localhost","password":"p"}' | field did)
waitfor _atproto.fay.localhost "did=$FD"
curl -s -X POST $M/_reset >/dev/null
post3 com.pzx.admin.syncDns '{}' | grep -q AuthenticationRequired || fail dns-sync-noadmin
curl -s -X POST -u admin:adminpw -H 'Content-Type: application/json' -d '{}' "http://localhost:$P3/xrpc/com.pzx.admin.syncDns" | grep -q '"queued":1' || fail dns-sync
waitfor _atproto.fay.localhost "did=$FD"
curl -s -X POST $M/_reset >/dev/null
PDS_ENV_FILE=/dev/null PDS_HOSTNAME=localhost PDS_PORT=$P3 PDS_ADMIN_PASSWORD=adminpw ./pdsadmin dns-sync | grep -q 'Queued 1' || fail cli-dns-sync
waitfor _atproto.fay.localhost "did=$FD"
curl -s -X POST -u admin:adminpw -H 'Content-Type: application/json' -d "{\"did\":\"$FD\"}" "http://localhost:$P3/xrpc/com.atproto.admin.deleteAccount" >/dev/null
waitfor _atproto.fay.localhost ""
curl -s -X POST -u admin:adminpw -H 'Content-Type: application/json' -d '{}' "$U/com.pzx.admin.syncDns" | grep -q DnsNotConfigured || fail dns-off
# webhook provider: any DNS host can be bridged
P4=$((PORT+4)); curl -s -X POST $M/_reset >/dev/null
PDS_PORT=$P4 PDS_DB=$D3/w.sqlite PDS_JWT_SECRET=t PDS_INVITE_REQUIRED=false PDS_DNS_PROVIDER=webhook \
  PDS_DNS_WEBHOOK_URL=$M/hook PDS_DNS_WEBHOOK_TOKEN=wh ./pds 2>"$D3/wlog" &
PID4=$!; trap 'kill $PID $PID2 $PID3 $MPID $PID4' EXIT
for _ in $(seq 50); do curl -s localhost:$P4 >/dev/null && break; sleep 0.1; done
WD=$(U=http://localhost:$P4/xrpc post com.atproto.server.createAccount '{"handle":"gus.localhost","password":"p"}' | field did)
for _ in $(seq 50); do curl -s $M/_state | grep -q "\"content\": \"did=$WD\"" && break; sleep 0.1; done
curl -s $M/_state | grep -q '"action": "upsert", "type": "TXT", "name": "_atproto.gus.localhost"' || fail "webhook $(curl -s $M/_state)"
PDS_PORT=$((PORT+5)) PDS_DB=$D3/x.sqlite PDS_DNS_PROVIDER=cloudflare ./pds 2>&1 | grep -q PDS_CLOUDFLARE_API_TOKEN || fail dns-config-check

# login attempts per identifier are capped (10 per 5 min)
for i in $(seq 10); do TOK= post com.atproto.server.createSession '{"identifier":"nobody.localhost","password":"x"}' >/dev/null; done
TOK= post com.atproto.server.createSession '{"identifier":"nobody.localhost","password":"x"}' | grep -q RateLimitExceeded || fail ratelimit
echo "all tests passed"
