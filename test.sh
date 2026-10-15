#!/bin/sh
# End-to-end smoke test: starts pds on a temp DB, exercises every XRPC route.
set -eu
PORT=${PORT:-2599}
DB=$(mktemp -d)/t.sqlite
PDS_PORT=$PORT PDS_DB=$DB PDS_JWT_SECRET=test ./pds 2>/dev/null &
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

R=$(post com.atproto.server.createAccount '{"handle":"Alice.localhost","password":"pw","email":"a@x.io"}')
DID=$(echo "$R" | field did); TOK=$(echo "$R" | field accessJwt); REF=$(echo "$R" | field refreshJwt)
case $DID in did:plc:*) ;; *) fail "createAccount $R";; esac
post com.atproto.server.createAccount '{"handle":"alice.localhost","password":"x"}' | grep -q HandleNotAvailable || fail dup handle
post com.atproto.server.createAccount '{"handle":"bob.evil.com","password":"x"}' | grep -q InvalidHandle || fail bad handle

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
get com.atproto.sync.subscribeRepos | grep -q MethodNotImplemented || fail 501
echo "all tests passed"
