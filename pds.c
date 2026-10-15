/* pds.c — minimal AT Protocol Personal Data Server.
 *
 * Accounts, sessions (HS256 JWT) and record CRUD over XRPC, stored in SQLite.
 * Each write rebuilds the repo's Merkle Search Tree and signs a v3 commit with
 * the account's secp256k1 key; com.atproto.sync.getRepo exports it as a CAR
 * and subscribeRepos streams commits. DIDs are did:plc, registered with the
 * PLC directory, and relays are asked to crawl (both off on localhost).
 */
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <microhttpd.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#define MAX_BODY (5 << 20) /* also the blob size limit */
#define ACCESS_TTL (2 * 3600)
#define REFRESH_TTL (60 * 24 * 3600)

static sqlite3 *db;
static const char *hostname, *plc_url, *crawler; /* NULL: stay local */
static const char *appview_url, *appview_did;
/* ponytail: one recursive lock serializes all state (sqlite, subscribers,
 * caches); only proxied calls run outside it. Finer locks if contention shows. */
static pthread_mutex_t big;
static char endpoint[300], service_did[300];
static unsigned char jwt_secret[32];

/* ---------- encoding helpers ---------- */

static void b32(const unsigned char *in, size_t n, char *out) {
	static const char a[] = "abcdefghijklmnopqrstuvwxyz234567";
	uint32_t acc = 0;
	int bits = 0;
	for (size_t i = 0; i < n; i++) {
		acc = (acc << 8) | in[i];
		bits += 8;
		while (bits >= 5) *out++ = a[(acc >> (bits -= 5)) & 31];
	}
	if (bits) *out++ = a[(acc << (5 - bits)) & 31];
	*out = 0;
}

static int b32dec(const char *s, unsigned char *out, size_t max) {
	static const char a[] = "abcdefghijklmnopqrstuvwxyz234567";
	uint32_t acc = 0;
	int bits = 0;
	size_t n = 0;
	for (const char *p; *s; s++) {
		if (!(p = strchr(a, *s))) return -1;
		acc = (acc << 5) | (uint32_t)(p - a);
		if ((bits += 5) >= 8) {
			if (n == max) return -1;
			out[n++] = (unsigned char)(acc >> (bits -= 8));
		}
	}
	return (int)n;
}

static void hex(const unsigned char *in, size_t n, char *out) {
	for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", in[i]);
}

static void b64url(const unsigned char *in, size_t n, char *out) {
	int len = EVP_EncodeBlock((unsigned char *)out, in, (int)n);
	while (len && out[len - 1] == '=') len--;
	out[len] = 0;
	for (char *p = out; *p; p++) *p = *p == '+' ? '-' : *p == '/' ? '_' : *p;
}

/* Returns decoded length or -1. out must hold n bytes. */
static int b64url_dec(const char *in, size_t n, unsigned char *out) {
	if (n % 4 == 1 || n > 4096) return -1;
	char tmp[4100];
	size_t pad = (4 - n % 4) % 4;
	for (size_t i = 0; i < n; i++) tmp[i] = in[i] == '-' ? '+' : in[i] == '_' ? '/' : in[i];
	memset(tmp + n, '=', pad);
	int len = EVP_DecodeBlock(out, (unsigned char *)tmp, (int)(n + pad));
	return len < 0 ? -1 : len - (int)pad;
}

/* Timestamp identifier: sortable base32 record key. */
static void tid(char out[14]) {
	static const char a[] = "234567abcdefghijklmnopqrstuvwxyz";
	static uint64_t last, clk = UINT64_MAX;
	if (clk == UINT64_MAX) {
		RAND_bytes((unsigned char *)&clk, sizeof clk);
		clk &= 1023;
	}
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	uint64_t us = (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
	if (us <= last) us = last + 1;
	last = us;
	uint64_t v = ((us << 10) | clk) & INT64_MAX;
	for (int i = 12; i >= 0; i--, v >>= 5) out[i] = a[v & 31];
	out[13] = 0;
}

/* ---------- DAG-CBOR + CID ---------- */

typedef struct { unsigned char *p; size_t n, cap; } buf;

static void put(buf *b, const void *d, size_t n) {
	if (b->n + n > b->cap) b->p = realloc(b->p, b->cap = (b->n + n) * 2);
	memcpy(b->p + b->n, d, n);
	b->n += n;
}

static void head(buf *b, int major, uint64_t v) {
	unsigned char h[9];
	int extra = v < 24 ? 0 : v <= 0xff ? 1 : v <= 0xffff ? 2 : v <= 0xffffffff ? 4 : 8;
	h[0] = (unsigned char)(major << 5 | (extra == 0 ? v : extra == 1 ? 24 : extra == 2 ? 25 : extra == 4 ? 26 : 27));
	for (int i = 0; i < extra; i++) h[1 + i] = (unsigned char)(v >> (8 * (extra - 1 - i)));
	put(b, h, 1 + extra);
}

static void text(buf *b, const char *s) {
	size_t n = strlen(s);
	head(b, 3, n);
	put(b, s, n);
}

/* A CID here is always 36 raw bytes: v1, codec, sha2-256, 32-byte digest. */
static void cid_put(buf *b, const unsigned char c[36]) {
	put(b, "\xd8\x2a", 2); /* tag 42 */
	head(b, 2, 37);
	put(b, "\0", 1); /* multibase identity prefix */
	put(b, c, 36);
}

static void cid_of(const buf *blk, unsigned char c[36]) {
	memcpy(c, "\x01\x71\x12\x20", 4); /* v1, dag-cbor, sha2-256, 32 bytes */
	SHA256(blk->p, blk->n, c + 4);
}

static void cid_str(const unsigned char c[36], char out[64]) {
	out[0] = 'b';
	b32(c, 36, out + 1);
}

static int cid_parse(const char *s, unsigned char c[36]) {
	return s && s[0] == 'b' && b32dec(s + 1, c, 36) == 36 && c[0] == 1 && c[2] == 0x12 && c[3] == 0x20 ? 0 : -1;
}

static int keycmp(const void *x, const void *y) {
	const char *a = (*(cJSON *const *)x)->string, *b = (*(cJSON *const *)y)->string;
	size_t la = strlen(a), lb = strlen(b);
	return la != lb ? (la < lb ? -1 : 1) : strcmp(a, b);
}

/* JSON → DAG-CBOR per the atproto data model ({"$link"} = CID, {"$bytes"} = bytes). */
static int cbor(buf *b, const cJSON *j) {
	if (cJSON_IsString(j)) {
		text(b, j->valuestring);
	} else if (cJSON_IsNumber(j)) {
		double d = j->valuedouble;
		if (d != floor(d) || fabs(d) > 9007199254740991.0) return -1; /* atproto: no floats */
		long long v = (long long)d;
		if (v >= 0) head(b, 0, (uint64_t)v);
		else head(b, 1, (uint64_t)(-1 - v));
	} else if (cJSON_IsBool(j)) {
		put(b, cJSON_IsTrue(j) ? "\xf5" : "\xf4", 1);
	} else if (cJSON_IsNull(j)) {
		put(b, "\xf6", 1);
	} else if (cJSON_IsArray(j)) {
		head(b, 4, (uint64_t)cJSON_GetArraySize(j));
		for (cJSON *e = j->child; e; e = e->next)
			if (cbor(b, e)) return -1;
	} else if (cJSON_IsObject(j)) {
		int n = cJSON_GetArraySize(j), i = 0;
		cJSON *only = n == 1 ? j->child : NULL;
		if (only && !strcmp(only->string, "$link")) {
			unsigned char c[36];
			if (!cJSON_IsString(only) || cid_parse(only->valuestring, c)) return -1;
			cid_put(b, c);
			return 0;
		}
		if (only && !strcmp(only->string, "$bytes")) {
			if (!cJSON_IsString(only)) return -1;
			size_t sl = strlen(only->valuestring);
			unsigned char *raw = malloc(sl + 1);
			int rl = b64url_dec(only->valuestring, sl, raw);
			if (rl >= 0) head(b, 2, (uint64_t)rl), put(b, raw, (size_t)rl);
			free(raw);
			return rl < 0 ? -1 : 0;
		}
		cJSON **k = malloc(sizeof *k * (n ? n : 1));
		for (cJSON *e = j->child; e; e = e->next) k[i++] = e;
		qsort(k, n, sizeof *k, keycmp);
		int bad = 0;
		head(b, 5, (uint64_t)n);
		for (i = 0; i < n && !bad; i++) {
			if (i && !keycmp(&k[i - 1], &k[i])) bad = 1; /* duplicate key */
			text(b, k[i]->string);
			bad = bad || cbor(b, k[i]);
		}
		free(k);
		return bad ? -1 : 0;
	} else {
		return -1;
	}
	return 0;
}

static int record_cid(const cJSON *rec, char out[64]) {
	buf b = {0};
	unsigned char c[36];
	int rc = cbor(&b, rec);
	if (!rc) cid_of(&b, c), cid_str(c, out);
	free(b.p);
	return rc;
}

/* ---------- signing keys (secp256k1) ---------- */

static char *new_key_pem(void) {
	EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "secp256k1");
	BIO *b = BIO_new(BIO_s_mem());
	char *p, *pem = NULL;
	if (k && PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL)) {
		long n = BIO_get_mem_data(b, &p);
		pem = strndup(p, (size_t)n);
	}
	BIO_free(b);
	EVP_PKEY_free(k);
	return pem;
}

static EVP_PKEY *load_key(const char *pem) {
	BIO *b = BIO_new_mem_buf(pem, -1);
	EVP_PKEY *k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
	BIO_free(b);
	return k;
}

static void b58(const unsigned char *in, size_t n, char *out) {
	static const char a[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	unsigned char d[128] = {0}; /* base-58 digits, little endian */
	size_t len = 0, o = 0;
	for (size_t i = 0; i < n && !in[i]; i++) out[o++] = '1';
	for (size_t i = 0; i < n; i++) {
		int carry = in[i];
		for (size_t j = 0; j < len; j++, carry /= 58) d[j] = (unsigned char)((carry += d[j] << 8) % 58);
		for (; carry; carry /= 58) d[len++] = (unsigned char)(carry % 58);
	}
	while (len) out[o++] = a[d[--len]];
	out[o] = 0;
}

/* Multikey form of the compressed public key: "zQ3s…". */
static int pub_multikey(EVP_PKEY *k, char out[64]) {
	unsigned char pub[65], mk[35] = {0xe7, 0x01}; /* multicodec secp256k1-pub */
	size_t n;
	if (!EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, sizeof pub, &n)) return -1;
	if (n == 65) mk[2] = 2 | (pub[64] & 1), memcpy(mk + 3, pub + 1, 32);
	else if (n == 33) memcpy(mk + 2, pub, 33);
	else return -1;
	out[0] = 'z';
	b58(mk, sizeof mk, out + 1);
	return 0;
}

/* ECDSA-SHA256 as compact r||s with low-S, as atproto requires. */
static int sign(EVP_PKEY *k, const buf *msg, unsigned char sig[64]) {
	unsigned char der[80];
	size_t dl = sizeof der;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int ok = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, k) == 1 && EVP_DigestSign(ctx, der, &dl, msg->p, msg->n) == 1;
	EVP_MD_CTX_free(ctx);
	const unsigned char *p = der;
	ECDSA_SIG *es = ok ? d2i_ECDSA_SIG(NULL, &p, (long)dl) : NULL;
	if (!es) return -1;
	const BIGNUM *r, *s;
	ECDSA_SIG_get0(es, &r, &s);
	BIGNUM *order = NULL, *half = BN_new(), *low = BN_dup(s);
	BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
	BN_rshift1(half, order);
	if (BN_cmp(low, half) > 0) BN_sub(low, order, low);
	BN_bn2binpad(r, sig, 32);
	BN_bn2binpad(low, sig + 32, 32);
	BN_free(order), BN_free(half), BN_free(low), ECDSA_SIG_free(es);
	return 0;
}

/* ---------- JWT (HS256) ---------- */

static void make_jwt(const char *did, const char *scope, const char *typ, long ttl, char out[1024]) {
	char hdr[64], payload[512], h64[128], p64[700];
	unsigned char sig[32];
	unsigned int siglen;
	long now = (long)time(NULL);
	snprintf(hdr, sizeof hdr, "{\"alg\":\"HS256\",\"typ\":\"%s\"}", typ);
	snprintf(payload, sizeof payload, "{\"scope\":\"%s\",\"sub\":\"%s\",\"aud\":\"%s\",\"iat\":%ld,\"exp\":%ld}",
	         scope, did, service_did, now, now + ttl);
	b64url((unsigned char *)hdr, strlen(hdr), h64);
	b64url((unsigned char *)payload, strlen(payload), p64);
	int n = snprintf(out, 1024, "%s.%s", h64, p64);
	HMAC(EVP_sha256(), jwt_secret, sizeof jwt_secret, (unsigned char *)out, n, sig, &siglen);
	out[n++] = '.';
	b64url(sig, siglen, out + n);
}

/* Checks bearer token signature, expiry and scope; writes subject DID. */
static int verify_jwt(const char *tok, const char *scope, char did[64]) {
	const char *d1 = strchr(tok, '.'), *d2 = d1 ? strchr(d1 + 1, '.') : NULL;
	if (!d2 || strlen(d2 + 1) != 43) return -1;
	unsigned char sig[32], payload[3100];
	unsigned int siglen;
	char want[64];
	HMAC(EVP_sha256(), jwt_secret, sizeof jwt_secret, (const unsigned char *)tok, d2 - tok, sig, &siglen);
	b64url(sig, siglen, want);
	if (CRYPTO_memcmp(want, d2 + 1, 43)) return -1;
	int n = b64url_dec(d1 + 1, d2 - d1 - 1, payload);
	if (n < 0) return -1;
	cJSON *p = cJSON_ParseWithLength((char *)payload, n);
	cJSON *sc = cJSON_GetObjectItemCaseSensitive(p, "scope"), *sub = cJSON_GetObjectItemCaseSensitive(p, "sub"),
	      *exp = cJSON_GetObjectItemCaseSensitive(p, "exp");
	int ok = cJSON_IsString(sc) && !strcmp(sc->valuestring, scope) && cJSON_IsString(sub) &&
	         strlen(sub->valuestring) < 64 && cJSON_IsNumber(exp) && exp->valuedouble > (double)time(NULL);
	if (ok) strcpy(did, sub->valuestring);
	cJSON_Delete(p);
	return ok ? 0 : -1;
}

/* ---------- storage ---------- */

static sqlite3_stmt *q(const char *sql, int n, ...) {
	sqlite3_stmt *s;
	if (sqlite3_prepare_v2(db, sql, -1, &s, NULL)) {
		fprintf(stderr, "sql error: %s\n", sqlite3_errmsg(db));
		exit(1);
	}
	va_list ap;
	va_start(ap, n);
	for (int i = 1; i <= n; i++) sqlite3_bind_text(s, i, va_arg(ap, const char *), -1, SQLITE_TRANSIENT);
	va_end(ap);
	return s;
}

static int exec1(sqlite3_stmt *s) {
	int rc = sqlite3_step(s);
	sqlite3_finalize(s);
	return rc == SQLITE_DONE ? 0 : -1;
}

typedef struct { char did[64], handle[256], email[256], salt[33], hash[65], pubkey[64], head[64], rev[16]; } account;

/* ident may be a DID or handle; with_email also matches email. */
static int find_account(const char *ident, int with_email, account *a) {
	if (!ident) return -1;
	sqlite3_stmt *s = q(with_email ? "SELECT did,handle,ifnull(email,''),salt,hash,pubkey,ifnull(head,''),ifnull(rev,'') FROM account "
	                                 "WHERE did=?1 OR handle=lower(?1) OR lower(email)=lower(?1)"
	                               : "SELECT did,handle,ifnull(email,''),salt,hash,pubkey,ifnull(head,''),ifnull(rev,'') FROM account "
	                                 "WHERE did=?1 OR handle=lower(?1)",
	                    1, ident);
	int found = sqlite3_step(s) == SQLITE_ROW;
	if (found) {
		snprintf(a->did, sizeof a->did, "%s", sqlite3_column_text(s, 0));
		snprintf(a->handle, sizeof a->handle, "%s", sqlite3_column_text(s, 1));
		snprintf(a->email, sizeof a->email, "%s", sqlite3_column_text(s, 2));
		snprintf(a->salt, sizeof a->salt, "%s", sqlite3_column_text(s, 3));
		snprintf(a->hash, sizeof a->hash, "%s", sqlite3_column_text(s, 4));
		snprintf(a->pubkey, sizeof a->pubkey, "%s", sqlite3_column_text(s, 5));
		snprintf(a->head, sizeof a->head, "%s", sqlite3_column_text(s, 6));
		snprintf(a->rev, sizeof a->rev, "%s", sqlite3_column_text(s, 7));
	}
	sqlite3_finalize(s);
	return found ? 0 : -1;
}

static void hash_pw(const char *pw, const char *salt, char out[65]) {
	unsigned char h[32];
	PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), (const unsigned char *)salt, (int)strlen(salt), 100000, EVP_sha256(),
	                  sizeof h, h);
	hex(h, sizeof h, out);
}

/* ---------- repo: MST + signed commits ---------- */

typedef struct { char *key; unsigned char cid[36]; int layer; } leaf;

/* MST layer = leading zero bits of sha256(key) / 2 (fanout 4). */
static int key_layer(const char *k) {
	unsigned char h[32];
	int z = 0;
	SHA256((const unsigned char *)k, strlen(k), h);
	for (int i = 0; i < 32; i++) {
		if (h[i]) {
			z += __builtin_clz(h[i]) - 24;
			break;
		}
		z += 8;
	}
	return z / 2;
}

static void varint(buf *b, uint64_t v) {
	do {
		unsigned char c = (v & 0x7f) | (v > 0x7f ? 0x80 : 0);
		put(b, &c, 1);
	} while (v >>= 7);
}

/* Hashes a block; also appends it to car (CAR v1 framing) when given. */
static void emit(buf *car, const buf *blk, unsigned char cid[36]) {
	cid_of(blk, cid);
	if (!car) return;
	varint(car, 36 + blk->n);
	put(car, cid, 36);
	put(car, blk->p, blk->n);
}

/* Blocks go to car; with a key, only nodes on that key's search path (a proof). */
typedef struct { const leaf *L; size_t n; buf *car; const char *key; } mst_ctx;

/* Node at `layer` over sorted leaves [lo,hi), all with layer <= `layer`.
 * Leaves of this layer are entries; runs of lower ones become subtrees. */
static void mst_node(const mst_ctx *x, size_t lo, size_t hi, int layer, unsigned char cid[36]) {
	const leaf *L = x->L;
	buf b = {0};
	unsigned char sub[36], left[36];
	size_t n = 0, i = lo;
	for (size_t k = lo; k < hi; k++) n += L[k].layer == layer;
	while (i < hi && L[i].layer != layer) i++;
	int has_left = i > lo;
	if (has_left) mst_node(x, lo, i, layer - 1, left);
	head(&b, 5, 2);
	text(&b, "e");
	head(&b, 4, n);
	for (const char *prev = ""; i < hi;) {
		size_t j = i + 1, p = 0;
		while (j < hi && L[j].layer != layer) j++;
		while (prev[p] && prev[p] == L[i].key[p]) p++;
		head(&b, 5, 4);
		text(&b, "k"), head(&b, 2, strlen(L[i].key + p)), put(&b, L[i].key + p, strlen(L[i].key + p));
		text(&b, "p"), head(&b, 0, p);
		text(&b, "t");
		if (j > i + 1) mst_node(x, i + 1, j, layer - 1, sub), cid_put(&b, sub);
		else put(&b, "\xf6", 1);
		text(&b, "v"), cid_put(&b, L[i].cid);
		prev = L[i].key, i = j;
	}
	text(&b, "l");
	if (has_left) cid_put(&b, left);
	else put(&b, "\xf6", 1);
	/* inclusive bounds: when the key is present, also take the spines of its
	 * neighbouring subtrees, which deleting it would merge */
	int on_path = !x->key || ((lo == 0 || strcmp(L[lo - 1].key, x->key) <= 0) &&
	                          (hi == x->n || strcmp(x->key, L[hi].key) <= 0));
	emit(on_path ? x->car : NULL, &b, cid);
	free(b.p);
}

/* ponytail: rebuilds the whole MST from the record table on every write and
 * export, O(records). Persist nodes and update incrementally if repos get big. */
static void mst_root(const char *did, buf *car, const char *key, unsigned char root[36]) {
	sqlite3_stmt *s = q("SELECT collection||'/'||rkey, cid FROM record WHERE did=? ORDER BY 1", 1, did);
	leaf *L = NULL;
	size_t n = 0, cap = 0;
	int top = 0;
	while (sqlite3_step(s) == SQLITE_ROW) {
		if (n == cap) L = realloc(L, sizeof *L * (cap = cap * 2 + 64));
		L[n].key = strdup((const char *)sqlite3_column_text(s, 0));
		cid_parse((const char *)sqlite3_column_text(s, 1), L[n].cid);
		if ((L[n].layer = key_layer(L[n].key)) > top) top = L[n].layer;
		n++;
	}
	sqlite3_finalize(s);
	mst_ctx x = {L, n, car, key};
	mst_node(&x, 0, n, top, root);
	while (n) free(L[--n].key);
	free(L);
}

static void commit_cbor(buf *b, const char *did, const char *rev, const unsigned char data[36], const unsigned char *sig) {
	head(b, 5, sig ? 6 : 5); /* keys in dag-cbor order: length, then bytes */
	text(b, "did"), text(b, did);
	text(b, "rev"), text(b, rev);
	if (sig) text(b, "sig"), head(b, 2, 64), put(b, sig, 64);
	text(b, "data"), cid_put(b, data);
	text(b, "prev"), put(b, "\xf6", 1);
	text(b, "version"), head(b, 0, 3);
}

/* Signs a commit over the repo's current records and makes it the head.
 * Call inside the transaction that changed the records. */
/* Also appends the new MST nodes and the commit block to `blocks` if given. */
static int new_commit(const char *did, buf *blocks, char cid_out[64], char rev[14]) {
	unsigned char root[36], sig[64], cid[36];
	buf u = {0}, sgn = {0};
	sqlite3_stmt *s = q("SELECT key FROM account WHERE did=?", 1, did);
	EVP_PKEY *k = sqlite3_step(s) == SQLITE_ROW ? load_key((const char *)sqlite3_column_text(s, 0)) : NULL;
	sqlite3_finalize(s);
	mst_root(did, blocks, NULL, root);
	tid(rev);
	commit_cbor(&u, did, rev, root, NULL);
	int rc = !k || sign(k, &u, sig) ? -1 : 0;
	if (!rc) {
		commit_cbor(&sgn, did, rev, root, sig);
		emit(blocks, &sgn, cid);
		cid_str(cid, cid_out);
		s = q("UPDATE account SET head=?, rev=?, head_block=?3 WHERE did=?4", 2, cid_out, rev);
		sqlite3_bind_blob(s, 3, sgn.p, (int)sgn.n, SQLITE_TRANSIENT);
		sqlite3_bind_text(s, 4, did, -1, SQLITE_TRANSIENT);
		rc = exec1(s);
	}
	EVP_PKEY_free(k);
	free(u.p), free(sgn.p);
	return rc;
}

/* ---------- firehose (com.atproto.sync.subscribeRepos) ---------- */

static void car_header(buf *car, const unsigned char root[36]) {
	buf h = {0};
	head(&h, 5, 2);
	text(&h, "roots"), head(&h, 4, 1), cid_put(&h, root);
	text(&h, "version"), head(&h, 0, 1);
	varint(car, h.n);
	put(car, h.p, h.n);
	free(h.p);
}

static int cid_cmp(const void *a, const void *b) { return memcmp(a, b, 36); }

/* Appends to `to` every CAR-framed block of `from` whose CID isn't in `old`. */
static void car_diff(buf *to, const buf *from, const buf *old) {
	unsigned char *seen = NULL;
	size_t n = 0;
	for (int pass = 0; pass < 2; pass++) {
		const buf *src = pass ? from : old;
		for (size_t i = 0; i < src->n;) {
			uint64_t len = 0;
			for (int sh = 0;; sh += 7) {
				unsigned char c = src->p[i++];
				len |= (uint64_t)(c & 0x7f) << sh;
				if (!(c & 0x80)) break;
			}
			const unsigned char *cid = src->p + i;
			if (!pass) {
				seen = realloc(seen, 36 * (n + 1));
				memcpy(seen + 36 * n++, cid, 36);
			} else if (!bsearch(cid, seen, n, 36, cid_cmp)) {
				varint(to, len);
				put(to, cid, len);
			}
			i += len;
		}
		if (!pass) qsort(seen, n, 36, cid_cmp);
	}
	free(seen);
}

static void now_iso(char out[32]) {
	struct timespec ts;
	struct tm tm;
	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm);
	size_t n = strftime(out, 32, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(out + n, 32 - n, ".%03ldZ", ts.tv_nsec / 1000000);
}

/* Event frames are stored whole (header + body) under their seq. */
static long long event_begin(const char *did, buf *f, const char *type) {
	if (exec1(q("INSERT INTO event(did) VALUES(?)", 1, did))) return -1;
	head(f, 5, 2);
	text(f, "t"), text(f, type);
	text(f, "op"), head(f, 0, 1);
	return sqlite3_last_insert_rowid(db);
}

static int event_end(long long seq, buf *f) {
	sqlite3_stmt *s = q("UPDATE event SET frame=?1 WHERE seq=?2", 0);
	sqlite3_bind_blob(s, 1, f->p, (int)f->n, SQLITE_TRANSIENT);
	sqlite3_bind_int64(s, 2, seq);
	free(f->p);
	return exec1(s);
}

typedef struct { const char *action, *path; const unsigned char *cid, *prev; } repo_op;

/* #commit: blocks are the CAR-framed diff (commit, new MST nodes, new records). */
static int commit_event(const char *did, const char *since, const unsigned char *prev_data, const char *ccid,
                        const char *rev, const buf *blocks, const repo_op *ops, int nops) {
	buf f = {0}, car = {0};
	unsigned char cc[36];
	char t[32];
	long long seq = event_begin(did, &f, "#commit");
	if (seq < 0) return -1;
	cid_parse(ccid, cc);
	car_header(&car, cc);
	put(&car, blocks->p, blocks->n);
	now_iso(t);
	head(&f, 5, prev_data ? 12 : 11); /* keys in dag-cbor order: length, then bytes */
	text(&f, "ops"), head(&f, 4, (uint64_t)nops);
	for (int i = 0; i < nops; i++) {
		head(&f, 5, ops[i].prev ? 4 : 3);
		text(&f, "cid");
		if (ops[i].cid) cid_put(&f, ops[i].cid);
		else put(&f, "\xf6", 1);
		text(&f, "path"), text(&f, ops[i].path);
		if (ops[i].prev) text(&f, "prev"), cid_put(&f, ops[i].prev);
		text(&f, "action"), text(&f, ops[i].action);
	}
	text(&f, "rev"), text(&f, rev);
	text(&f, "seq"), head(&f, 0, (uint64_t)seq);
	text(&f, "repo"), text(&f, did);
	text(&f, "time"), text(&f, t);
	text(&f, "blobs"), head(&f, 4, 0);
	text(&f, "since");
	if (since && *since) text(&f, since);
	else put(&f, "\xf6", 1);
	text(&f, "blocks"), head(&f, 2, car.n), put(&f, car.p, car.n);
	text(&f, "commit"), cid_put(&f, cc);
	text(&f, "rebase"), put(&f, "\xf4", 1);
	text(&f, "tooBig"), put(&f, "\xf4", 1);
	if (prev_data) text(&f, "prevData"), cid_put(&f, prev_data);
	free(car.p);
	return event_end(seq, &f);
}

/* #identity then #account (when announcing a new account) or #identity alone. */
static int account_events(const char *did, const char *handle, int with_account) {
	char t[32];
	now_iso(t);
	for (int i = 0; i < 1 + with_account; i++) {
		buf f = {0};
		long long seq = event_begin(did, &f, i ? "#account" : "#identity");
		if (seq < 0) return -1;
		head(&f, 5, 4);
		text(&f, "did"), text(&f, did);
		text(&f, "seq"), head(&f, 0, (uint64_t)seq);
		text(&f, "time"), text(&f, t);
		if (i) text(&f, "active"), put(&f, "\xf5", 1);
		else text(&f, "handle"), text(&f, handle);
		if (event_end(seq, &f)) return -1;
	}
	return 0;
}

#define MAX_SUBS 256
static struct { MHD_socket fd; struct MHD_UpgradeResponseHandle *urh; } subs[MAX_SUBS];
static int nsubs;
static long long sent_seq; /* highest seq pushed to live subscribers */

static int send_all(MHD_socket fd, const void *p, size_t n) {
	for (ssize_t w; n; p = (const char *)p + w, n -= (size_t)w)
		if ((w = send(fd, p, n, 0)) <= 0) return -1;
	return 0;
}

static int ws_send(MHD_socket fd, const void *p, size_t n) {
	unsigned char h[10] = {0x82}; /* FIN + binary */
	size_t hl = 2;
	if (n < 126) h[1] = (unsigned char)n;
	else if (n < 65536) h[1] = 126, h[2] = (unsigned char)(n >> 8), h[3] = (unsigned char)n, hl = 4;
	else {
		h[1] = 127, hl = 10;
		for (int i = 0; i < 8; i++) h[2 + i] = (unsigned char)((uint64_t)n >> (56 - 8 * i));
	}
	return send_all(fd, h, hl) || send_all(fd, p, n);
}

/* Pushes events committed since the last call to every subscriber. */
static void broadcast(void) {
	sqlite3_stmt *s = q("SELECT seq, frame FROM event WHERE seq>?1 ORDER BY seq", 0);
	sqlite3_bind_int64(s, 1, sent_seq);
	while (sqlite3_step(s) == SQLITE_ROW) {
		sent_seq = sqlite3_column_int64(s, 0);
		for (int i = 0; i < nsubs; i++)
			if (ws_send(subs[i].fd, sqlite3_column_blob(s, 1), (size_t)sqlite3_column_bytes(s, 1))) {
				MHD_upgrade_action(subs[i].urh, MHD_UPGRADE_ACTION_CLOSE);
				subs[i--] = subs[--nsubs];
			}
	}
	sqlite3_finalize(s);
}

/* ponytail: sends are blocking with a 5s timeout on the single server thread,
 * so one stuck subscriber can stall everyone briefly, and incoming frames
 * (ping/close) are never read. Move to per-subscriber queues + poll if needed. */
static void subscribe(long long cursor, MHD_socket fd, struct MHD_UpgradeResponseHandle *urh) {
	struct timeval tv = {5, 0};
	int one = 1;
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
	if (nsubs == MAX_SUBS) {
		MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
		return;
	}
	if (cursor > sent_seq) {
		buf f = {0};
		head(&f, 5, 1), text(&f, "op"), head(&f, 1, 0); /* op: -1 */
		head(&f, 5, 2), text(&f, "error"), text(&f, "FutureCursor");
		text(&f, "message"), text(&f, "cursor is ahead of the stream");
		ws_send(fd, f.p, f.n);
		free(f.p);
		MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
		return;
	}
	if (cursor >= 0) { /* backfill; events are kept forever */
		sqlite3_stmt *s = q("SELECT frame FROM event WHERE seq>?1 AND seq<=?2 ORDER BY seq", 0);
		sqlite3_bind_int64(s, 1, cursor);
		sqlite3_bind_int64(s, 2, sent_seq);
		int bad = 0;
		while (!bad && sqlite3_step(s) == SQLITE_ROW)
			bad = ws_send(fd, sqlite3_column_blob(s, 0), (size_t)sqlite3_column_bytes(s, 0));
		sqlite3_finalize(s);
		if (bad) {
			MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);
			return;
		}
	}
	subs[nsubs].fd = fd;
	subs[nsubs++].urh = urh;
}

static void on_upgrade(void *cls, struct MHD_Connection *c, void *req_cls, const char *extra, size_t extra_n,
                       MHD_socket fd, struct MHD_UpgradeResponseHandle *urh) {
	(void)c, (void)req_cls, (void)extra, (void)extra_n;
	pthread_mutex_lock(&big);
	subscribe((long long)(intptr_t)cls - 1, fd, urh);
	pthread_mutex_unlock(&big);
}

/* ---------- outbound: PLC directory, relays ---------- */

static size_t collect(char *p, size_t size, size_t n, void *u) {
	if (u) put(u, p, size * n);
	return size * n;
}

/* POSTs when body is non-NULL. Returns the HTTP status, 0 if unreachable. */
static long http(const char *url, struct curl_slist *hdrs, const void *body, size_t n, buf *out, char ctype[128]) {
	CURL *c = curl_easy_init();
	long code = 0;
	char *ct = NULL;
	if (!c) return 0;
	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
	curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, collect);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, out);
	if (body) {
		curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
		curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)n);
	}
	if (curl_easy_perform(c) == CURLE_OK) {
		curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
		curl_easy_getinfo(c, CURLINFO_CONTENT_TYPE, &ct);
		if (ctype) snprintf(ctype, 128, "%s", ct ? ct : "application/octet-stream");
	}
	curl_easy_cleanup(c);
	return code;
}

/* ponytail: synchronous, holding the global lock (30s timeout). Fine for
 * account creation and startup; queue it if outbound calls become frequent. */
static int post_json(const char *url, const char *body) {
	struct curl_slist *h = curl_slist_append(NULL, "Content-Type: application/json");
	long code = http(url, h, body, strlen(body), NULL, NULL);
	curl_slist_free_all(h);
	if (code / 100 == 2) return 0;
	fprintf(stderr, "POST %s failed (HTTP %ld)\n", url, code);
	return -1;
}

/* Signed PLC op as JSON. With prev NULL it is the genesis op and the DID is
 * derived from its hash; otherwise it updates the DID whose last op is prev.
 * ponytail: the account key doubles as the PLC rotation key, and handle
 * changes are never sent to PLC. Add a PDS rotation key + update ops later. */
static char *plc_op(EVP_PKEY *k, const char *pubkey, const char *handle, const char *prev, char did[64]) {
	char key[80], aka[300], sig64[100], h32[64];
	unsigned char sig[64], h[32];
	snprintf(key, sizeof key, "did:key:%s", pubkey);
	snprintf(aka, sizeof aka, "at://%s", handle);
	cJSON *op = cJSON_CreateObject(), *vm = cJSON_CreateObject(), *svcs = cJSON_CreateObject(),
	      *pds = cJSON_CreateObject();
	cJSON_AddStringToObject(op, "type", "plc_operation");
	cJSON_AddItemToObject(op, "rotationKeys", cJSON_CreateStringArray((const char *[]){key}, 1));
	cJSON_AddStringToObject(vm, "atproto", key);
	cJSON_AddItemToObject(op, "verificationMethods", vm);
	cJSON_AddItemToObject(op, "alsoKnownAs", cJSON_CreateStringArray((const char *[]){aka}, 1));
	cJSON_AddStringToObject(pds, "type", "AtprotoPersonalDataServer");
	cJSON_AddStringToObject(pds, "endpoint", endpoint);
	cJSON_AddItemToObject(svcs, "atproto_pds", pds);
	cJSON_AddItemToObject(op, "services", svcs);
	if (prev) cJSON_AddStringToObject(op, "prev", prev);
	else cJSON_AddNullToObject(op, "prev");
	buf b = {0};
	char *json = NULL;
	if (!cbor(&b, op) && !sign(k, &b, sig)) {
		b64url(sig, sizeof sig, sig64);
		cJSON_AddStringToObject(op, "sig", sig64);
		if (!prev) {
			b.n = 0;
			cbor(&b, op);
			SHA256(b.p, b.n, h);
			b32(h, sizeof h, h32);
			snprintf(did, 64, "did:plc:%.24s", h32);
		}
		json = cJSON_PrintUnformatted(op);
	}
	free(b.p);
	cJSON_Delete(op);
	return json;
}

/* Asks the relay to start crawling (it then subscribes to our firehose). */
static void request_crawl(void) {
	char url[512], body[300];
	if (!crawler) return;
	snprintf(url, sizeof url, "%s/xrpc/com.atproto.sync.requestCrawl", crawler);
	snprintf(body, sizeof body, "{\"hostname\":\"%s\"}", hostname);
	post_json(url, body);
}

/* ---------- validation ---------- */

static int valid_nsid(const char *s) {
	size_t n = strlen(s);
	int dots = 0;
	if (n < 5 || n > 317 || s[0] == '.' || s[n - 1] == '.') return 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] == '.') {
			if (s[i + 1] == '.') return 0;
			dots++;
		} else if (!isalnum((unsigned char)s[i]) && s[i] != '-') {
			return 0;
		}
	}
	return dots >= 2;
}

static int valid_rkey(const char *s) {
	size_t n = strlen(s);
	if (n < 1 || n > 512 || !strcmp(s, ".") || !strcmp(s, "..")) return 0;
	for (; *s; s++)
		if (!isalnum((unsigned char)*s) && !strchr("._:~-", *s)) return 0;
	return 1;
}

/* Handles are "<label>.<hostname>"; label is 1-63 of [a-z0-9-], no edge hyphens. */
static int valid_handle(const char *h) {
	const char *dot = strchr(h, '.');
	size_t n = dot ? (size_t)(dot - h) : 0;
	if (!n || n > 63 || h[0] == '-' || h[n - 1] == '-' || strcmp(dot + 1, hostname)) return 0;
	for (size_t i = 0; i < n; i++)
		if (!islower((unsigned char)h[i]) && !isdigit((unsigned char)h[i]) && h[i] != '-') return 0;
	return 1;
}

/* ---------- HTTP plumbing ---------- */

typedef enum MHD_Result res;

/* Takes ownership of body (malloc'd). */
static res send_raw(struct MHD_Connection *c, unsigned st, const char *type, void *body, size_t n) {
	struct MHD_Response *r = MHD_create_response_from_buffer(n, body, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(r, "Content-Type", type);
	MHD_add_response_header(r, "Access-Control-Allow-Origin", "*");
	MHD_add_response_header(r, "Access-Control-Allow-Headers", "*");
	MHD_add_response_header(r, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
	/* blobs are user-supplied bytes: never let a browser run them as a page */
	MHD_add_response_header(r, "X-Content-Type-Options", "nosniff");
	MHD_add_response_header(r, "Content-Security-Policy", "default-src 'none'; sandbox");
	res ret = MHD_queue_response(c, st, r);
	MHD_destroy_response(r);
	return ret;
}

static res send_body(struct MHD_Connection *c, unsigned st, const char *type, char *body) {
	return send_raw(c, st, type, body, strlen(body));
}

static res reply(struct MHD_Connection *c, unsigned st, cJSON *o) {
	char *s = cJSON_PrintUnformatted(o);
	cJSON_Delete(o);
	return send_body(c, st, "application/json", s);
}

static res err(struct MHD_Connection *c, unsigned st, const char *name, const char *msg) {
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "error", name);
	cJSON_AddStringToObject(o, "message", msg);
	return reply(c, st, o);
}

#define ARG(name) MHD_lookup_connection_value(c, MHD_GET_ARGUMENT_KIND, name)

static const char *str(const cJSON *o, const char *k) {
	cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
	return cJSON_IsString(v) ? v->valuestring : NULL;
}

static int auth(struct MHD_Connection *c, const char *scope, char did[64]) {
	const char *h = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Authorization");
	return h && !strncmp(h, "Bearer ", 7) ? verify_jwt(h + 7, scope, did) : -1;
}

static cJSON *did_doc(const account *a);

static res session(struct MHD_Connection *c, const account *a) {
	char at[1024], rt[1024];
	make_jwt(a->did, "com.atproto.access", "at+jwt", ACCESS_TTL, at);
	make_jwt(a->did, "com.atproto.refresh", "refresh+jwt", REFRESH_TTL, rt);
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "accessJwt", at);
	cJSON_AddStringToObject(o, "refreshJwt", rt);
	cJSON_AddStringToObject(o, "handle", a->handle);
	cJSON_AddStringToObject(o, "did", a->did);
	if (*a->email) cJSON_AddStringToObject(o, "email", a->email);
	cJSON_AddItemToObject(o, "didDoc", did_doc(a));
	cJSON_AddBoolToObject(o, "active", 1);
	return reply(c, 200, o);
}

/* ---------- service auth + proxying to other services ---------- */

typedef struct { char *p; size_t n; int too_big; } body;

/* ES256K JWT signed with the user's repo key, proving the user to `aud`. */
static int service_jwt(const char *did, const char *aud, const char *lxm, long ttl, char out[2048]) {
	sqlite3_stmt *s = q("SELECT key FROM account WHERE did=?", 1, did);
	EVP_PKEY *k = sqlite3_step(s) == SQLITE_ROW ? load_key((const char *)sqlite3_column_text(s, 0)) : NULL;
	sqlite3_finalize(s);
	if (!k) return -1;
	unsigned char rnd[16], sig[64];
	char jti[33];
	long now = (long)time(NULL);
	RAND_bytes(rnd, sizeof rnd);
	hex(rnd, sizeof rnd, jti);
	cJSON *p = cJSON_CreateObject();
	cJSON_AddNumberToObject(p, "iat", (double)now);
	cJSON_AddStringToObject(p, "iss", did);
	cJSON_AddStringToObject(p, "aud", aud);
	cJSON_AddNumberToObject(p, "exp", (double)(now + ttl));
	if (lxm) cJSON_AddStringToObject(p, "lxm", lxm);
	cJSON_AddStringToObject(p, "jti", jti);
	char *pj = cJSON_PrintUnformatted(p);
	cJSON_Delete(p);
	const char *hj = "{\"typ\":\"JWT\",\"alg\":\"ES256K\"}";
	int rc = strlen(pj) > 1000 ? -1 : 0;
	if (!rc) {
		b64url((const unsigned char *)hj, strlen(hj), out);
		size_t n = strlen(out);
		out[n++] = '.';
		b64url((const unsigned char *)pj, strlen(pj), out + n);
		buf m = {(unsigned char *)out, strlen(out), 0};
		rc = sign(k, &m, sig);
		n = strlen(out);
		out[n++] = '.';
		b64url(sig, sizeof sig, out + n);
	}
	free(pj);
	EVP_PKEY_free(k);
	return rc;
}

static struct { char ref[256], url[512]; } svc_cache[16];
static int nsvc;

/* "did:web:host#id" → that service's endpoint from host's did.json.
 * ponytail: did:web only, cached in memory forever. */
static int resolve_service(const char *ref, char aud[256], char url[512]) {
	const char *frag = strchr(ref, '#');
	if (!frag || strncmp(ref, "did:web:", 8) || strlen(ref) >= 256) return -1;
	snprintf(aud, 256, "%.*s", (int)(frag - ref), ref);
	for (int i = 0; i < nsvc; i++)
		if (!strcmp(svc_cache[i].ref, ref)) return snprintf(url, 512, "%s", svc_cache[i].url), 0;
	char host[256], doc[300], *pc;
	snprintf(host, sizeof host, "%s", aud + 8);
	if ((pc = strstr(host, "%3A")) || (pc = strstr(host, "%3a"))) *pc = ':', memmove(pc + 1, pc + 3, strlen(pc + 3) + 1);
	if (strpbrk(host, "/%?#@")) return -1;
	int dev = !strcmp(host, "localhost") || !strncmp(host, "localhost:", 10);
	snprintf(doc, sizeof doc, "%s://%s/.well-known/did.json", dev ? "http" : "https", host);
	buf r = {0};
	long code = http(doc, NULL, NULL, 0, &r, NULL);
	put(&r, "", 1);
	cJSON *d = code == 200 ? cJSON_Parse((char *)r.p) : NULL, *svc;
	free(r.p);
	int rc = -1;
	size_t al = strlen(aud);
	cJSON_ArrayForEach(svc, cJSON_GetObjectItemCaseSensitive(d, "service")) {
		const char *id = str(svc, "id"), *ep = str(svc, "serviceEndpoint");
		if (id && ep && (!strcmp(id, frag) || (!strncmp(id, aud, al) && !strcmp(id + al, frag)))) {
			snprintf(url, 512, "%s", ep);
			rc = 0;
			break;
		}
	}
	cJSON_Delete(d);
	if (!rc && nsvc < 16) {
		snprintf(svc_cache[nsvc].ref, sizeof svc_cache[nsvc].ref, "%s", ref);
		snprintf(svc_cache[nsvc++].url, sizeof svc_cache[0].url, "%s", url);
	}
	return rc;
}

static enum MHD_Result add_arg(void *cls, enum MHD_ValueKind kind, const char *k, const char *v) {
	(void)kind;
	buf *b = cls;
	char *ek = curl_easy_escape(NULL, k, 0), *ev = v ? curl_easy_escape(NULL, v, 0) : NULL;
	put(b, memchr(b->p, '?', b->n) ? "&" : "?", 1);
	put(b, ek, strlen(ek));
	if (ev) put(b, "=", 1), put(b, ev, strlen(ev));
	curl_free(ek), curl_free(ev);
	return MHD_YES;
}

/* Forwards an XRPC call to the AppView, or to the service named by the
 * atproto-proxy header, authenticated as the user with a service JWT.
 * Runs without the global lock except for key/cache access. */
static res proxy(struct MHD_Connection *c, const char *method, const char *nsid, const body *bd) {
	const char *target = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "atproto-proxy"),
	           *authz = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Authorization");
	char did[64], aud[256], base[512], tok[2048], line[2200], ctype[128];
	/* resolving arbitrary did:web hosts is only for signed-in users */
	if ((authz || target) && auth(c, "com.atproto.access", did))
		return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	pthread_mutex_lock(&big);
	int rc = target ? resolve_service(target, aud, base)
	                : (snprintf(aud, sizeof aud, "%s", appview_did), snprintf(base, sizeof base, "%s", appview_url), 0);
	if (!rc && authz && service_jwt(did, aud, nsid, 60, tok)) rc = -2;
	pthread_mutex_unlock(&big);
	if (rc == -1) return err(c, 400, "InvalidRequest", "could not resolve atproto-proxy service");
	if (rc) return err(c, 500, "InternalServerError", "could not sign service token");

	buf u = {0}, out = {0};
	put(&u, base, strlen(base)), put(&u, "/xrpc/", 6), put(&u, nsid, strlen(nsid));
	MHD_get_connection_values(c, MHD_GET_ARGUMENT_KIND, add_arg, &u);
	put(&u, "", 1);
	struct curl_slist *h = NULL;
	if (authz) snprintf(line, sizeof line, "Authorization: Bearer %s", tok), h = curl_slist_append(h, line);
	const char *fwd[] = {"Content-Type", "Accept-Language", "atproto-accept-labelers"};
	for (int i = 0; i < 3; i++) {
		const char *v = MHD_lookup_connection_value(c, MHD_HEADER_KIND, fwd[i]);
		if (v && strlen(v) < 1000) snprintf(line, sizeof line, "%s: %s", fwd[i], v), h = curl_slist_append(h, line);
	}
	int post = !strcmp(method, "POST");
	long code = http((char *)u.p, h, post ? (bd && bd->n ? bd->p : "") : NULL, post && bd ? bd->n : 0, &out, ctype);
	curl_slist_free_all(h);
	free(u.p);
	if (!code) {
		free(out.p);
		return err(c, 502, "UpstreamFailure", "upstream service unreachable");
	}
	return send_raw(c, (unsigned)code, ctype, out.p ? out.p : malloc(1), out.n);
}

static res get_service_auth(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	char did[64], tok[2048];
	const char *aud = ARG("aud"), *lxm = ARG("lxm"), *exp = ARG("exp");
	if (auth(c, "com.atproto.access", did)) return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	if (!aud || strncmp(aud, "did:", 4) || strlen(aud) > 256 || (lxm && strlen(lxm) > 256))
		return err(c, 400, "InvalidRequest", "aud must be a DID");
	long ttl = exp ? atol(exp) - (long)time(NULL) : 60;
	if (ttl <= 0 || ttl > 3600) return err(c, 400, "BadExpiration", "exp must be within the next hour");
	if (service_jwt(did, aud, lxm, ttl, tok)) return err(c, 500, "InternalServerError", "could not sign token");
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "token", tok);
	return reply(c, 200, o);
}

/* app.bsky.actor preferences live on the PDS, not the AppView. */
static res get_prefs(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	char did[64];
	if (auth(c, "com.atproto.access", did)) return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	sqlite3_stmt *s = q("SELECT prefs FROM pref WHERE did=?", 1, did);
	cJSON *o = cJSON_CreateObject(),
	      *p = sqlite3_step(s) == SQLITE_ROW ? cJSON_Parse((const char *)sqlite3_column_text(s, 0)) : NULL;
	sqlite3_finalize(s);
	cJSON_AddItemToObject(o, "preferences", p ? p : cJSON_CreateArray());
	return reply(c, 200, o);
}

static res put_prefs(struct MHD_Connection *c, cJSON *b) {
	char did[64];
	if (auth(c, "com.atproto.access", did)) return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	cJSON *p = cJSON_GetObjectItemCaseSensitive(b, "preferences");
	if (!cJSON_IsArray(p)) return err(c, 400, "InvalidRequest", "preferences must be an array");
	char *json = cJSON_PrintUnformatted(p);
	int rc = exec1(q("INSERT OR REPLACE INTO pref(did, prefs) VALUES(?,?)", 2, did, json));
	free(json);
	return rc ? err(c, 500, "InternalServerError", "write failed") : send_body(c, 200, "application/json", strdup("{}"));
}

/* ---------- XRPC handlers ---------- */

static res health(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "version", "pds.c 0.1");
	return reply(c, 200, o);
}

static res describe_server(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	char dom[300];
	snprintf(dom, sizeof dom, ".%s", hostname);
	const char *doms[] = {dom};
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "did", service_did);
	cJSON_AddItemToObject(o, "availableUserDomains", cJSON_CreateStringArray(doms, 1));
	cJSON_AddBoolToObject(o, "inviteCodeRequired", 0);
	return reply(c, 200, o);
}

static res create_account(struct MHD_Connection *c, cJSON *b) {
	const char *h = str(b, "handle"), *pw = str(b, "password"), *email = str(b, "email");
	if (!h || !pw || !*pw) return err(c, 400, "InvalidRequest", "handle and password are required");
	char handle[256];
	if (strlen(h) >= sizeof handle) return err(c, 400, "InvalidHandle", "handle too long");
	for (size_t i = 0; (handle[i] = (char)tolower((unsigned char)h[i])); i++);
	if (!valid_handle(handle)) return err(c, 400, "InvalidHandle", "handle must be <name>.<hostname>");
	if (email && (strlen(email) > 254 || !strchr(email, '@')))
		return err(c, 400, "InvalidRequest", "invalid email");
	account a;
	if (!find_account(handle, 0, &a)) return err(c, 400, "HandleNotAvailable", "handle already taken");
	if (email && !find_account(email, 1, &a)) return err(c, 400, "InvalidRequest", "email already taken");

	unsigned char salt[16];
	RAND_bytes(salt, sizeof salt);
	snprintf(a.handle, sizeof a.handle, "%s", handle);
	snprintf(a.email, sizeof a.email, "%s", email ? email : "");
	hex(salt, sizeof salt, a.salt);
	hash_pw(pw, a.salt, a.hash);
	char *pem = new_key_pem();
	EVP_PKEY *k = pem ? load_key(pem) : NULL;
	char *op = k && !pub_multikey(k, a.pubkey) ? plc_op(k, a.pubkey, a.handle, NULL, a.did) : NULL;
	char plc[600];
	EVP_PKEY_free(k);
	snprintf(plc, sizeof plc, "%s/%s", plc_url ? plc_url : "", a.did);
	buf blocks = {0};
	sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
	int rc = !op ||
	         exec1(q("INSERT INTO account(did,handle,email,salt,hash,key,pubkey,plc_op) VALUES(?,?,?,?,?,?,?,?)", 8,
	                 a.did, a.handle, email, a.salt, a.hash, pem, a.pubkey, op)) ||
	         new_commit(a.did, &blocks, a.head, a.rev) || /* empty repo */
	         account_events(a.did, a.handle, 1) ||
	         commit_event(a.did, NULL, NULL, a.head, a.rev, &blocks, NULL, 0) || (plc_url && post_json(plc, op));
	sqlite3_exec(db, rc ? "ROLLBACK" : "COMMIT", NULL, NULL, NULL);
	free(pem), free(op), free(blocks.p);
	broadcast();
	if (rc) return err(c, 500, "InternalServerError", "could not create account");
	request_crawl();
	return session(c, &a);
}

static res create_session(struct MHD_Connection *c, cJSON *b) {
	const char *id = str(b, "identifier"), *pw = str(b, "password");
	account a;
	char h[65];
	if (!id || !pw || find_account(id, 1, &a)) {
		hash_pw("x", "timing", h); /* keep unknown-user path as slow as a real check */
		return err(c, 401, "AuthenticationRequired", "Invalid identifier or password");
	}
	hash_pw(pw, a.salt, h);
	if (CRYPTO_memcmp(h, a.hash, 64)) return err(c, 401, "AuthenticationRequired", "Invalid identifier or password");
	return session(c, &a);
}

static res get_session(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	char did[64];
	account a;
	if (auth(c, "com.atproto.access", did) || find_account(did, 0, &a))
		return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "handle", a.handle);
	cJSON_AddStringToObject(o, "did", a.did);
	if (*a.email) cJSON_AddStringToObject(o, "email", a.email);
	cJSON_AddItemToObject(o, "didDoc", did_doc(&a));
	cJSON_AddBoolToObject(o, "active", 1);
	return reply(c, 200, o);
}

/* ponytail: refresh tokens are stateless, so they can't be revoked before
 * expiry. Add a token table if logout/revocation matters. */
static res refresh_session(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	char did[64];
	account a;
	if (auth(c, "com.atproto.refresh", did) || find_account(did, 0, &a))
		return err(c, 401, "ExpiredToken", "invalid or expired refresh token");
	return session(c, &a);
}

static res delete_session(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	return send_body(c, 200, "application/json", strdup("{}"));
}

static res resolve_handle(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	const char *h = ARG("handle");
	if (!h || strncmp(h, "did:", 4) == 0) return err(c, 400, "InvalidRequest", "handle is required");
	if (find_account(h, 0, &a)) return proxy(c, "GET", "com.atproto.identity.resolveHandle", NULL);
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "did", a.did);
	return reply(c, 200, o);
}

static cJSON *did_doc(const account *a) {
	char aka[300], vmid[80];
	snprintf(aka, sizeof aka, "at://%s", a->handle);
	snprintf(vmid, sizeof vmid, "%s#atproto", a->did);
	const char *ctx[] = {"https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1",
	                     "https://w3id.org/security/suites/secp256k1-2019/v1"};
	cJSON *d = cJSON_CreateObject(), *svc = cJSON_CreateObject(), *arr = cJSON_CreateArray(),
	      *vm = cJSON_CreateObject();
	cJSON_AddItemToObject(d, "@context", cJSON_CreateStringArray(ctx, 3));
	cJSON_AddStringToObject(d, "id", a->did);
	cJSON_AddItemToObject(d, "alsoKnownAs", cJSON_CreateStringArray((const char *[]){aka}, 1));
	cJSON_AddStringToObject(vm, "id", vmid);
	cJSON_AddStringToObject(vm, "type", "Multikey");
	cJSON_AddStringToObject(vm, "controller", a->did);
	cJSON_AddStringToObject(vm, "publicKeyMultibase", a->pubkey);
	cJSON_AddItemToObject(d, "verificationMethod", cJSON_CreateArray());
	cJSON_AddItemToArray(cJSON_GetObjectItem(d, "verificationMethod"), vm);
	cJSON_AddStringToObject(svc, "id", "#atproto_pds");
	cJSON_AddStringToObject(svc, "type", "AtprotoPersonalDataServer");
	cJSON_AddStringToObject(svc, "serviceEndpoint", endpoint);
	cJSON_AddItemToArray(arr, svc);
	cJSON_AddItemToObject(d, "service", arr);
	return d;
}

static int valid_domain(const char *h) {
	size_t n = strlen(h), label = 0;
	int dots = 0, alpha_tld = 0;
	if (n < 3 || n > 253) return 0;
	for (size_t i = 0; i <= n; i++) {
		if (h[i] == '.' || !h[i]) {
			if (!label || label > 63 || h[i - 1] == '-' || h[i - label] == '-') return 0;
			dots += h[i] == '.', label = 0, alpha_tld = 0;
		} else if (islower((unsigned char)h[i]) || isdigit((unsigned char)h[i]) || h[i] == '-') {
			label++, alpha_tld |= islower((unsigned char)h[i]);
		} else {
			return 0;
		}
	}
	return dots && alpha_tld;
}

/* Custom-domain handles must serve our DID at https://<handle>/.well-known/atproto-did.
 * ponytail: the DNS TXT (_atproto.<handle>) method isn't checked; add it with
 * res_query if users want DNS-only handles. */
static int domain_points_to(const char *handle, const char *did) {
	char url[300];
	buf r = {0};
	snprintf(url, sizeof url, "https://%s/.well-known/atproto-did", handle);
	long code = http(url, NULL, NULL, 0, &r, NULL);
	while (r.n && isspace(r.p[r.n - 1])) r.n--;
	int ok = code == 200 && r.n == strlen(did) && !memcmp(r.p, did, r.n);
	free(r.p);
	return ok;
}

static res update_handle(struct MHD_Connection *c, cJSON *b) {
	char did[64], handle[256], prev[64], plc[600];
	account a, other;
	if (auth(c, "com.atproto.access", did) || find_account(did, 0, &a))
		return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	const char *h = str(b, "handle");
	if (!h || strlen(h) >= sizeof handle) return err(c, 400, "InvalidHandle", "handle is required");
	for (size_t i = 0; (handle[i] = (char)tolower((unsigned char)h[i])); i++);
	if (!valid_handle(handle) && !(valid_domain(handle) && domain_points_to(handle, did)))
		return err(c, 400, "InvalidHandle", "handle must be <name>.<hostname> or a domain serving your DID");
	if (!find_account(handle, 0, &other) && strcmp(other.did, did))
		return err(c, 400, "HandleNotAvailable", "handle already taken");

	sqlite3_stmt *s = q("SELECT key, plc_op FROM account WHERE did=?", 1, did);
	sqlite3_step(s);
	EVP_PKEY *k = load_key((const char *)sqlite3_column_text(s, 0));
	cJSON *last = cJSON_Parse((const char *)sqlite3_column_text(s, 1));
	sqlite3_finalize(s);
	buf lb = {0};
	unsigned char lc[36];
	char *op = NULL;
	if (k && last && !cbor(&lb, last)) {
		cid_of(&lb, lc);
		cid_str(lc, prev);
		op = plc_op(k, a.pubkey, handle, prev, a.did);
	}
	EVP_PKEY_free(k), cJSON_Delete(last), free(lb.p);
	snprintf(plc, sizeof plc, "%s/%s", plc_url ? plc_url : "", did);
	sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
	int rc = !op || exec1(q("UPDATE account SET handle=?, plc_op=? WHERE did=?", 3, handle, op, did)) ||
	         account_events(did, handle, 0) || (plc_url && post_json(plc, op));
	sqlite3_exec(db, rc ? "ROLLBACK" : "COMMIT", NULL, NULL, NULL);
	free(op);
	broadcast();
	return rc ? err(c, 500, "InternalServerError", "could not update handle")
	          : send_body(c, 200, "application/json", strdup("{}"));
}

/* The PDS's own did:web document. */
static res service_did_doc(struct MHD_Connection *c) {
	cJSON *d = cJSON_CreateObject(), *svc = cJSON_CreateObject(), *arr = cJSON_CreateArray();
	cJSON_AddItemToObject(d, "@context", cJSON_CreateStringArray((const char *[]){"https://www.w3.org/ns/did/v1"}, 1));
	cJSON_AddStringToObject(d, "id", service_did);
	cJSON_AddStringToObject(svc, "id", "#atproto_pds");
	cJSON_AddStringToObject(svc, "type", "AtprotoPersonalDataServer");
	cJSON_AddStringToObject(svc, "serviceEndpoint", endpoint);
	cJSON_AddItemToArray(arr, svc);
	cJSON_AddItemToObject(d, "service", arr);
	return reply(c, 200, d);
}

static res describe_repo(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	if (find_account(ARG("repo"), 0, &a)) return err(c, 400, "RepoNotFound", "could not find repo");
	cJSON *o = cJSON_CreateObject(), *cols = cJSON_CreateArray();
	cJSON_AddStringToObject(o, "handle", a.handle);
	cJSON_AddStringToObject(o, "did", a.did);
	cJSON_AddItemToObject(o, "didDoc", did_doc(&a));
	sqlite3_stmt *s = q("SELECT DISTINCT collection FROM record WHERE did=? ORDER BY collection", 1, a.did);
	while (sqlite3_step(s) == SQLITE_ROW)
		cJSON_AddItemToArray(cols, cJSON_CreateString((const char *)sqlite3_column_text(s, 0)));
	sqlite3_finalize(s);
	cJSON_AddItemToObject(o, "collections", cols);
	cJSON_AddBoolToObject(o, "handleIsCorrect", 1);
	return reply(c, 200, o);
}

static cJSON *record_view(const char *did, const char *col, const char *rkey, const char *cid, const char *value) {
	char uri[1024];
	snprintf(uri, sizeof uri, "at://%s/%s/%s", did, col, rkey);
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "uri", uri);
	cJSON_AddStringToObject(o, "cid", cid);
	if (value) cJSON_AddItemToObject(o, "value", cJSON_Parse(value));
	return o;
}

static res get_record(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	const char *col = ARG("collection"), *rkey = ARG("rkey");
	if (!col || !rkey) return err(c, 400, "InvalidRequest", "collection and rkey are required");
	if (find_account(ARG("repo"), 0, &a)) return err(c, 400, "RepoNotFound", "could not find repo");
	sqlite3_stmt *s = q("SELECT cid,value FROM record WHERE did=? AND collection=? AND rkey=?", 3, a.did, col, rkey);
	res r = sqlite3_step(s) == SQLITE_ROW
	            ? reply(c, 200, record_view(a.did, col, rkey, (const char *)sqlite3_column_text(s, 0),
	                                        (const char *)sqlite3_column_text(s, 1)))
	            : err(c, 400, "RecordNotFound", "could not locate record");
	sqlite3_finalize(s);
	return r;
}

static res list_records(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	const char *col = ARG("collection"), *cursor = ARG("cursor"), *rev = ARG("reverse"), *lim = ARG("limit");
	if (!col) return err(c, 400, "InvalidRequest", "collection is required");
	if (find_account(ARG("repo"), 0, &a)) return err(c, 400, "RepoNotFound", "could not find repo");
	int limit = lim ? atoi(lim) : 50;
	if (limit < 1 || limit > 100) return err(c, 400, "InvalidRequest", "limit must be 1-100");
	char limstr[8], last[520] = "";
	snprintf(limstr, sizeof limstr, "%d", limit);
	int asc = rev && !strcmp(rev, "true");
	sqlite3_stmt *s =
	    q(asc ? "SELECT rkey,cid,value FROM record WHERE did=?1 AND collection=?2 AND (?3 IS NULL OR rkey>?3) "
	            "ORDER BY rkey ASC LIMIT CAST(?4 AS INTEGER)"
	          : "SELECT rkey,cid,value FROM record WHERE did=?1 AND collection=?2 AND (?3 IS NULL OR rkey<?3) "
	            "ORDER BY rkey DESC LIMIT CAST(?4 AS INTEGER)",
	      4, a.did, col, cursor, limstr);
	cJSON *o = cJSON_CreateObject(), *arr = cJSON_AddArrayToObject(o, "records");
	int n = 0;
	while (sqlite3_step(s) == SQLITE_ROW) {
		snprintf(last, sizeof last, "%s", sqlite3_column_text(s, 0));
		cJSON_AddItemToArray(arr, record_view(a.did, col, last, (const char *)sqlite3_column_text(s, 1),
		                                      (const char *)sqlite3_column_text(s, 2)));
		n++;
	}
	sqlite3_finalize(s);
	if (n == limit) cJSON_AddStringToObject(o, "cursor", last);
	return reply(c, 200, o);
}

enum { CREATE, PUT, DELETE };

typedef struct {
	int op, exists, changed;
	const char *col, *rkey;
	cJSON *rec;
	char rk[14], cid[64], cur[64], path[1024];
} write_t;

/* Checks one write against the repo and fills in rkey, cid and the current
 * version. Returns an error message (and its XRPC name), or NULL if fine. */
static const char *prep_write(const char *did, write_t *w, const cJSON *swap, const char **name) {
	*name = "InvalidRequest";
	if (!w->col || !valid_nsid(w->col)) return "invalid collection";
	if (!w->rkey && w->op == CREATE) tid(w->rk), w->rkey = w->rk;
	if (!w->rkey || !valid_rkey(w->rkey)) return "invalid rkey";
	snprintf(w->path, sizeof w->path, "%s/%s", w->col, w->rkey);
	sqlite3_stmt *s = q("SELECT cid FROM record WHERE did=? AND collection=? AND rkey=?", 3, did, w->col, w->rkey);
	if ((w->exists = sqlite3_step(s) == SQLITE_ROW)) snprintf(w->cur, sizeof w->cur, "%s", sqlite3_column_text(s, 0));
	sqlite3_finalize(s);
	if (swap && w->op != CREATE &&
	    (cJSON_IsNull(swap) ? w->exists : !cJSON_IsString(swap) || !w->exists || strcmp(swap->valuestring, w->cur)))
		return *name = "InvalidSwap", "record was at a different version";
	if (w->op == CREATE && w->exists) return "record already exists";
	if (w->op == DELETE) return NULL;
	*name = "InvalidRecord";
	if (!cJSON_IsObject(w->rec)) return "record must be an object";
	cJSON *type = cJSON_GetObjectItemCaseSensitive(w->rec, "$type");
	if (!type) cJSON_AddStringToObject(w->rec, "$type", w->col);
	else if (!cJSON_IsString(type) || strcmp(type->valuestring, w->col)) return "$type must match collection";
	return record_cid(w->rec, w->cid) ? "record is not valid atproto data" : NULL;
}

/* Applies writes as one signed commit and one #commit event, or not at all.
 * Returns how many writes changed something (0: no commit made), -1 on error. */
static int commit_writes(const char *did, const char *since, write_t *w, int n, char ccid[64], char rev[14]) {
	buf old = {0}, now = {0}, diff = {0};
	unsigned char prev_data[36], root[36], (*cids)[2][36] = calloc((size_t)n, sizeof *cids);
	repo_op *ops = calloc((size_t)n, sizeof *ops);
	int rc = 0, changed = 0;
	sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);
	mst_root(did, &old, NULL, prev_data);
	for (int i = 0; i < n && !rc; i++) {
		char *json = w[i].op == DELETE ? NULL : cJSON_PrintUnformatted(w[i].rec);
		rc = exec1(json ? q("INSERT OR REPLACE INTO record(did,collection,rkey,cid,value) VALUES(?,?,?,?,?)", 5, did,
		                    w[i].col, w[i].rkey, w[i].cid, json)
		                : q("DELETE FROM record WHERE did=? AND collection=? AND rkey=?", 3, did, w[i].col, w[i].rkey));
		free(json);
		changed += w[i].changed = !rc && sqlite3_changes(db) > 0;
	}
	if (!rc && changed) rc = new_commit(did, &now, ccid, rev);
	if (!rc && changed) {
		car_diff(&diff, &now, &old);
		int nops = 0;
		for (int i = 0; i < n; i++) {
			if (!w[i].changed) continue;
			/* ops must be invertible from the event alone (sync 1.1): send the
			 * new nodes plus each key's search path, which may reuse old nodes */
			buf proof = {0};
			mst_root(did, &proof, w[i].path, root);
			car_diff(&diff, &proof, &diff);
			free(proof.p);
			if (w[i].rec) {
				buf rb = {0};
				cbor(&rb, w[i].rec);
				emit(&diff, &rb, cids[i][0]);
				free(rb.p);
			}
			ops[nops++] = (repo_op){w[i].op == DELETE ? "delete" : w[i].exists ? "update" : "create", w[i].path,
			                        w[i].rec ? cids[i][0] : NULL,
			                        w[i].exists && !cid_parse(w[i].cur, cids[i][1]) ? cids[i][1] : NULL};
		}
		rc = commit_event(did, since, prev_data, ccid, rev, &diff, ops, nops);
	}
	sqlite3_exec(db, rc ? "ROLLBACK" : "COMMIT", NULL, NULL, NULL);
	free(old.p), free(now.p), free(diff.p), free(cids), free(ops);
	broadcast();
	return rc ? -1 : changed;
}

static void add_commit(cJSON *o, const char *cid, const char *rev) {
	cJSON *c = cJSON_AddObjectToObject(o, "commit");
	cJSON_AddStringToObject(c, "cid", cid);
	cJSON_AddStringToObject(c, "rev", rev);
}

/* Shared front half of every write: the caller must own the repo, and an
 * optional swapCommit must match the current head. Returns an error or 0. */
static res writer(struct MHD_Connection *c, const cJSON *b, account *a) {
	char did[64];
	if (auth(c, "com.atproto.access", did)) return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	if (find_account(str(b, "repo"), 0, a) || strcmp(a->did, did))
		return err(c, 403, "Forbidden", "can only write to your own repo");
	const char *swap = str(b, "swapCommit");
	if (swap && strcmp(swap, a->head)) return err(c, 400, "InvalidSwap", "repo head has moved");
	return 0;
}

static res repo_write(struct MHD_Connection *c, cJSON *b, int op) {
	account a;
	char ccid[64], rev[14];
	res r = writer(c, b, &a);
	if (r) return r;
	write_t w = {.op = op, .col = str(b, "collection"), .rkey = str(b, "rkey")};
	w.rec = op == DELETE ? NULL : cJSON_GetObjectItemCaseSensitive(b, "record");
	const char *name, *e = prep_write(a.did, &w, cJSON_GetObjectItemCaseSensitive(b, "swapRecord"), &name);
	if (e) return err(c, 400, name, e);
	int changed = commit_writes(a.did, a.rev, &w, 1, ccid, rev);
	if (changed < 0) return err(c, 500, "InternalServerError", "write failed");
	cJSON *o = op == DELETE ? cJSON_CreateObject() : record_view(a.did, w.col, w.rkey, w.cid, NULL);
	if (changed) add_commit(o, ccid, rev);
	if (op != DELETE) cJSON_AddStringToObject(o, "validationStatus", "unknown");
	return reply(c, 200, o);
}

static res create_record(struct MHD_Connection *c, cJSON *b) { return repo_write(c, b, CREATE); }
static res put_record(struct MHD_Connection *c, cJSON *b) { return repo_write(c, b, PUT); }
static res delete_record(struct MHD_Connection *c, cJSON *b) { return repo_write(c, b, DELETE); }

static res apply_writes(struct MHD_Connection *c, cJSON *b) {
	static const char *kinds[] = {"#create", "#update", "#delete"}, *results[] = {"#createResult", "#updateResult",
	                                                                            "#deleteResult"};
	account a;
	char ccid[64], rev[14], t[80];
	res r = writer(c, b, &a);
	if (r) return r;
	cJSON *ws = cJSON_GetObjectItemCaseSensitive(b, "writes"), *x;
	int n = cJSON_GetArraySize(ws), i = 0;
	if (!cJSON_IsArray(ws) || n < 1 || n > 200) return err(c, 400, "InvalidRequest", "writes must hold 1-200 items");
	write_t *w = calloc((size_t)n, sizeof *w);
	const char *e = NULL, *name = "InvalidRequest";
	cJSON_ArrayForEach(x, ws) {
		const char *type = str(x, "$type"), *hash = type ? strchr(type, '#') : NULL;
		w[i].op = -1;
		for (int k = 0; k < 3; k++)
			if (hash && !strncmp(type, "com.atproto.repo.applyWrites", (size_t)(hash - type)) &&
			    hash - type == 28 && !strcmp(hash, kinds[k]))
				w[i].op = k;
		if (w[i].op < 0) {
			e = "unknown write $type", name = "InvalidRequest";
			break;
		}
		w[i].col = str(x, "collection"), w[i].rkey = str(x, "rkey");
		w[i].rec = w[i].op == DELETE ? NULL : cJSON_GetObjectItemCaseSensitive(x, "value");
		if ((e = prep_write(a.did, &w[i], NULL, &name))) break;
		for (int j = 0; j < i && !e; j++)
			if (!strcmp(w[j].path, w[i].path)) e = "duplicate write to one record", name = "InvalidRequest";
		if (e) break;
		i++;
	}
	int changed = e ? 0 : commit_writes(a.did, a.rev, w, n, ccid, rev);
	if (e || changed < 0) {
		free(w);
		return e ? err(c, 400, name, e) : err(c, 500, "InternalServerError", "write failed");
	}
	cJSON *o = cJSON_CreateObject(), *res_ = cJSON_CreateArray();
	if (changed) add_commit(o, ccid, rev);
	for (i = 0; i < n; i++) {
		cJSON *one = w[i].op == DELETE ? cJSON_CreateObject() : record_view(a.did, w[i].col, w[i].rkey, w[i].cid, NULL);
		snprintf(t, sizeof t, "com.atproto.repo.applyWrites%s", results[w[i].op]);
		cJSON_AddStringToObject(one, "$type", t);
		if (w[i].op != DELETE) cJSON_AddStringToObject(one, "validationStatus", "unknown");
		cJSON_AddItemToArray(res_, one);
	}
	cJSON_AddItemToObject(o, "results", res_);
	free(w);
	return reply(c, 200, o);
}

/* ---------- sync ---------- */

static int did_arg(struct MHD_Connection *c, account *a) {
	const char *d = ARG("did");
	return d && !strncmp(d, "did:", 4) && !find_account(d, 0, a) ? 0 : -1;
}

static res get_latest_commit(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	if (did_arg(c, &a)) return err(c, 400, "RepoNotFound", "could not find repo for DID");
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "cid", a.head);
	cJSON_AddStringToObject(o, "rev", a.rev);
	return reply(c, 200, o);
}

static res get_repo_status(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	if (did_arg(c, &a)) return err(c, 400, "RepoNotFound", "could not find repo for DID");
	cJSON *o = cJSON_CreateObject();
	cJSON_AddStringToObject(o, "did", a.did);
	cJSON_AddBoolToObject(o, "active", 1);
	cJSON_AddStringToObject(o, "rev", a.rev);
	return reply(c, 200, o);
}

static res list_repos(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	const char *lim = ARG("limit");
	int limit = lim ? atoi(lim) : 500;
	if (limit < 1 || limit > 1000) return err(c, 400, "InvalidRequest", "limit must be 1-1000");
	char limstr[8], last[64] = "";
	snprintf(limstr, sizeof limstr, "%d", limit);
	sqlite3_stmt *s = q("SELECT did,head,rev FROM account WHERE ?1 IS NULL OR did>?1 ORDER BY did "
	                    "LIMIT CAST(?2 AS INTEGER)",
	                    2, ARG("cursor"), limstr);
	cJSON *o = cJSON_CreateObject(), *arr = cJSON_AddArrayToObject(o, "repos");
	int n = 0;
	for (; sqlite3_step(s) == SQLITE_ROW; n++) {
		cJSON *r = cJSON_CreateObject();
		snprintf(last, sizeof last, "%s", sqlite3_column_text(s, 0));
		cJSON_AddStringToObject(r, "did", last);
		cJSON_AddStringToObject(r, "head", (const char *)sqlite3_column_text(s, 1));
		cJSON_AddStringToObject(r, "rev", (const char *)sqlite3_column_text(s, 2));
		cJSON_AddBoolToObject(r, "active", 1);
		cJSON_AddItemToArray(arr, r);
	}
	sqlite3_finalize(s);
	if (n == limit) cJSON_AddStringToObject(o, "cursor", last);
	return reply(c, 200, o);
}

/* Whole repo as CAR v1: commit, MST nodes, records.
 * ponytail: always a full export; the `since` diff param is ignored. */
static res get_repo(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	if (did_arg(c, &a)) return err(c, 400, "RepoNotFound", "could not find repo for DID");
	buf car = {0}, blk = {0};
	unsigned char cid[36];
	sqlite3_stmt *s = q("SELECT head_block FROM account WHERE did=?", 1, a.did);
	if (sqlite3_step(s) == SQLITE_ROW) put(&blk, sqlite3_column_blob(s, 0), (size_t)sqlite3_column_bytes(s, 0));
	sqlite3_finalize(s);
	cid_of(&blk, cid);
	car_header(&car, cid);
	emit(&car, &blk, cid);
	mst_root(a.did, &car, NULL, cid);
	s = q("SELECT value FROM record WHERE did=?", 1, a.did);
	while (sqlite3_step(s) == SQLITE_ROW) {
		cJSON *v = cJSON_Parse((const char *)sqlite3_column_text(s, 0));
		blk.n = 0;
		cbor(&blk, v); /* validated on write, so this succeeds */
		cJSON_Delete(v);
		emit(&car, &blk, cid);
	}
	sqlite3_finalize(s);
	free(blk.p);
	return send_raw(c, 200, "application/vnd.ipld.car", car.p, car.n);
}

/* ---------- blobs ---------- */

static res get_blob(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	if (did_arg(c, &a)) return err(c, 400, "RepoNotFound", "could not find repo for DID");
	sqlite3_stmt *s = q("SELECT mime, data FROM blob WHERE did=? AND cid=?", 2, a.did, ARG("cid"));
	res r;
	if (sqlite3_step(s) == SQLITE_ROW) {
		size_t n = (size_t)sqlite3_column_bytes(s, 1);
		void *data = malloc(n ? n : 1);
		memcpy(data, sqlite3_column_blob(s, 1), n);
		r = send_raw(c, 200, (const char *)sqlite3_column_text(s, 0), data, n);
	} else {
		r = err(c, 400, "BlobNotFound", "blob not found");
	}
	sqlite3_finalize(s);
	return r;
}

static res list_blobs(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	account a;
	if (did_arg(c, &a)) return err(c, 400, "RepoNotFound", "could not find repo for DID");
	const char *lim = ARG("limit");
	int limit = lim ? atoi(lim) : 500;
	if (limit < 1 || limit > 1000) return err(c, 400, "InvalidRequest", "limit must be 1-1000");
	char limstr[8], last[64] = "";
	snprintf(limstr, sizeof limstr, "%d", limit);
	sqlite3_stmt *s = q("SELECT cid FROM blob WHERE did=?1 AND (?2 IS NULL OR cid>?2) ORDER BY cid "
	                    "LIMIT CAST(?3 AS INTEGER)",
	                    3, a.did, ARG("cursor"), limstr);
	cJSON *o = cJSON_CreateObject(), *arr = cJSON_AddArrayToObject(o, "cids");
	int n = 0;
	for (; sqlite3_step(s) == SQLITE_ROW; n++) {
		snprintf(last, sizeof last, "%s", sqlite3_column_text(s, 0));
		cJSON_AddItemToArray(arr, cJSON_CreateString(last));
	}
	sqlite3_finalize(s);
	if (n == limit) cJSON_AddStringToObject(o, "cursor", last);
	return reply(c, 200, o);
}

static res subscribe_repos(struct MHD_Connection *c, cJSON *b) {
	(void)b;
	const char *key = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Sec-WebSocket-Key"),
	           *up = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Upgrade"), *cur = ARG("cursor");
	if (!key || strlen(key) > 64 || !up || strcasecmp(up, "websocket"))
		return err(c, 400, "InvalidRequest", "websocket upgrade required");
	char *end;
	long long cursor = cur ? strtoll(cur, &end, 10) : -1;
	if (cur && (*end || cursor < 0)) return err(c, 400, "InvalidRequest", "invalid cursor");
	char in[128], accept[32];
	unsigned char h[20];
	snprintf(in, sizeof in, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
	SHA1((unsigned char *)in, strlen(in), h);
	EVP_EncodeBlock((unsigned char *)accept, h, sizeof h);
	struct MHD_Response *r = MHD_create_response_for_upgrade(on_upgrade, (void *)(intptr_t)(cursor + 1));
	MHD_add_response_header(r, "Upgrade", "websocket");
	MHD_add_response_header(r, "Sec-WebSocket-Accept", accept);
	res ret = MHD_queue_response(c, MHD_HTTP_SWITCHING_PROTOCOLS, r);
	MHD_destroy_response(r);
	return ret;
}

static const struct {
	const char *path;
	int post;
	res (*fn)(struct MHD_Connection *, cJSON *);
} routes[] = {
    {"/xrpc/_health", 0, health},
    {"/xrpc/com.atproto.server.describeServer", 0, describe_server},
    {"/xrpc/com.atproto.server.createAccount", 1, create_account},
    {"/xrpc/com.atproto.server.createSession", 1, create_session},
    {"/xrpc/com.atproto.server.getSession", 0, get_session},
    {"/xrpc/com.atproto.server.refreshSession", 1, refresh_session},
    {"/xrpc/com.atproto.server.deleteSession", 1, delete_session},
    {"/xrpc/com.atproto.identity.resolveHandle", 0, resolve_handle},
    {"/xrpc/com.atproto.identity.updateHandle", 1, update_handle},
    {"/xrpc/com.atproto.repo.describeRepo", 0, describe_repo},
    {"/xrpc/com.atproto.repo.getRecord", 0, get_record},
    {"/xrpc/com.atproto.repo.listRecords", 0, list_records},
    {"/xrpc/com.atproto.repo.createRecord", 1, create_record},
    {"/xrpc/com.atproto.repo.putRecord", 1, put_record},
    {"/xrpc/com.atproto.repo.deleteRecord", 1, delete_record},
    {"/xrpc/com.atproto.repo.applyWrites", 1, apply_writes},
    {"/xrpc/com.atproto.sync.getRepo", 0, get_repo},
    {"/xrpc/com.atproto.sync.getLatestCommit", 0, get_latest_commit},
    {"/xrpc/com.atproto.sync.getRepoStatus", 0, get_repo_status},
    {"/xrpc/com.atproto.sync.listRepos", 0, list_repos},
    {"/xrpc/com.atproto.sync.subscribeRepos", 0, subscribe_repos},
    {"/xrpc/com.atproto.sync.getBlob", 0, get_blob},
    {"/xrpc/com.atproto.server.getServiceAuth", 0, get_service_auth},
    {"/xrpc/app.bsky.actor.getPreferences", 0, get_prefs},
    {"/xrpc/app.bsky.actor.putPreferences", 1, put_prefs},
    {"/xrpc/com.atproto.sync.listBlobs", 0, list_blobs},
};

/* Handle → DID over HTTPS: GET /.well-known/atproto-did with Host: <handle>. */
static res well_known_did(struct MHD_Connection *c) {
	const char *host = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Host");
	char h[256];
	account a;
	snprintf(h, sizeof h, "%s", host ? host : "");
	h[strcspn(h, ":")] = 0;
	if (find_account(h, 0, &a) || strncmp(h, "did:", 4) == 0)
		return send_body(c, 404, "text/plain", strdup("not found"));
	return send_body(c, 200, "text/plain", strdup(a.did));
}

/* Raw body (not JSON); the blob's CID is a raw-codec CIDv1.
 * ponytail: blobs are kept forever, even if no record ever references them,
 * and records aren't checked to reference blobs that exist. Add a GC sweep
 * of unreferenced blobs if storage matters. */
static res upload_blob(struct MHD_Connection *c, const body *bd) {
	char did[64], cs[64], size[24];
	if (auth(c, "com.atproto.access", did)) return err(c, 401, "AuthenticationRequired", "invalid or expired token");
	if (bd->too_big) return err(c, 413, "BlobTooLarge", "blob exceeds 5MB");
	const char *mime = MHD_lookup_connection_value(c, MHD_HEADER_KIND, "Content-Type");
	if (!mime || !*mime || strlen(mime) > 128 || strpbrk(mime, "\r\n")) mime = "application/octet-stream";
	unsigned char cid[36] = {0x01, 0x55, 0x12, 0x20}; /* v1, raw, sha2-256 */
	SHA256(bd->n ? (unsigned char *)bd->p : (unsigned char *)"", bd->n, cid + 4);
	cid_str(cid, cs);
	snprintf(size, sizeof size, "%zu", bd->n);
	sqlite3_stmt *s = q("INSERT OR IGNORE INTO blob(did,cid,mime,size,data) VALUES(?1,?2,?3,CAST(?4 AS INTEGER),?5)",
	                    4, did, cs, mime, size);
	sqlite3_bind_blob(s, 5, bd->n ? bd->p : "", (int)bd->n, SQLITE_TRANSIENT);
	if (exec1(s)) return err(c, 500, "InternalServerError", "could not store blob");
	cJSON *o = cJSON_CreateObject(), *blob = cJSON_AddObjectToObject(o, "blob");
	cJSON_AddStringToObject(blob, "$type", "blob");
	cJSON_AddStringToObject(cJSON_AddObjectToObject(blob, "ref"), "$link", cs);
	cJSON_AddStringToObject(blob, "mimeType", mime);
	cJSON_AddNumberToObject(blob, "size", (double)bd->n);
	return reply(c, 200, o);
}

static res dispatch(struct MHD_Connection *c, const char *url, const char *method, body *bd);

static res handler(void *cls, struct MHD_Connection *c, const char *url, const char *method, const char *ver,
                   const char *up, size_t *upsz, void **ctx) {
	(void)cls, (void)ver;
	body *bd = *ctx;
	if (!bd) {
		*ctx = calloc(1, sizeof *bd);
		return MHD_YES;
	}
	if (*upsz) {
		if (bd->n + *upsz > MAX_BODY) bd->too_big = 1;
		else {
			bd->p = realloc(bd->p, bd->n + *upsz + 1);
			memcpy(bd->p + bd->n, up, *upsz);
			bd->n += *upsz;
		}
		*upsz = 0;
		return MHD_YES;
	}
	if (!strcmp(method, "OPTIONS")) return send_body(c, 204, "text/plain", strdup(""));
	if (bd->too_big && strcmp(url, "/xrpc/com.atproto.repo.uploadBlob"))
		return err(c, 413, "PayloadTooLarge", "request body too large");
	const char *nsid = !strncmp(url, "/xrpc/", 6) ? url + 6 : "";
	int known = !strncmp(url, "/.well-known/", 13) || !strcmp(nsid, "com.atproto.repo.uploadBlob");
	for (size_t i = 0; i < sizeof routes / sizeof *routes; i++) known |= !strcmp(url, routes[i].path);
	if (!known && valid_nsid(nsid) &&
	    (!strncmp(nsid, "app.bsky.", 9) || MHD_lookup_connection_value(c, MHD_HEADER_KIND, "atproto-proxy")))
		return proxy(c, method, nsid, bd);
	pthread_mutex_lock(&big);
	res r = dispatch(c, url, method, bd);
	pthread_mutex_unlock(&big);
	return r;
}

static res dispatch(struct MHD_Connection *c, const char *url, const char *method, body *bd) {
	if (!strcmp(url, "/.well-known/atproto-did")) return well_known_did(c);
	if (!strcmp(url, "/.well-known/did.json")) return service_did_doc(c);
	if (!strcmp(url, "/xrpc/com.atproto.repo.uploadBlob"))
		return strcmp(method, "POST") ? err(c, 405, "InvalidRequest", "wrong HTTP method") : upload_blob(c, bd);
	for (size_t i = 0; i < sizeof routes / sizeof *routes; i++) {
		if (strcmp(url, routes[i].path)) continue;
		if (strcmp(method, routes[i].post ? "POST" : "GET"))
			return err(c, 405, "InvalidRequest", "wrong HTTP method");
		cJSON *json = NULL;
		if (routes[i].post && bd->n) {
			json = cJSON_ParseWithLength(bd->p, bd->n);
			if (!cJSON_IsObject(json)) {
				cJSON_Delete(json);
				return err(c, 400, "InvalidRequest", "body must be a JSON object");
			}
		}
		res r = routes[i].fn(c, json);
		cJSON_Delete(json);
		return r;
	}
	return err(c, strncmp(url, "/xrpc/", 6) ? 404 : 501, "MethodNotImplemented", "method not implemented");
}

static void done(void *cls, struct MHD_Connection *c, void **ctx, enum MHD_RequestTerminationCode t) {
	(void)cls, (void)c, (void)t;
	body *bd = *ctx;
	if (bd) free(bd->p), free(bd);
	*ctx = NULL;
}

static const char *env(const char *k, const char *def) {
	const char *v = getenv(k);
	return v && *v ? v : def;
}

int main(void) {
	hostname = env("PDS_HOSTNAME", "localhost");
	int port = atoi(env("PDS_PORT", "2583"));
	const char *secret = getenv("PDS_JWT_SECRET");
	if (secret && *secret) SHA256((const unsigned char *)secret, strlen(secret), jwt_secret);
	else {
		fprintf(stderr, "warning: PDS_JWT_SECRET unset, tokens die on restart\n");
		RAND_bytes(jwt_secret, sizeof jwt_secret);
	}
	if (!strcmp(hostname, "localhost")) snprintf(endpoint, sizeof endpoint, "http://localhost:%d", port);
	else snprintf(endpoint, sizeof endpoint, "https://%s", hostname);
	snprintf(service_did, sizeof service_did, "did:web:%s", hostname);
	int local = !strcmp(hostname, "localhost");
	plc_url = env("PDS_PLC_URL", local ? NULL : "https://plc.directory");
	crawler = env("PDS_CRAWLER", local ? NULL : "https://bsky.network");
	appview_url = env("PDS_APPVIEW_URL", "https://api.bsky.app");
	appview_did = env("PDS_APPVIEW_DID", "did:web:api.bsky.app");
	curl_global_init(CURL_GLOBAL_DEFAULT);
	pthread_mutexattr_t ma;
	pthread_mutexattr_init(&ma);
	pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&big, &ma);

	if (sqlite3_open(env("PDS_DB", "pds.sqlite"), &db) ||
	    sqlite3_exec(db,
	                 "PRAGMA journal_mode=WAL;"
	                 "CREATE TABLE IF NOT EXISTS account(did TEXT PRIMARY KEY, handle TEXT UNIQUE NOT NULL,"
	                 " email TEXT UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL, key TEXT NOT NULL,"
	                 " pubkey TEXT NOT NULL, head TEXT, rev TEXT, head_block BLOB, plc_op TEXT);"
	                 "CREATE TABLE IF NOT EXISTS record(did TEXT NOT NULL, collection TEXT NOT NULL,"
	                 " rkey TEXT NOT NULL, cid TEXT NOT NULL, value TEXT NOT NULL,"
	                 " PRIMARY KEY(did, collection, rkey));"
	                 "CREATE TABLE IF NOT EXISTS pref(did TEXT PRIMARY KEY, prefs TEXT NOT NULL);"
	                 "CREATE TABLE IF NOT EXISTS blob(did TEXT NOT NULL, cid TEXT NOT NULL, mime TEXT NOT NULL,"
	                 " size INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(did, cid));"
	                 "CREATE TABLE IF NOT EXISTS event(seq INTEGER PRIMARY KEY AUTOINCREMENT, did TEXT NOT NULL,"
	                 " frame BLOB);",
	                 NULL, NULL, NULL)) {
		fprintf(stderr, "db: %s\n", sqlite3_errmsg(db));
		return 1;
	}
	sqlite3_stmt *s = q("SELECT ifnull(max(seq), 0) FROM event", 0);
	sqlite3_step(s);
	sent_seq = sqlite3_column_int64(s, 0);
	sqlite3_finalize(s);

	struct MHD_Daemon *d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD |
	                                            MHD_USE_ERROR_LOG | MHD_ALLOW_UPGRADE,
	                                        (uint16_t)port, NULL, NULL, handler, NULL, MHD_OPTION_NOTIFY_COMPLETED,
	                                        done, NULL,
	                                        MHD_OPTION_END);
	if (!d) {
		fprintf(stderr, "cannot listen on port %d\n", port);
		return 1;
	}
	fprintf(stderr, "PDS %s listening on :%d (plc: %s, crawler: %s)\n", hostname, port, plc_url ? plc_url : "off",
	        crawler ? crawler : "off");
	request_crawl();
	for (;;) pause();
}
