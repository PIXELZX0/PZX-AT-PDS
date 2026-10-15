/* pdsadmin.c — admin CLI for pds.c, a port of Bluesky's pdsadmin scripts.
 *
 * Settings come from the environment, then from the env file
 * (PDS_ENV_FILE, else /pds/pds.env, else ./pds.env): PDS_HOSTNAME,
 * PDS_ADMIN_PASSWORD, and optionally PDS_URL, PDS_PORT, PDS_CRAWLERS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>

static const char *hostname;
static char base[512];

static void die(const char *fmt, const char *arg) {
	fprintf(stderr, "error: ");
	fprintf(stderr, fmt, arg);
	fputc('\n', stderr);
	exit(1);
}

static void load_env_file(void) {
	const char *path = getenv("PDS_ENV_FILE");
	if (!path) path = access("/pds/pds.env", R_OK) == 0 ? "/pds/pds.env" : "pds.env";
	FILE *f = fopen(path, "r");
	if (!f) return;
	char line[1024];
	while (fgets(line, sizeof line, f)) {
		char *k = line + strspn(line, " \t"), *eq = strchr(k, '='), *v, *end;
		if (*k == '#' || !eq) continue;
		*eq = 0, v = eq + 1;
		if (!strncmp(k, "export ", 7)) k += 7;
		end = v + strcspn(v, "\r\n");
		*end = 0;
		if (end > v + 1 && (*v == '"' || *v == '\'') && end[-1] == *v) v++, end[-1] = 0;
		setenv(k, v, 0); /* the real environment wins */
	}
	fclose(f);
}

static const char *need(const char *k) {
	const char *v = getenv(k);
	if (!v || !*v) die("%s is not set (environment or pds.env)", k);
	return v;
}

typedef struct { char *p; size_t n; } mem;

static size_t collect(char *p, size_t size, size_t n, void *u) {
	mem *m = u;
	m->p = realloc(m->p, m->n + size * n + 1);
	memcpy(m->p + m->n, p, size * n);
	m->n += size * n;
	m->p[m->n] = 0;
	return size * n;
}

/* Calls url (POST when body is given) and returns the parsed JSON reply;
 * any non-2xx reply is printed as an XRPC error and exits. */
static cJSON *call(const char *url, const cJSON *body, int as_admin) {
	CURL *c = curl_easy_init();
	struct curl_slist *h = curl_slist_append(NULL, "Content-Type: application/json");
	mem m = {0};
	char *json = body ? cJSON_PrintUnformatted(body) : NULL, userpwd[400];
	long code = 0;
	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
	curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, collect);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, &m);
	if (json) curl_easy_setopt(c, CURLOPT_POSTFIELDS, json);
	if (as_admin) {
		snprintf(userpwd, sizeof userpwd, "admin:%s", need("PDS_ADMIN_PASSWORD"));
		curl_easy_setopt(c, CURLOPT_USERPWD, userpwd);
	}
	CURLcode rc = curl_easy_perform(c);
	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
	curl_slist_free_all(h);
	curl_easy_cleanup(c);
	free(json);
	if (rc != CURLE_OK) die("cannot reach %s", url);
	cJSON *r = cJSON_Parse(m.p ? m.p : "{}");
	free(m.p);
	if (code / 100 != 2) {
		cJSON *e = cJSON_GetObjectItem(r, "error"), *msg = cJSON_GetObjectItem(r, "message");
		fprintf(stderr, "error: %s: %s\n", cJSON_IsString(e) ? e->valuestring : "HTTP error",
		        cJSON_IsString(msg) ? msg->valuestring : url);
		exit(1);
	}
	return r ? r : cJSON_CreateObject();
}

static cJSON *xrpc(const char *nsid, const char *query, const cJSON *body, int as_admin) {
	char url[1024];
	snprintf(url, sizeof url, "%s/xrpc/%s%s%s", base, nsid, query ? "?" : "", query ? query : "");
	return call(url, body, as_admin);
}

static const char *s(const cJSON *o, const char *k) {
	cJSON *v = cJSON_GetObjectItem(o, k);
	return cJSON_IsString(v) ? v->valuestring : "";
}

/* 24 random [A-Za-z0-9] characters, like the original's base64 trimming. */
static void random_password(char out[25]) {
	static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	FILE *f = fopen("/dev/urandom", "rb");
	int n = 0, c;
	if (!f) die("cannot open %s", "/dev/urandom");
	while (n < 24 && (c = fgetc(f)) != EOF)
		if (c < 248) out[n++] = a[c % 62]; /* 248 = 4*62: no modulo bias */
	fclose(f);
	out[n] = 0;
}

static const char *arg_or_prompt(int argc, char **argv, int i, const char *prompt, char *buf, size_t n) {
	if (i < argc) return argv[i];
	printf(prompt, hostname);
	fflush(stdout);
	if (!fgets(buf, (int)n, stdin)) exit(1);
	buf[strcspn(buf, "\r\n")] = 0;
	return buf;
}

static const char *did_arg(int argc, char **argv) {
	if (argc < 4 || strncmp(argv[3], "did:", 4)) die("%s", "DID parameter required (e.g. did:plc:xyz123abc456)");
	return argv[3];
}

static cJSON *invite_code(void) {
	cJSON *b = cJSON_CreateObject();
	cJSON_AddNumberToObject(b, "useCount", 1);
	cJSON *r = xrpc("com.atproto.server.createInviteCode", NULL, b, 1);
	cJSON_Delete(b);
	return r;
}

static void account_list(void) {
	char q[300], cursor[128] = "";
	cJSON *rows = cJSON_CreateArray(), *repo;
	size_t w[2] = {6, 5}; /* "Handle", "Email" */
	for (;;) {
		snprintf(q, sizeof q, "limit=1000%s%s", *cursor ? "&cursor=" : "", cursor);
		cJSON *r = xrpc("com.atproto.sync.listRepos", q, NULL, 0);
		cJSON_ArrayForEach(repo, cJSON_GetObjectItem(r, "repos")) {
			snprintf(q, sizeof q, "did=%s", s(repo, "did"));
			cJSON *info = xrpc("com.atproto.admin.getAccountInfo", q, NULL, 1);
			if (strlen(s(info, "handle")) > w[0]) w[0] = strlen(s(info, "handle"));
			if (strlen(s(info, "email")) > w[1]) w[1] = strlen(s(info, "email"));
			cJSON_AddItemToArray(rows, info);
		}
		snprintf(cursor, sizeof cursor, "%s", s(r, "cursor"));
		cJSON_Delete(r);
		if (!*cursor) break;
	}
	printf("%-*s  %-*s  %s\n", (int)w[0], "Handle", (int)w[1], "Email", "DID");
	cJSON *info;
	cJSON_ArrayForEach(info, rows) printf("%-*s  %-*s  %s\n", (int)w[0], s(info, "handle"), (int)w[1],
	                                      s(info, "email"), s(info, "did"));
	cJSON_Delete(rows);
}

static void account_create(int argc, char **argv) {
	char eb[256], hb[256], pw[25];
	const char *email = arg_or_prompt(argc, argv, 3, "Enter an email address (e.g. alice@%s): ", eb, sizeof eb);
	const char *handle = arg_or_prompt(argc, argv, 4, "Enter a handle (e.g. alice.%s): ", hb, sizeof hb);
	if (!*email || !*handle) die("%s", "email and handle are required");
	random_password(pw);
	cJSON *inv = invite_code(), *b = cJSON_CreateObject();
	cJSON_AddStringToObject(b, "email", email);
	cJSON_AddStringToObject(b, "handle", handle);
	cJSON_AddStringToObject(b, "password", pw);
	cJSON_AddStringToObject(b, "inviteCode", s(inv, "code"));
	cJSON *r = xrpc("com.atproto.server.createAccount", NULL, b, 0);
	printf("\nAccount created successfully!\n"
	       "-----------------------------\n"
	       "Handle   : %s\n"
	       "DID      : %s\n"
	       "Password : %s\n"
	       "-----------------------------\n"
	       "Save this password, it will not be displayed again.\n\n",
	       s(r, "handle"), s(r, "did"), pw);
	cJSON_Delete(inv), cJSON_Delete(b), cJSON_Delete(r);
}

static void account_delete(int argc, char **argv) {
	const char *did = did_arg(argc, argv);
	char yn[16] = "";
	printf("This action is permanent.\nAre you sure you'd like to delete %s? [y/N] ", did);
	fflush(stdout);
	if (!fgets(yn, sizeof yn, stdin) || (yn[0] != 'y' && yn[0] != 'Y')) exit(0);
	cJSON *b = cJSON_CreateObject();
	cJSON_AddStringToObject(b, "did", did);
	cJSON_Delete(xrpc("com.atproto.admin.deleteAccount", NULL, b, 1));
	cJSON_Delete(b);
	printf("%s deleted\n", did);
}

static void account_takedown(int argc, char **argv, int applied) {
	const char *did = did_arg(argc, argv);
	char ref[32];
	snprintf(ref, sizeof ref, "%ld", (long)time(NULL));
	cJSON *b = cJSON_CreateObject(), *subj = cJSON_AddObjectToObject(b, "subject"),
	      *td = cJSON_AddObjectToObject(b, "takedown");
	cJSON_AddStringToObject(subj, "$type", "com.atproto.admin.defs#repoRef");
	cJSON_AddStringToObject(subj, "did", did);
	cJSON_AddBoolToObject(td, "applied", applied);
	if (applied) cJSON_AddStringToObject(td, "ref", ref);
	cJSON_Delete(xrpc("com.atproto.admin.updateSubjectStatus", NULL, b, 1));
	cJSON_Delete(b);
	printf("%s %s\n", did, applied ? "taken down" : "untaken down");
}

static void account_reset_password(int argc, char **argv) {
	const char *did = did_arg(argc, argv);
	char pw[25];
	random_password(pw);
	cJSON *b = cJSON_CreateObject();
	cJSON_AddStringToObject(b, "did", did);
	cJSON_AddStringToObject(b, "password", pw);
	cJSON_Delete(xrpc("com.atproto.admin.updateAccountPassword", NULL, b, 1));
	cJSON_Delete(b);
	printf("\nPassword reset for %s\nNew password: %s\n\n", did, pw);
}

static void request_crawl(int argc, char **argv) {
	const char *hosts = argc > 2 ? argv[2] : getenv("PDS_CRAWLERS");
	if (!hosts || !*hosts) die("%s", "no relay host given and PDS_CRAWLERS is not set");
	char *list = strdup(hosts), *save, url[600];
	cJSON *b = cJSON_CreateObject();
	cJSON_AddStringToObject(b, "hostname", hostname);
	for (char *h = strtok_r(list, ",", &save); h; h = strtok_r(NULL, ",", &save)) {
		h += strspn(h, " ");
		printf("Requesting crawl from %s\n", h);
		snprintf(url, sizeof url, "%s%s/xrpc/com.atproto.sync.requestCrawl", strstr(h, "://") ? "" : "https://", h);
		cJSON_Delete(call(url, b, 0));
	}
	cJSON_Delete(b);
	free(list);
	puts("done");
}

static void usage(void) {
	puts("pdsadmin help\n"
	     "---\n"
	     "update\n"
	     "  Update to the latest PDS version.\n"
	     "    e.g. pdsadmin update\n"
	     "\n"
	     "account\n"
	     "  list\n"
	     "    List accounts\n"
	     "    e.g. pdsadmin account list\n"
	     "  create <EMAIL> <HANDLE>\n"
	     "    Create a new account\n"
	     "    e.g. pdsadmin account create alice@example.com alice.example.com\n"
	     "  delete <DID>\n"
	     "    Delete an account specified by DID.\n"
	     "    e.g. pdsadmin account delete did:plc:xyz123abc456\n"
	     "  takedown <DID>\n"
	     "    Takedown an account specified by DID.\n"
	     "    e.g. pdsadmin account takedown did:plc:xyz123abc456\n"
	     "  untakedown <DID>\n"
	     "    Remove a takedown from an account specified by DID.\n"
	     "    e.g. pdsadmin account untakedown did:plc:xyz123abc456\n"
	     "  reset-password <DID>\n"
	     "    Reset a password for an account specified by DID.\n"
	     "    e.g. pdsadmin account reset-password did:plc:xyz123abc456\n"
	     "\n"
	     "request-crawl [<RELAY HOST>]\n"
	     "    Request a crawl from a relay host.\n"
	     "    e.g. pdsadmin request-crawl bsky.network\n"
	     "\n"
	     "create-invite-code\n"
	     "  Create a new invite code.\n"
	     "    e.g. pdsadmin create-invite-code\n"
	     "\n"
	     "help\n"
	     "    Display this help information.");
}

int main(int argc, char **argv) {
	const char *cmd = argc > 1 ? argv[1] : "help", *sub = argc > 2 ? argv[2] : "";
	if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) return usage(), 0;
	load_env_file();
	hostname = need("PDS_HOSTNAME");
	const char *url = getenv("PDS_URL"), *port = getenv("PDS_PORT");
	if (url && *url) snprintf(base, sizeof base, "%s", url);
	else if (!strcmp(hostname, "localhost")) snprintf(base, sizeof base, "http://localhost:%s", port ? port : "2583");
	else snprintf(base, sizeof base, "https://%s", hostname);
	curl_global_init(CURL_GLOBAL_DEFAULT);

	if (!strcmp(cmd, "update")) {
		fputs("pds.c is built from source: git pull && make, then restart pds\n", stderr);
		return 1;
	} else if (!strcmp(cmd, "create-invite-code")) {
		cJSON *r = invite_code();
		puts(s(r, "code"));
		cJSON_Delete(r);
	} else if (!strcmp(cmd, "request-crawl")) {
		request_crawl(argc, argv);
	} else if (!strcmp(cmd, "account") && !strcmp(sub, "list")) {
		account_list();
	} else if (!strcmp(cmd, "account") && !strcmp(sub, "create")) {
		account_create(argc, argv);
	} else if (!strcmp(cmd, "account") && !strcmp(sub, "delete")) {
		account_delete(argc, argv);
	} else if (!strcmp(cmd, "account") && !strcmp(sub, "takedown")) {
		account_takedown(argc, argv, 1);
	} else if (!strcmp(cmd, "account") && !strcmp(sub, "untakedown")) {
		account_takedown(argc, argv, 0);
	} else if (!strcmp(cmd, "account") && !strcmp(sub, "reset-password")) {
		account_reset_password(argc, argv);
	} else {
		fprintf(stderr, "Unknown command: %s %s\n\n", cmd, sub);
		usage();
		return 1;
	}
	return 0;
}
