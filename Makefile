PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /usr/local)
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
CFLAGS += -I$(PREFIX)/include -I$(PREFIX)/opt/openssl/include
LDFLAGS += -L$(PREFIX)/lib -L$(PREFIX)/opt/openssl/lib

all: pds pdsadmin

pds: LDLIBS = -lmicrohttpd -lcjson -lcurl -lcrypto -lsqlite3 -lm
pds: pds.c

pdsadmin: LDLIBS = -lcjson -lcurl
pdsadmin: pdsadmin.c

test: all
	./test.sh

clean:
	rm -f pds pdsadmin pds.sqlite*

.PHONY: all test clean
