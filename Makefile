PREFIX ?= $(shell brew --prefix 2>/dev/null || echo /usr/local)
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE
CFLAGS += -I$(PREFIX)/include -I$(PREFIX)/opt/openssl/include
LDLIBS = -L$(PREFIX)/lib -L$(PREFIX)/opt/openssl/lib -lmicrohttpd -lcjson -lcurl -lcrypto -lsqlite3 -lm

pds: pds.c

test: pds
	./test.sh

clean:
	rm -f pds pds.sqlite*

.PHONY: test clean
