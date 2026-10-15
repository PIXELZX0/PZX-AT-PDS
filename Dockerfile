FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev make libmicrohttpd-dev libcjson-dev libcurl4-openssl-dev libssl-dev libsqlite3-dev \
      curl python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN make PREFIX=/usr && make test

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libmicrohttpd12 libcjson1 libcurl4 libssl3 libsqlite3-0 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -d /pds pds && mkdir /pds && chown pds /pds
COPY --from=build /src/pds /src/pdsadmin /usr/local/bin/
# admin.html is optional; the glob keeps COPY from failing when it's absent
COPY --from=build /src/admin.htm[l] /usr/local/share/pds/
ENV PDS_DB=/pds/pds.sqlite PDS_ADMIN_HTML=/usr/local/share/pds/admin.html PDS_PORT=2583
USER pds
WORKDIR /pds
VOLUME /pds
EXPOSE 2583
CMD ["pds"]
