FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox-static gdbserver trace-cmd \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/www \
    && printf 'contrace-ok\n' >/srv/www/index.html

EXPOSE 31337

CMD ["/bin/busybox", "httpd", "-f", "-p", "31337", "-h", "/srv/www"]
