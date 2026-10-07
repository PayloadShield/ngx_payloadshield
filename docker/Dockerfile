# syntax=docker/dockerfile:1
ARG NGINX_VERSION=1.28.3
ARG DEBIAN_IMAGE=debian:bookworm-slim

FROM ${DEBIAN_IMAGE} AS builder
ARG NGINX_VERSION
# Optional integrity check of the Nginx tarball.
ARG NGINX_SHA256=""
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl libssl-dev libpcre2-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    && if [ -n "${NGINX_SHA256}" ]; then echo "${NGINX_SHA256}  nginx-${NGINX_VERSION}.tar.gz" | sha256sum -c -; fi \
    && tar xzf "nginx-${NGINX_VERSION}.tar.gz"
COPY . /src/ngx_payloadshield
RUN make -C /src/ngx_payloadshield/tests test
WORKDIR /build/nginx-${NGINX_VERSION}
RUN ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --with-compat \
        --with-http_ssl_module \
        --with-http_v2_module \
        --add-dynamic-module=/src/ngx_payloadshield \
        --with-cc-opt="-D_GNU_SOURCE" \
    && make -j"$(nproc)" \
    && make install

FROM ${DEBIAN_IMAGE} AS runtime
ARG NGINX_VERSION
LABEL org.opencontainers.image.title="payloadshield-nginx" \
      org.opencontainers.image.version="${NGINX_VERSION}"
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libpcre2-8-0 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin nginx \
    && mkdir -p /var/log/nginx /var/cache/nginx /etc/payloadshield \
    && chown -R nginx:nginx /var/log/nginx /var/cache/nginx
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=builder /usr/lib/nginx /usr/lib/nginx
COPY --from=builder /etc/nginx /etc/nginx
COPY docker/nginx.conf /etc/nginx/nginx.conf
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log
EXPOSE 8080
STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]

# Test-only image: adds Python and runs the integration suite at build time.
FROM runtime AS test
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY tests/integration /tests/integration
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -r /tests/integration/requirements.txt
ENV NGINX_BIN=/usr/sbin/nginx \
    PAYLOADSHIELD_MODULE=/usr/lib/nginx/modules/ngx_http_payloadshield_module.so
# Run as the unprivileged user so Nginx workers can use the test temp directories.
USER nginx
RUN /venv/bin/python -m unittest discover -v -s /tests/integration

FROM runtime AS final
USER nginx
