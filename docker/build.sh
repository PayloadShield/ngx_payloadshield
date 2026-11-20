#!/usr/bin/env bash
# Builds, tests and smoke-tests one image per version in NGINX_VERSIONS
# (space separated; default: docker/nginx-versions.json). Nothing is pushed.
# set -euo pipefail
cd "$(dirname "$0")/.."
VERSIONS="${NGINX_VERSIONS:-$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' docker/nginx-versions.json | tr '\n' ' ')}"
for v in $VERSIONS; do
  echo "=== nginx $v ==="
  # The test stage runs the integration suite as part of the build.
  docker build -f docker/Dockerfile --build-arg NGINX_VERSION="$v" --target test -t "payloadshield-nginx:$v-test" .
  docker build -f docker/Dockerfile --build-arg NGINX_VERSION="$v" --target final -t "payloadshield-nginx:$v" .
  module_file="dist/ngx_http_payloadshield_module_$v.so"
  if [ ! -f "$module_file" ]; then
    mkdir -p "$(dirname "$module_file")"
    container_id=$(docker create "payloadshield-nginx:$v")
    if ! docker cp "$container_id:/usr/lib/nginx/modules/ngx_http_payloadshield_module.so" "$module_file"; then
      docker rm "$container_id" >/dev/null
      echo "Failed to copy the PayloadShield module for Nginx $v" >&2
      exit 1
    fi
    docker rm "$container_id" >/dev/null
  fi
  bash docker/smoke_test.sh "payloadshield-nginx:$v" "$v"
done
