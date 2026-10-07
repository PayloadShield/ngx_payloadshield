#!/usr/bin/env bash
# Builds, tests and smoke-tests one image per version in NGINX_VERSIONS
# (space separated; default: docker/nginx-versions.json). Nothing is pushed.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSIONS="${NGINX_VERSIONS:-$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' docker/nginx-versions.json | tr '\n' ' ')}"
for v in $VERSIONS; do
  echo "=== nginx $v ==="
  # The test stage runs the integration suite as part of the build.
  docker build -f docker/Dockerfile --build-arg NGINX_VERSION="$v" --target test -t "payloadshield-nginx:$v-test" .
  docker build -f docker/Dockerfile --build-arg NGINX_VERSION="$v" --target final -t "payloadshield-nginx:$v" .
  bash docker/smoke_test.sh "payloadshield-nginx:$v" "$v"
done
