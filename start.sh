#!/usr/bin/env bash
# Container entrypoint: optionally clone the repo to assess, then start THRYV.
set -e
mkdir -p /data/repos /data/artifacts
if [ -n "$THRYV_CLONE_URL" ] && [ ! -d /data/repos/target/.git ]; then
  git clone --depth 1 "$THRYV_CLONE_URL" /data/repos/target || echo "clone failed; scan without repo"
fi
exec python -m thryv serve
