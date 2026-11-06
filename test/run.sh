#!/usr/bin/env bash
# Prove hooks.js against real n8n images, before an n8n bump merges.
#
#   apps/n8n/n8n-oidc/test/run.sh              # the version pinned in apps/n8n/compose.yaml
#                                              # (when run from the `up` repo; elsewhere pass versions)
#   apps/n8n/n8n-oidc/test/run.sh 2.45.7 2.36.9
#   HOOK=/path/to/hooks.js apps/n8n/n8n-oidc/test/run.sh 2.45.7
#
# WHY. hooks.js reaches into n8n by absolute path, and n8n moves those paths
# between minors (2.45.x removed the file the hook used to require, and n8n
# exited at startup). Checking that a path exists is not enough, so this runs
# the hook: n8n starts with it loaded, the OIDC login redirects, the callback
# issues a session cookie, and n8n accepts that cookie on authenticated routes.
#
# Needs podman. On a Mac: `podman machine start`. The NixOS hosts have none.
# It uses a throwaway SQLite database inside a throwaway pod and touches no
# host and no real identity provider.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
hook=${HOOK:-$here/../hooks.js}
compose=$here/../../compose.yaml
port=${PORT:-5678}

if [ $# -eq 0 ]; then
  [ -f "$compose" ] || { echo "usage: $0 <n8n-version>..." >&2; exit 2; }
  v=$(sed -n 's#^[[:space:]]*image:[[:space:]]*ghcr.io/n8n-io/n8n:\([0-9][0-9.]*\).*#\1#p' "$compose" | head -n1)
  [ -n "$v" ] || { echo "no n8n image pin found in $compose" >&2; exit 2; }
  set -- "$v"
fi

pod=oidc-hook-test
cleanup() { podman pod rm -f "$pod" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fails=0
for version in "$@"; do
  img=ghcr.io/n8n-io/n8n:$version
  echo "=== n8n $version"
  cleanup
  podman pull -q "$img" >/dev/null
  podman pod create --name "$pod" -p "$port:5678" >/dev/null
  podman run -d --pod "$pod" --name "$pod-idp" --entrypoint node \
    -v "$here/idp.js:/idp.js:ro" "$img" /idp.js </dev/null >/dev/null
  # N8N_ADDITIONAL_NON_UI_ROUTES=auth matches production: without it n8n's SPA
  # fallback answers /auth/oidc/* with index.html before the hook's routes.
  podman run -d --pod "$pod" --name "$pod-n8n" -v "$hook:/opt/n8n-oidc/hooks.js:ro" \
    -e EXTERNAL_HOOK_FILES=/opt/n8n-oidc/hooks.js -e N8N_ENCRYPTION_KEY=test \
    -e N8N_ADDITIONAL_NON_UI_ROUTES=auth -e N8N_SECURE_COOKIE=false \
    -e N8N_DIAGNOSTICS_ENABLED=false \
    -e OIDC_ISSUER_URL=http://127.0.0.1:9999 -e OIDC_CLIENT_ID=t -e OIDC_CLIENT_SECRET=t \
    -e "OIDC_REDIRECT_URI=http://127.0.0.1:$port/auth/oidc/callback" \
    "$img" </dev/null >/dev/null

  up=0
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$port/healthz" >/dev/null; then up=1; break; fi
    sleep 3
  done
  if [ $up -eq 0 ]; then
    echo "FAIL  n8n did not start with the hook"
    podman logs "$pod-n8n" 2>&1 | grep -E "Cannot find module|Error:|External hook|failed" | head -5 || true
    fails=$((fails + 1)); continue
  fi
  # n8n listens before it runs the ready hooks, so /healthz can answer for a
  # moment and then the process exits on a hook that throws. Let it get past
  # that, then require the container to still be running.
  sleep 8
  if [ "$(podman inspect -f '{{.State.Running}}' "$pod-n8n" 2>/dev/null)" != true ]; then
    echo "FAIL  n8n started and then exited (the hook threw in n8n.ready?)"
    podman logs "$pod-n8n" 2>&1 | grep -E "Cannot find module|Error:|External hook|failed" | head -5 || true
    fails=$((fails + 1)); continue
  fi

  work=$(mktemp -d)
  curl -s -o /dev/null -D "$work/login" -c "$work/jar" "http://127.0.0.1:$port/auth/oidc/login"
  state=$(grep -i '^location' "$work/login" | sed -E 's/.*[?&]state=([a-f0-9]+).*/\1/' | tr -d '\r' || true)
  if [ -z "$state" ]; then
    echo "FAIL  /auth/oidc/login did not redirect to the provider"; fails=$((fails + 1)); continue
  fi
  curl -s -o /dev/null -D "$work/cb" -b "$work/jar" -c "$work/jar" \
    "http://127.0.0.1:$port/auth/oidc/callback?code=x&state=$state"
  if ! grep -q 'n8n-auth=' "$work/cb"; then
    echo "FAIL  callback issued no session cookie: $(grep -i '^location' "$work/cb" | tr -d '\r')"
    podman logs "$pod-n8n" 2>&1 | grep -i "Callback error" | head -2 || true
    fails=$((fails + 1)); continue
  fi
  a=$(curl -s -b "$work/jar" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/rest/login")
  b=$(curl -s -b "$work/jar" -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/rest/workflows")
  c=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/rest/login")
  if [ "$a" = 200 ] && [ "$b" = 200 ] && [ "$c" = 401 ]; then
    echo "PASS  startup, redirect, cookie issued, accepted (login $a, workflows $b), no-cookie $c"
  else
    echo "FAIL  n8n rejected the issued cookie (login $a, workflows $b, no-cookie $c)"
    fails=$((fails + 1))
  fi
done

[ "$fails" -eq 0 ]
