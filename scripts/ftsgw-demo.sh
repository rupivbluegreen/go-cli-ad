#!/usr/bin/env bash
# scripts/ftsgw-demo.sh — boots OpenLDAP, generates TLS + Ed25519 keys,
# runs ftsgw-server, then walks login -> whoami -> status -> logout.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
WORK=$(mktemp -d -t ftsgw-demo.XXXXXX)
SRV_PID=""
cleanup() {
  if [ -n "${SRV_PID:-}" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
  docker rm -f ftsgw-demo-ldap >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> starting OpenLDAP"
docker run -d --rm --name ftsgw-demo-ldap \
  -e LDAP_ORGANISATION=Example -e LDAP_DOMAIN=example.com -e LDAP_ADMIN_PASSWORD=admin \
  -p 13389:389 osixia/openldap:1.5.0 >/dev/null
for i in $(seq 1 30); do
  if docker exec ftsgw-demo-ldap ldapsearch -x -H ldap://localhost -b dc=example,dc=com >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> seeding alice"
docker cp scripts/ftsgw-demo-seed.ldif ftsgw-demo-ldap:/seed.ldif
docker exec ftsgw-demo-ldap ldapadd -x -D 'cn=admin,dc=example,dc=com' -w admin -f /seed.ldif

echo "==> generating TLS + signing key"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=localhost" \
  -keyout "$WORK/server.key" -out "$WORK/server.crt" >/dev/null 2>&1
openssl genpkey -algorithm Ed25519 -out "$WORK/signing.pem"
python3 - "$WORK/signing.pem" "$WORK/signing.ed25519" <<'PY'
import base64, re, sys
src, dst = sys.argv[1], sys.argv[2]
raw = open(src,"rb").read()
body = b"".join(re.findall(rb"-----BEGIN.*?-----\n(.*?)-----END.*?-----", raw, re.S))
der = base64.b64decode(body)
seed = der[-32:]
open(dst,"w").write("-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(seed).decode() + "\n-----END PRIVATE KEY-----\n")
PY
chmod 0600 "$WORK/signing.ed25519" "$WORK/server.key"

echo "==> writing config"
sed -e "s|@@WORK@@|$WORK|g" scripts/ftsgw-demo-config.yaml.tpl > "$WORK/config.yaml"

echo "==> starting ftsgw-server"
export FTSGW_LDAP_BIND_DN='cn=admin,dc=example,dc=com'
export FTSGW_LDAP_BIND_PASSWORD='admin'
"$ROOT/bin/ftsgw-server" --config "$WORK/config.yaml" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 30); do
  if curl -fsk https://localhost:18443/healthz >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "==> ftsgw-cli login -> whoami -> status -> logout"
export FTSGW_USERNAME='cn=alice,dc=example,dc=com'
echo hunter2 | "$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" \
  --token-path "$WORK/token.json" login
"$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" --token-path "$WORK/token.json" whoami
"$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" --token-path "$WORK/token.json" status
"$ROOT/bin/ftsgw-cli" --broker https://localhost:18443 --ca-bundle "$WORK/server.crt" --token-path "$WORK/token.json" logout

echo "==> demo OK"
