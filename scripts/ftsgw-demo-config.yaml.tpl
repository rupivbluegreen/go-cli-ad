server:
  listen_addr: ":18443"
  tls_cert_path: @@WORK@@/server.crt
  tls_key_path:  @@WORK@@/server.key
signer:
  kind: file
  key_path: @@WORK@@/signing.ed25519
  key_id:   demo-2026-01
idp:
  kind: ldap
  url:  ldap://localhost:13389
  base_dn: "dc=example,dc=com"
  bind_dn_env: FTSGW_LDAP_BIND_DN
  bind_password_env: FTSGW_LDAP_BIND_PASSWORD
  user_search_filter:  "(cn=%s)"
  group_search_filter: "(member=%s)"
  start_tls: false
  timeout: 10s
tokens:
  ttl: 15m
  refresh_window: 4h
  issuer:   "ftsgw-server"
  audience: "ftsgw"
audit:
  file_path: @@WORK@@/audit.log
  syslog: { enabled: false, addr: "", network: tcp+tls }
ratelimit:
  per_ip_rps: 50
  per_ip_burst: 100
  auth_per_username_per_minute: 30
