listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault/vault-server.crt.pem"
  tls_key_file = "/etc/vault/vault-server.key.pem"
  tls_client_ca_file = "/etc/vault/vault-server.ca.crt.pem"
}

api_addr = "https://${vault_tls_cn}:8200"

storage "gcs" {
  bucket           = "${storage_bucket}"
}
