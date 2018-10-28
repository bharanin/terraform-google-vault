#!/bin/bash -xe

##################
# Constants
##################
HASHI_GPGKEY="91A6E7F85D05C65630BEF18951852D87348FFC4C";
GPG_KEY_SERVERS="hkp://p80.pool.sks-keyservers.net:80 hkp://keyserver.ubuntu.com:80 hkp://pgp.mit.edu:80"

##################
# Functions
##################

# Retrieve and import requested key into gpg
# 1: Requested key fingerprint
get_gpg_key() {
  local gpgkey=$$1;
  local found='';
  for server in $${GPG_KEY_SERVERS}; do
      echo "Fetching GPG key $${gpgkey} from $${server}";
      gpg --keyserver "$${server}" --recv-keys "$${gpgkey}" && found=yes && break;
  done;
  test -z "$${found}" && echo >&2 "error: failed to fetch GPG key $${gpgkey}" && return 1;
  return 0;
}

# Export ascii-armored gpg key
# $1: key fingerprint to export
# $2: path to export key
export_ascii_gpg_key() {
  local gpgkey=$1
  local keypath=$2
  echo "Exporting key $${gpgkey} to $${keypath}"
  gpg --armor --export "$${gpgkey}" > "$${keypath}" && return 0;
  return 1;
}

apt-get update
apt-get install -y unzip jq netcat nginx gnupg ca-certificates openssl dirmngr

# Download vault, verify signature, install
get_gpg_key "$${HASHI_GPGKEY}"

cd /tmp && \
  curl -sLO https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_linux_amd64.zip && \
  curl -sLO https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_SHA256SUMS && \
  curl -sLO https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_SHA256SUMS.sig && \
  gpg --batch --verify vault_${vault_version}_SHA256SUMS.sig vault_${vault_version}_SHA256SUMS && \
  grep vault_${vault_version}_linux_amd64.zip vault_${vault_version}_SHA256SUMS | sha256sum -c && \
  unzip vault_${vault_version}_linux_amd64.zip && \
  mv vault /usr/local/bin/vault && \
  rm vault_${vault_version}_linux_amd64.zip

# Install Stackdriver for logging
curl -sSL https://dl.google.com/cloudagents/install-logging-agent.sh | bash

# Vault config
mkdir -p /etc/vault
cat - > /etc/vault/config.hcl <<'EOF'
${config}
EOF
chmod 0600 /etc/vault/config.hcl

# Service environment
cat - > /etc/vault/vault.env <<EOF
VAULT_ARGS=${vault_args}
EOF
chmod 0600 /etc/vault/vault.env

# TLS key and certs
for tls_file in ${vault_ca_cert} ${vault_tls_key} ${vault_tls_cert}; do
  gcloud kms decrypt \
    --location global \
    --keyring=${kms_keyring_name} \
    --key=${kms_key_name} \
    --plaintext-file /etc/vault/$${tls_file//.encrypted.base64/} \
    --ciphertext-file=<(gsutil cat gs://${assets_bucket}/$${tls_file} | base64 -d)
  chmod 0600 /etc/vault/$${tls_file//.encrypted.base64/}
done

# Systemd service
cat - > /etc/systemd/system/vault.service <<'EOF'
[Service]
EnvironmentFile=/etc/vault/vault.env
ExecStart=
ExecStart=/usr/local/bin/vault server -config=/etc/vault/config.hcl $${VAULT_ARGS}
EOF
chmod 0600 /etc/systemd/system/vault.service

systemctl daemon-reload
systemctl enable vault
systemctl start vault

# Setup vault env
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT=/etc/vault/vault-server.ca.crt.pem
export VAULT_CLIENT_CERT=/etc/vault/vault-server.crt.pem
export VAULT_CLIENT_KEY=/etc/vault/vault-server.key.pem

# Add health-check proxy, GCE doesn't support https health checks.
cat - > /etc/nginx/sites-available/default <<EOF
server {
    listen 80;
    location / {
        proxy_pass $${VAULT_ADDR}/v1/sys/health?standbyok=true&sealedcode=200;
    }
}
EOF

systemctl enable nginx
systemctl restart nginx

# Wait 30s for Vault to start
(while [[ $count -lt 15 && "$(vault status 2>&1)" =~ "connection refused" ]]; do ((count=count+1)) ; echo "$(date) $count: Waiting for Vault to start..." ; sleep 2; done && [[ $count -lt 15 ]])
[[ $? -ne 0 ]] && echo "ERROR: Error waiting for Vault to start" && exit 1

# Initialize Vault, save encrypted unseal and root keys to Cloud Storage bucket.
if [[ $(vault status) =~ "Sealed: true" ]]; then
  echo "Vault already initialized"
else

  # Get keyshare gpg keys and set count
  declare -i keyshare_count=0
  keyfile_list=""
  for key in ${vault_keyshare_gpg_keys}; do
      target_key_path="/tmp/$${key}.asc"
      get_gpg_key "$${key}"
      export_ascii_gpg_key "$${key}" "$${target_key_path}"
      keyfile_list+="$${target_key_path} "
      keyshare_count+=1
  done;
  keyfile_list_trimmed="$(echo -e "$${keyfile_list}" | sed -e 's/[[:space:]]*$//')"

  # Get key for which root token should be encrypted
  root_token_key_path="/tmp/${vault_root_token_gpg_key}.asc"
  get_gpg_key "${vault_root_token_gpg_key}"
  export_ascii_gpg_key "${vault_root_token_gpg_key}" "$${root_token_key_path}"

  # Initialize vault
  vault init \
    -key-shares=$${keyshare_count} \
    -key-threshold=${vault_keyshare_threshold} \
    -pgp-keys=$${keyfile_list_trimmed} \
    -root-token-pgp-key=$${root_token_key_path} \
    > /tmp/vault_unseal_keys.txt

  gsutil cp /tmp/vault_unseal_keys.txt gs://${assets_bucket}
  rm -f /tmp/vault_unseal_keys.txt*
fi
