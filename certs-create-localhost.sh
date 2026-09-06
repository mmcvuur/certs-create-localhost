#!/usr/bin/env bash

set -euo pipefail

# ===== Settings you may tweak =====
COMMON_NAME_CA="Local Dev Root CA"
COMMON_NAME_LEAF="localhost"
DAYS_CA=3652                       # 10 years for the CA
DAYS_LEAF=397                      # Safari/macos cap: <= 825 days; 397 is a safe pick
OUT_DIR="${PWD}/certs-localhost"   # Where to place the issued certs for nginx
CA_DIR="${HOME}/.localCA"          # Where to keep your CA key/cert
KEY_BITS=4096

# ===== Derived paths =====
CA_KEY="${CA_DIR}/rootCA.key"
CA_PEM="${CA_DIR}/rootCA.pem"
CA_SRL="${CA_DIR}/rootCA.srl"

LEAF_KEY="${OUT_DIR}/${COMMON_NAME_LEAF}.key"
LEAF_CSR="${OUT_DIR}/${COMMON_NAME_LEAF}.csr"
LEAF_CRT="${OUT_DIR}/${COMMON_NAME_LEAF}.crt"
LEAF_FULLCHAIN="${OUT_DIR}/${COMMON_NAME_LEAF}-fullchain.pem"

OPENSSL_CNF_TMP="$(mktemp /tmp/openssl-localhost.XXXXXX.cnf)"

# ===== Helpers =====
have() { command -v "$1" >/dev/null 2>&1; }

err() { printf "\n\033[31mERROR:\033[0m %s\n" "$*" >&2; exit 1; }

title() { printf "\n\033[36m==>\033[0m %s\n" "$*"; }

# ===== Checks =====
have openssl || err "openssl not found. Install Xcode CLT or 'brew install openssl'."
have security || err "macOS 'security' tool not found."

mkdir -p "$OUT_DIR" "$CA_DIR"

# ===== Create a CA if missing =====
if [[ ! -f "$CA_KEY" || ! -f "$CA_PEM" ]]; then
  title "Generating local CA (stored in ${CA_DIR})"
  openssl genrsa -out "$CA_KEY" "$KEY_BITS"
  # Create a minimal CA cert
  openssl req -x509 -new -nodes -key "$CA_KEY" \
    -sha256 -days "$DAYS_CA" \
    -subj "/CN=${COMMON_NAME_CA}" \
    -out "$CA_PEM"

  title "Trusting the CA in the macOS System keychain (admin password may be required)"
#  sudo security add-trusted-cert -d -r trustRoot \
#    -k /Library/Keychains/System.keychain "$CA_PEM"
else
  title "Using existing CA: ${CA_PEM}"
  # Ensure it’s trusted; if not present, add it
  if ! security find-certificate -c "$COMMON_NAME_CA" /Library/Keychains/System.keychain >/dev/null 2>&1; then
    title "Trusting existing CA in System keychain (admin password may be required)"
#    sudo security add-trusted-cert -d -r trustRoot \
#      -k /Library/Keychains/System.keychain "$CA_PEM"
  fi
fi

# ===== Build an OpenSSL config with SANs =====
cat > "$OPENSSL_CNF_TMP" <<'EOF'
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = __COMMON_NAME__

[ req_ext ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1

[ v3_ext ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment
EOF

# Inject the common name
sed -i '' "s/__COMMON_NAME__/${COMMON_NAME_LEAF}/" "$OPENSSL_CNF_TMP" 2>/dev/null || \
  sed -i "s/__COMMON_NAME__/${COMMON_NAME_LEAF}/" "$OPENSSL_CNF_TMP"

# ===== Generate leaf key + CSR =====
title "Creating leaf key and CSR for ${COMMON_NAME_LEAF}"
openssl genrsa -out "$LEAF_KEY" "$KEY_BITS"
chmod 600 "$LEAF_KEY"

openssl req -new -key "$LEAF_KEY" \
  -out "$LEAF_CSR" \
  -config "$OPENSSL_CNF_TMP"

# ===== Sign with the CA =====
title "Signing certificate with the local CA"
openssl x509 -req -in "$LEAF_CSR" \
  -CA "$CA_PEM" -CAkey "$CA_KEY" -CAcreateserial -CAserial "$CA_SRL" \
  -out "$LEAF_CRT" -days "$DAYS_LEAF" -sha256 \
  -extfile "$OPENSSL_CNF_TMP" -extensions v3_ext

# ===== Make a fullchain for nginx =====
cat "$LEAF_CRT" "$CA_PEM" > "$LEAF_FULLCHAIN"

# ===== Verify =====
title "Verifying the new certificate"
openssl verify -CAfile "$CA_PEM" "$LEAF_CRT"

# ===== Done =====
rm -f "$OPENSSL_CNF_TMP"
printf "\n\033[32mSuccess!\033[0m Created:\n"
printf "  Key:       %s\n" "$LEAF_KEY"
printf "  Cert:      %s\n" "$LEAF_CRT"
printf "  Fullchain: %s\n" "$LEAF_FULLCHAIN"

cat <<NGINX

Use in nginx (example):

    server {
        listen 443 ssl;
        server_name localhost;

        ssl_certificate     ${LEAF_FULLCHAIN};
        ssl_certificate_key ${LEAF_KEY};

        # Recommended modern settings
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        location / {
            proxy_pass http://127.0.0.1:5000;
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }

Reload nginx after updating the config:

    sudo nginx -t && sudo nginx -s reload

NGINX

printf "\nIf you ever need to remove the CA trust:\n"
printf "  sudo security remove-trusted-cert -d \"%s\"\n" "$CA_PEM"
