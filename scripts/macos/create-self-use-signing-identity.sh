#!/bin/sh
set -eu

identity=${SFG_SELF_USE_SIGNING_IDENTITY:-"Sensitive File Guard Local Development"}
keychain=${SFG_SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/SensitiveFileGuardSelfUse.keychain-db"}

password_service="top.plfjy.SensitiveFileGuard.self-use-keychain"
password_account="$keychain"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "==> 创建新的 user Keychain"

password=$(openssl rand -hex 32)

security delete-keychain "$keychain" >/dev/null 2>&1 || true

security create-keychain \
    -p "$password" \
    "$keychain"

security unlock-keychain \
    -p "$password" \
    "$keychain"


security set-keychain-settings \
    -lut 21600 \
    "$keychain"


# 关键：恢复原设计
security add-generic-password \
    -a "$password_account" \
    -s "$password_service" \
    -w "$password" \
    "$keychain"


security list-keychains \
    -d user \
    -s \
    "$keychain" \
    "$HOME/Library/Keychains/login.keychain-db"


echo "==> 生成 code signing certificate"

openssl req \
    -new \
    -newkey rsa:3072 \
    -x509 \
    -nodes \
    -days 3650 \
    -subj "/CN=$identity/O=Sensitive File Guard/OU=Development" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=critical,codeSigning" \
    -keyout "$work/key.pem" \
    -out "$work/cert.pem"


echo "==> 创建 PKCS12"

openssl pkcs12 \
    -export \
    -legacy \
    -name "$identity" \
    -inkey "$work/key.pem" \
    -in "$work/cert.pem" \
    -passout pass:guard-p12 \
    -out "$work/signing.p12"


echo "==> 导入 identity"

security import \
    "$work/signing.p12" \
    -k "$keychain" \
    -f pkcs12 \
    -P guard-p12 \
    -T /usr/bin/codesign


echo "==> 设置 private key ACL"

security set-key-partition-list \
    -S apple-tool:,apple: \
    -s \
    -k "$password" \
    "$keychain"


echo "==> 添加 trust"

security add-trusted-cert \
    -d \
    -r trustRoot \
    -p codeSign \
    -k "$HOME/Library/Keychains/login.keychain-db" \
    "$work/cert.pem"


echo "==> 验证"

security find-identity \
    -v \
    -p codesigning \
    "$keychain"


echo "==> 完成"