#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "create-self-use-signing-identity.sh requires macOS" >&2
    exit 2
fi

identity=${SELF_USE_SIGNING_IDENTITY:-Guard Local Development Certificate}
keychain=${SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/GuardSelfUse.keychain-db"}
password_service=io.github.plfjy.SensitiveFileGuard.self-use-keychain

resolved=$("$(dirname "$0")/resolve-self-use-signing-identity.sh" \
    "$identity" "$keychain" 2>/dev/null) && {
    echo "existing self-use signing identity: $identity ($resolved)"
    exit 0
}

for command_name in openssl security; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

if [ -f "$keychain" ]; then
    password=$(security find-generic-password -a "$USER" -s "$password_service" -w 2>/dev/null) || {
        echo "existing self-use keychain password is unavailable from the login keychain: $keychain" >&2
        exit 2
    }
else
    password=$(openssl rand -hex 32)
    security create-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security add-generic-password -U -a "$USER" -s "$password_service" -w "$password"
fi
security unlock-keychain -p "$password" "$keychain"

work=$(mktemp -d "${TMPDIR:-/tmp}/guard-local-identity.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj "/CN=$identity" -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=critical,codeSigning' \
    -keyout "$work/key.pem" -out "$work/certificate.pem"
openssl pkcs12 -export -legacy -passout pass:guard-local-import -name "$identity" \
    -inkey "$work/key.pem" -in "$work/certificate.pem" -out "$work/identity.p12"
security import "$work/identity.p12" -k "$keychain" -f pkcs12 \
    -P guard-local-import -T /usr/bin/codesign
security add-trusted-cert -r trustRoot -p codeSign -k "$keychain" "$work/certificate.pem"
security set-key-partition-list -S apple-tool:,apple: -s -k "$password" "$keychain"
security list-keychains -d user -s "$keychain" "$HOME/Library/Keychains/login.keychain-db"
identity_line=$(security find-identity -v -p codesigning "$keychain" | grep -F "\"$identity\"" || true)
test -n "$identity_line" || {
    echo "local certificate was imported but is not a valid code-signing identity" >&2
    exit 2
}
printf '%s\n' "$identity_line"
echo "created local identity: $identity"
echo "self-use signing keychain: $keychain"
echo "Keep this certificate and private key in the local Keychain. Do not commit or bundle it."
