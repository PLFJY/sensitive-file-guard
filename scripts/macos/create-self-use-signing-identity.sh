#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "create-self-use-signing-identity.sh requires macOS" >&2
    exit 2
fi

identity=${SELF_USE_SIGNING_IDENTITY:-Guard Local Development Certificate}
keychain=${SELF_USE_KEYCHAIN:-"$HOME/Library/Keychains/login.keychain-db"}

security find-identity -v -p codesigning "$keychain" | grep -F "\"$identity\"" >/dev/null 2>&1 && {
    echo "existing self-use signing identity: $identity"
    exit 0
}

for command_name in openssl security; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/guard-local-identity.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj "/CN=$identity" \
    -keyout "$work/key.pem" -out "$work/certificate.pem"
openssl pkcs12 -export -passout pass: -name "$identity" \
    -inkey "$work/key.pem" -in "$work/certificate.pem" -out "$work/identity.p12"
security import "$work/identity.p12" -k "$keychain" -P '' -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k '' "$keychain"
security find-identity -v -p codesigning "$keychain" | grep -F "\"$identity\""
echo "created local identity: $identity"
echo "Keep this certificate and private key in the local Keychain. Do not commit or bundle it."
