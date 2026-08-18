#!/bin/sh
# Creates (or confirms) the macOS self-use code-signing identity directly in
# the login Keychain.
#
# Deliberately NO standalone Keychain and NO separate password: the login
# Keychain is unlocked by the system at login, and the private key is imported
# with an allow-all-applications ACL so codesign works non-interactively
# without any password entry. The XPC SigningRequirements are derived at
# runtime from the running extension's own signature
# (SigningRequirements::current_process), so replacing the certificate needs
# no code change - only a rebuilt and re-activated extension.
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "create-self-use-signing-identity.sh requires macOS" >&2
    exit 2
fi

identity=${SELF_USE_SIGNING_IDENTITY:-Guard Local Development Certificate}
keychain=${SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/login.keychain-db"}

for command_name in openssl security codesign; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

if security find-certificate -c "$identity" "$keychain" >/dev/null 2>&1; then
    line=$(security find-identity -v -p codesigning "$keychain" | grep -F "\"$identity\"" || true)
    if [ -n "$line" ]; then
        printf '%s\n' "$line"
        echo "existing self-use signing identity: $identity in $keychain"
        exit 0
    fi
    echo "identity exists in $keychain but is not usable; delete it and re-run" >&2
    exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/guard-local-identity.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj "/CN=$identity" -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' -addext 'extendedKeyUsage=critical,codeSigning' \
    -keyout "$work/key.pem" -out "$work/certificate.pem" 2>/dev/null
openssl pkcs12 -export -legacy -passout pass:guard-local-import -name "$identity" \
    -inkey "$work/key.pem" -in "$work/certificate.pem" -out "$work/identity.p12"
security import "$work/identity.p12" -k "$keychain" -f pkcs12 \
    -P guard-local-import -A
security add-trusted-cert -d -r trustRoot -p codeSign -k "$keychain" "$work/certificate.pem"

line=$(security find-identity -v -p codesigning "$keychain" | grep -F "\"$identity\"" || true)
test -n "$line" || {
    echo "local certificate was imported but is not a usable code-signing identity" >&2
    exit 2
}
printf '%s\n' "$line"
echo "created local identity in login Keychain: $identity"
echo "self-use signing keychain: $keychain (system-unlocked, no separate password)"