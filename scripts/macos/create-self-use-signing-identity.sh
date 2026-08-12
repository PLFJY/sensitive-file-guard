#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "create-self-use-signing-identity.sh requires macOS" >&2
    exit 2
fi

identity=${SELF_USE_SIGNING_IDENTITY:-Guard Local Development Certificate}
keychain=${SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/GuardSelfUse.keychain-db"}
password_service=top.plfjy.SensitiveFileGuard.self-use-keychain
password_account=$keychain
# Read-only compatibility for a keychain created before the product identifier
# moved to top.plfjy. New and updated credentials are stored only under the new
# service name.
legacy_password_service=io.github.plfjy.SensitiveFileGuard.self-use-keychain

for command_name in openssl security; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

store_password() {
    if security find-generic-password -a "$password_account" \
        -s "$password_service" >/dev/null 2>&1; then
        security add-generic-password -U -a "$password_account" \
            -s "$password_service" -w "$password"
    else
        security add-generic-password -a "$password_account" \
            -s "$password_service" -w "$password"
    fi
}

resolved=$("$(dirname "$0")/resolve-self-use-signing-identity.sh" \
    "$identity" "$keychain" 2>/dev/null || true)

if [ -f "$keychain" ]; then
    password=
    credential_source=
    for candidate in \
        "$password_service|$password_account" \
        "$password_service|$USER" \
        "$legacy_password_service|$USER"
    do
        service=${candidate%%|*}
        account=${candidate#*|}
        candidate_password=$(security find-generic-password \
            -a "$account" -s "$service" -w 2>/dev/null || true)
        if [ -n "$candidate_password" ] && \
            security unlock-keychain -p "$candidate_password" "$keychain" \
                >/dev/null 2>&1; then
            password=$candidate_password
            credential_source=$candidate
            break
        fi
    done
    unset candidate_password
    test -n "$password" || {
        echo "stored credentials cannot unlock the existing self-use keychain: $keychain" >&2
        echo "Do not enter the macOS login password. Preserve this keychain and create a new one at a different path." >&2
        exit 2
    }
    if [ "$credential_source" != "$password_service|$password_account" ]; then
        store_password
        echo "migrated self-use Keychain credential to its path-scoped account"
    fi
else
    password=$(openssl rand -hex 32)
    security create-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    store_password
fi
security unlock-keychain -p "$password" "$keychain" >/dev/null

if [ -n "$resolved" ]; then
    # The dedicated keychain has a generated password, not the user's login
    # password. Refresh codesign's non-interactive ACL for an existing key.
    security set-key-partition-list -S apple-tool:,apple: -s \
        -k "$password" "$keychain" >/dev/null
    unset password
    echo "existing self-use signing identity: $identity ($resolved)"
    exit 0
fi

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
security set-key-partition-list -S apple-tool:,apple: -s \
    -k "$password" "$keychain" >/dev/null
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
