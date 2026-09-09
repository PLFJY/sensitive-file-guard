#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "create-self-use-signing-identity.sh requires macOS" >&2
    exit 2
fi

identity=${SFG_SELF_USE_SIGNING_IDENTITY:-'Sensitive File Guard Local Development'}
keychain=${SFG_SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/SensitiveFileGuardSelfUse.keychain-db"}
login_keychain="$HOME/Library/Keychains/login.keychain-db"
password_service=top.plfjy.SensitiveFileGuard.self-use-keychain
password_account=$keychain
legacy_password_service=io.github.plfjy.SensitiveFileGuard.self-use-keychain

for command_name in openssl security; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "missing required command: $command_name" >&2
        exit 2
    }
done

store_password_in_login_keychain() {
    security add-generic-password -U \
        -a "$password_account" \
        -s "$password_service" \
        -w "$password" \
        "$login_keychain"
}

load_and_verify_saved_password() {
    for candidate in \
        "$password_service|$password_account" \
        "$password_service|$USER" \
        "$legacy_password_service|$USER"
    do
        service=${candidate%%|*}
        account=${candidate#*|}
        candidate_password=$(security find-generic-password \
            -a "$account" -s "$service" -w "$login_keychain" 2>/dev/null || true)
        if [ -n "$candidate_password" ] && \
            security unlock-keychain -p "$candidate_password" "$keychain" \
                >/dev/null 2>&1; then
            password=$candidate_password
            credential_source=$candidate
            unset candidate_password
            return 0
        fi
    done
    unset candidate_password
    return 1
}

ensure_keychain_in_user_search_list() {
    search_list=$(security list-keychains -d user)
    if printf '%s\n' "$search_list" | \
        sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//' | \
        grep -F -x "$keychain" >/dev/null; then
        return 0
    fi

    set -- "$keychain"
    while IFS= read -r listed_keychain; do
        listed_keychain=$(printf '%s\n' "$listed_keychain" | \
            sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')
        if [ -n "$listed_keychain" ] && [ "$listed_keychain" != "$keychain" ]; then
            set -- "$@" "$listed_keychain"
        fi
    done <<EOF
$search_list
EOF
    security list-keychains -d user -s "$@"
}

if [ -e "$keychain" ]; then
    password=
    credential_source=
    if ! load_and_verify_saved_password; then
        echo "cannot unlock existing self-use signing keychain: $keychain" >&2
        echo "its generated password is missing from the login keychain or no longer matches" >&2
        echo "the script will not delete or replace an existing signing identity" >&2
        echo "move the keychain aside explicitly before creating a replacement" >&2
        exit 2
    fi
    if [ "$credential_source" != "$password_service|$password_account" ]; then
        store_password_in_login_keychain
        echo "migrated self-use keychain credential to its path-scoped login-keychain item"
    fi
else
    password=$(openssl rand -hex 32)
    security create-keychain -p "$password" "$keychain"
    chmod 600 "$keychain"
    security unlock-keychain -p "$password" "$keychain"
    # The dedicated keychain may lock on sleep or after six hours. Build
    # scripts unlock it from the separately stored login-keychain credential.
    security set-keychain-settings -lut 21600 "$keychain"
    if ! store_password_in_login_keychain; then
        echo "could not save the generated password in the login keychain" >&2
        echo "removing the newly created, otherwise unrecoverable keychain" >&2
        security delete-keychain "$keychain" >/dev/null 2>&1 || true
        exit 2
    fi
fi

ensure_keychain_in_user_search_list

resolved=$("$(dirname "$0")/resolve-self-use-signing-identity.sh" \
    "$identity" "$keychain" 2>/dev/null || true)
if [ -n "$resolved" ]; then
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
    -subj "/CN=$identity/O=Sensitive File Guard/OU=Development" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=critical,codeSigning' \
    -keyout "$work/key.pem" -out "$work/certificate.pem"
openssl pkcs12 -export -legacy -passout pass:guard-local-import \
    -name "$identity" -inkey "$work/key.pem" -in "$work/certificate.pem" \
    -out "$work/identity.p12"
security import "$work/identity.p12" -k "$keychain" -f pkcs12 \
    -P guard-local-import -T /usr/bin/codesign
security add-trusted-cert -r trustRoot -p codeSign \
    -k "$login_keychain" "$work/certificate.pem"
security set-key-partition-list -S apple-tool:,apple: -s \
    -k "$password" "$keychain" >/dev/null
unset password

resolved=$("$(dirname "$0")/resolve-self-use-signing-identity.sh" \
    "$identity" "$keychain")
echo "created local identity: $identity ($resolved)"
echo "self-use signing keychain: $keychain"
echo "the generated keychain password is stored only in the login keychain"
