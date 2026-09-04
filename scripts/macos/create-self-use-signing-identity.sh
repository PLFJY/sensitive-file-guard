#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "create-self-use-signing-identity.sh requires macOS" >&2
    exit 2
fi

identity=${SFG_SELF_USE_SIGNING_IDENTITY:-'Sensitive File Guard Local Development'}
keychain=${SFG_SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/SensitiveFileGuardSelfUse.keychain-db"}
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

replace_unrecoverable_keychain() {
    echo "无法使用登录 Keychain 中保存的凭据解锁现有专用 Keychain：$keychain" >&2
    echo "接下来 macOS 会要求输入该专用 Keychain 的密码，不是 macOS 登录密码。" >&2
    echo "密码正确后，脚本会再次确认是否移除旧 Keychain 并重新创建。" >&2
    if ! security unlock-keychain "$keychain"; then
        echo "专用 Keychain 解锁失败，保留原文件并停止。" >&2
        return 1
    fi

    printf '确认移除旧专用 Keychain 并重新创建？[y/N] '
    confirmation=
    IFS= read -r confirmation || true
    case "$confirmation" in
        y|Y|yes|YES|Yes) ;;
        *)
            echo "已取消，保留原专用 Keychain。" >&2
            return 1
            ;;
    esac

    security delete-keychain "$keychain" || {
        echo "移除旧专用 Keychain 失败，保留现有状态。" >&2
        return 1
    }
    test ! -e "$keychain" || {
        echo "移除旧专用 Keychain 后文件仍存在，停止重建。" >&2
        return 1
    }
    echo "旧专用 Keychain 已移除，将在原路径创建新的 Keychain。"
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
        replace_unrecoverable_keychain || exit 2
        password=$(openssl rand -hex 32)
        security create-keychain -p "$password" "$keychain"
        security set-keychain-settings -lut 21600 "$keychain"
        store_password
        resolved=
    }
    if [ -n "${credential_source:-}" ] && \
        [ "$credential_source" != "$password_service|$password_account" ]; then
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
