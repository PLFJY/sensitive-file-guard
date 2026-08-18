#!/bin/sh
set -eu

identity=${1:?usage: resolve-self-use-signing-identity.sh IDENTITY [KEYCHAIN]}
keychain=${2:-}

case "$identity" in
    *'"'*|*'
'*)
        echo "invalid self-use signing identity" >&2
        exit 2
        ;;
esac

if [ -n "$keychain" ]; then
    identities=$(security find-identity -p codesigning "$keychain")
else
    identities=$(security find-identity -p codesigning)
fi

if printf '%s\n' "$identity" | grep -Eq '^[[:xdigit:]]{40}$'; then
    matches=$(printf '%s\n' "$identities" | grep -i -F " $identity " || true)
else
    # Match by identity name (no quote-format dependency; the identity lives in
    # the login Keychain and is trusted in the user domain). find-identity can
    # list the same identity in both the matching and valid sections, so
    # deduplicate by the 40-hex hash before counting.
    matches=$(printf '%s\n' "$identities" | grep -F "$identity" || true)
fi
matches=$(printf '%s\n' "$matches" | awk '/^[[:space:]]*[0-9]+\)/ { print $2 }' | sort -u)
count=$(printf '%s\n' "$matches" | awk 'NF { count += 1 } END { print count + 0 }')
if [ "$count" -ne 1 ]; then
    echo "self-use signing identity must resolve to exactly one valid private-key identity; found $count" >&2
    exit 2
fi

resolved=$matches
printf '%s\n' "$resolved" | grep -Eq '^[[:xdigit:]]{40}$' || {
    echo "security returned an invalid signing identity hash" >&2
    exit 2
}
printf '%s\n' "$resolved"
