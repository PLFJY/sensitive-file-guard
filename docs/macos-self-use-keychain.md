# macOS self-use signing identity

The macOS self-use (local development) build signs with a local certificate
kept directly in the **login Keychain**:

    keychain : ~/Library/Keychains/login.keychain-db
    identity : Guard Local Development Certificate
    password : none (system-unlocked at login)

There is deliberately **no standalone Keychain and no separate password**. The
login Keychain is unlocked by the system at login, and the private key is
imported with an allow-all-applications ACL, so codesign works
non-interactively with zero password entry. The certificate is trusted in the
user domain (security add-trusted-cert -d), which is what a system-extension
activation expects from a local development signature.

Recreating the identity:

    scripts/macos/create-self-use-signing-identity.sh

That script is idempotent: it confirms an existing usable identity, or
generates a fresh RSA-3072 self-signed code-signing certificate directly into
the login Keychain (import with -A ACL, then user-domain trust).

The XPC SigningRequirements are derived at runtime from the running
extension's own signature (SigningRequirements::current_process), so
replacing the certificate requires no code change - only a rebuilt and
re-activated extension. The certificate is NEVER committed or bundled; it is
a local development identity only.

Build scripts (build-dev-app.sh, build-release-app.sh) resolve the identity by
name through the default keychain search list; they contain no password or
keychain-unlock operations at all.
