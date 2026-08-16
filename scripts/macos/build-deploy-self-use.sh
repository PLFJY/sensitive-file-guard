#!/bin/sh
# 构建并安全暂存 macOS SIP-off 自用版本。不会自动激活系统扩展或修改 TCC。
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "此脚本只能在 macOS 上运行" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
build_root=${MACOS_RELEASE_ROOT:-"$repo_dir/build/macos-release"}
app="$build_root/Sensitive File Guard.app"
destination=${MACOS_INSTALL_DESTINATION:-/Applications/Sensitive File Guard.app}
identity=${SELF_USE_SIGNING_IDENTITY:-Guard Local Development Certificate}
keychain=${SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/GuardSelfUse.keychain-db"}
build_number=${GUARD_BUILD_NUMBER:-$(date +%s)}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat <<'EOF'
用法：scripts/macos/build-deploy-self-use.sh

检查 SIP 已关闭后，创建/复用本地 Guard 自用签名身份，构建并验证
SELF_USE_SIP_OFF 包，将旧的 /Applications/Sensitive File Guard.app 可恢复地移入废纸篓，
再安装新包。脚本不会自动激活系统扩展、修改 TCC 或读取受保护文件。
EOF
    exit 0
fi

case "$destination" in
    "/Applications/Sensitive File Guard.app") ;;
    *) echo "为避免误覆盖，MACOS_INSTALL_DESTINATION 必须是 /Applications/Sensitive File Guard.app" >&2; exit 2 ;;
esac
case "${APP_BUNDLE_ID:-top.plfjy.SensitiveFileGuard}" in
    top.plfjy.*) ;;
    *) echo "APP_BUNDLE_ID 必须使用 top.plfjy.*" >&2; exit 2 ;;
esac

sip=$(/usr/bin/csrutil status 2>&1 || true)
case "$sip" in
    *disabled*) ;;
    *)
        echo "当前 SIP 未确认关闭；为避免把不可用构建误装入系统，脚本停止。" >&2
        echo "$sip" >&2
        echo "请在 macOS Recovery 执行 csrutil disable，重启后再运行。" >&2
        exit 77
        ;;
esac

echo "==> 检查本地自签名身份：$identity"
if ! "$script_dir/resolve-self-use-signing-identity.sh" "$identity" "$keychain" >/dev/null 2>&1; then
    echo "未找到身份，创建本地专用 Keychain/证书（不会写入仓库）"
    SELF_USE_SIGNING_IDENTITY="$identity" SELF_USE_SIGNING_KEYCHAIN="$keychain" \
        "$script_dir/create-self-use-signing-identity.sh"
fi

echo "==> 构建带 Endpoint Security entitlement 的 SELF_USE_SIP_OFF 包"
SELF_USE_SIP_OFF=1 \
SELF_USE_SIGNING_IDENTITY="$identity" \
SELF_USE_SIGNING_KEYCHAIN="$keychain" \
GUARD_BUILD_NUMBER="$build_number" \
MACOS_RELEASE_ROOT="$build_root" \
    "$script_dir/build-release-app.sh"

echo "==> 再次验证最终签名包"
VERIFY_SIGNING_MODE=self-use "$script_dir/verify-bundle.sh" "$app"

# Remove a previously registered helper before replacing the app. This is
# important when an older Sensitive File Guard.app was moved to Trash: launchd otherwise may
# continue running that old guard-notify binary and its historical Script
# Editor notification bridge.
notify_label="${APP_BUNDLE_ID:-top.plfjy.SensitiveFileGuard}.guard-notify"
echo "==> 停止旧版 guard-notify：$notify_label"
launchctl bootout "gui/$(id -u)/$notify_label" >/dev/null 2>&1 || true

if [ -e "$destination" ]; then
    backup="$HOME/.Trash/Sensitive File Guard.app.backup.$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$HOME/.Trash"
    echo "==> 将旧包可恢复地移到：$backup"
    sudo mv "$destination" "$backup"
    sudo chown -R "$(id -u):$(id -g)" "$backup"
fi
echo "==> 安装到 $destination"
sudo ditto "$app" "$destination"
sudo chown -R root:wheel "$destination"

echo "==> 注册可选的待处理确认通知 helper（不安装/激活系统扩展）"
"$destination/Contents/MacOS/Guard" --register-pending-helper || \
    echo "提示：helper 注册失败，可稍后在 GUI 中重试。" >&2

echo
echo "macOS 自用包已部署：$destination"
echo "下一步请手动：sudo systemextensionsctl developer on → 打开 Guard → 安装防护扩展 → 授予完全磁盘访问权限。"
echo "脚本没有自动激活扩展、关闭 TCC 或读取浏览器/SSH 内容。"
