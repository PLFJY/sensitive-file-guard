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
identity=${SFG_SELF_USE_SIGNING_IDENTITY:-'Sensitive File Guard Local Development'}
keychain=${SFG_SELF_USE_SIGNING_KEYCHAIN:-"$HOME/Library/Keychains/SensitiveFileGuardSelfUse.keychain-db"}
build_number=${GUARD_BUILD_NUMBER:-$(date +%s)}
migration_test=0

move_to_recoverable_backup() {
    source=$1
    backup=$2
    if [ "$migration_test" -eq 1 ]; then
        mv "$source" "$backup"
    else
        sudo mv "$source" "$backup"
        sudo chown -R "$(id -u):$(id -g)" "$backup"
    fi
}

stage_existing_apps() {
    target=$1
    legacy_target=$2
    trash=$3
    if [ -e "$target" ]; then
        backup="$trash/Sensitive File Guard.app.backup.$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$trash"
        echo "==> 将旧包可恢复地移到：$backup"
        move_to_recoverable_backup "$target" "$backup"
    fi
    if [ -e "$legacy_target" ]; then
        legacy_backup="$trash/Guard.app.legacy-backup.$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$trash"
        echo "==> 将旧版 Guard.app 可恢复地移到：$legacy_backup"
        move_to_recoverable_backup "$legacy_target" "$legacy_backup"
    fi
}

verify_installed_app_payload() {
    source_app=$1
    installed_app=$2
    for relative_path in \
        'Contents/Info.plist' \
        'Contents/MacOS/SensitiveFileGuard' \
        'Contents/MacOS/guard-notify'; do
        if ! cmp -s "$source_app/$relative_path" "$installed_app/$relative_path"; then
            echo "已安装包验证失败：$relative_path 与刚构建的包不一致" >&2
            return 1
        fi
    done
    VERIFY_SIGNING_MODE=self-use "$script_dir/verify-bundle.sh" "$installed_app"
    echo "已验证：/Applications 中的 GUI 与 guard-notify 已与本次构建完全一致"
}

running_pids_for_executable() {
    executable=$1
    /usr/sbin/lsof -a -t -d txt "$executable" 2>/dev/null | sort -n -u || true
}

stop_running_app_payload() {
    installed_app=$1
    host_executable="$installed_app/Contents/MacOS/SensitiveFileGuard"
    notify_executable="$installed_app/Contents/MacOS/guard-notify"
    for executable in "$host_executable" "$notify_executable"; do
        pids=$(running_pids_for_executable "$executable")
        if [ -n "$pids" ]; then
            echo "==> 停止正在运行的旧版：$executable（PID: $pids）"
            for pid in $pids; do
                kill -TERM "$pid" 2>/dev/null || true
            done
        fi
    done

    attempt=0
    while [ "$attempt" -lt 50 ]; do
        remaining_pids=
        for executable in "$host_executable" "$notify_executable"; do
            pids=$(running_pids_for_executable "$executable")
            if [ -n "$pids" ]; then
                remaining_pids="$remaining_pids $pids"
            fi
        done
        [ -z "$remaining_pids" ] && return 0
        attempt=$((attempt + 1))
        sleep 0.1
    done

    echo "旧版 GUI/helper 未在 5 秒内退出，拒绝替换正在运行的 app" >&2
    return 1
}

run_legacy_migration_test() {
    migration_test=1
    test_root=$(mktemp -d "${TMPDIR:-/tmp}/sensitive-file-guard-legacy-migration.XXXXXX")
    cleanup() { rm -rf -- "$test_root"; }
    trap cleanup EXIT HUP INT TERM
    applications="$test_root/Applications"
    trash="$test_root/Trash"
    source_app="$test_root/release/Sensitive File Guard.app"
    target="$applications/Sensitive File Guard.app"
    legacy_target="$applications/Guard.app"
    mkdir -p "$source_app" "$target" "$legacy_target"
    printf '%s\n' 'new synthetic bundle' >"$source_app/marker"
    printf '%s\n' 'prior synthetic bundle' >"$target/marker"
    printf '%s\n' 'legacy synthetic bundle' >"$legacy_target/marker"

    stage_existing_apps "$target" "$legacy_target" "$trash"
    ditto "$source_app" "$target"

    test ! -e "$legacy_target"
    test "$(cat "$target/marker")" = 'new synthetic bundle'
    prior_backup=$(find "$trash" -maxdepth 1 -type d \
        -name 'Sensitive File Guard.app.backup.*' -print -quit)
    legacy_backup=$(find "$trash" -maxdepth 1 -type d \
        -name 'Guard.app.legacy-backup.*' -print -quit)
    test -n "$prior_backup"
    test -n "$legacy_backup"
    test "$(cat "$prior_backup/marker")" = 'prior synthetic bundle'
    test "$(cat "$legacy_backup/marker")" = 'legacy synthetic bundle'
    echo "PASS: legacy Guard.app and prior Sensitive File Guard.app migrate to recoverable backups"
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    cat <<'EOF'
用法：scripts/macos/build-deploy-self-use.sh

检查 SIP 已关闭后，创建/复用本地 Guard 自用签名身份，构建并验证
SELF_USE_SIP_OFF 包，将旧的 /Applications/Sensitive File Guard.app 可恢复地移入废纸篓，
再安装新包。脚本不会自动激活系统扩展、修改 TCC 或读取受保护文件。

测试迁移逻辑（仅创建并删除 mktemp fixture，不构建、不签名、不访问 /Applications）：
  scripts/macos/build-deploy-self-use.sh --test-legacy-migration
EOF
    exit 0
fi

if [ "${1:-}" = "--test-legacy-migration" ]; then
    run_legacy_migration_test
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
    SFG_SELF_USE_SIGNING_IDENTITY="$identity" SFG_SELF_USE_SIGNING_KEYCHAIN="$keychain" \
        "$script_dir/create-self-use-signing-identity.sh"
fi

echo "==> 构建带 Endpoint Security entitlement 的 SELF_USE_SIP_OFF 包"
SELF_USE_SIP_OFF=1 \
CODESIGN_TIMESTAMP=none \
SFG_SELF_USE_SIGNING_IDENTITY="$identity" \
SFG_SELF_USE_SIGNING_KEYCHAIN="$keychain" \
GUARD_BUILD_NUMBER="$build_number" \
MACOS_RELEASE_ROOT="$build_root" \
    "$script_dir/build-release-app.sh"

echo "==> 再次验证最终签名包"
VERIFY_SIGNING_MODE=self-use "$script_dir/verify-bundle.sh" "$app"

# Authenticate before stopping the current helper or moving the installed
# app. A cancelled sudo prompt must leave the running installation untouched.
echo "==> 验证 /Applications 安装权限"
sudo -v

# Remove a previously registered helper before replacing the app. This is
# important when an older Sensitive File Guard.app was moved to Trash: launchd otherwise may
# continue running that old guard-notify binary and its historical Script
# Editor notification bridge.
notify_label="${APP_BUNDLE_ID:-top.plfjy.SensitiveFileGuard}.guard-notify"
echo "==> 停止旧版 guard-notify：$notify_label"
launchctl bootout "gui/$(id -u)/$notify_label" >/dev/null 2>&1 || true
stop_running_app_payload "$destination"

legacy_destination=/Applications/Guard.app
stage_existing_apps "$destination" "$legacy_destination" "$HOME/.Trash"
echo "==> 安装到 $destination"
sudo ditto "$app" "$destination"
sudo chown -R root:wheel "$destination"
verify_installed_app_payload "$app" "$destination"

installed_guard="$destination/Contents/MacOS/SensitiveFileGuard"
echo "==> 刷新并注册待处理确认 helper（不安装/激活系统扩展）"
# App replacement is the one place where a registered helper must be
# deliberately refreshed. Normal GUI enable operations are idempotent and do
# not unregister a healthy helper.
"$installed_guard" --unregister-pending-helper
attempt=0
while [ "$attempt" -lt 50 ]; do
    helper_status=$("$installed_guard" --pending-helper-status 2>&1 || true)
    [ "$helper_status" = NotRegistered ] && break
    attempt=$((attempt + 1))
    sleep 0.1
done
if [ "$helper_status" != NotRegistered ]; then
    echo "helper 注销未完成，停止部署：$helper_status" >&2
    exit 1
fi
if ! "$installed_guard" --register-pending-helper; then
    helper_status=$("$installed_guard" --pending-helper-status 2>&1 || true)
    echo "helper 注册失败：$helper_status" >&2
    echo "请在系统设置 → 通用 → 登录项中允许 Sensitive File Guard，然后重新运行部署脚本。" >&2
    exit 1
fi
helper_status=$("$installed_guard" --pending-helper-status 2>&1 || true)
if [ "$helper_status" != Enabled ]; then
    echo "helper 注册后未进入 Enabled：$helper_status" >&2
    exit 1
fi
attempt=0
while ! launchctl print "gui/$(id -u)/$notify_label" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 50 ]; then
        echo "helper 已注册，但 launchd 未在 5 秒内加载 $notify_label" >&2
        exit 1
    fi
    sleep 0.1
done
echo "helper 已注册并由 launchd 加载：$notify_label"

echo
echo "macOS 自用包已部署：$destination"
echo "下一步请手动：sudo systemextensionsctl developer on → 打开 Sensitive File Guard → 安装防护扩展 → 授予完全磁盘访问权限。"
echo "脚本没有自动激活扩展、关闭 TCC 或读取浏览器/SSH 内容。"
