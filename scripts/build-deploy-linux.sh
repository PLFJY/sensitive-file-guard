#!/usr/bin/env bash
# 一键构建并部署 Linux 版本。只在普通用户下编译，安装阶段才使用 sudo。
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_only=0
no_start=0
assume_yes=0

usage() {
  cat <<'EOF'
用法：scripts/build-deploy-linux.sh [选项]

默认流程：cargo build --release → sudo deploy/install.sh → 创建配置（仅当不存在）
→ 启动 guardd 和桌面通知服务。

选项：
  --build-only  只构建，不安装、不改变系统服务
  --no-start    安装并配置，但不启动 guardd/通知服务
  --yes         新建配置时跳过 guardctl setup 确认
  -h, --help    显示帮助
EOF
}

while (($#)); do
  case "$1" in
    --build-only) build_only=1 ;;
    --no-start) no_start=1 ;;
    --yes) assume_yes=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知选项：$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[[ "$(uname -s)" == Linux ]] || { echo "此脚本只能在 Linux 上运行" >&2; exit 2; }
command -v cargo >/dev/null || { echo "缺少 cargo" >&2; exit 2; }
cd "$repo_dir"

echo "==> 以当前普通用户构建 release（二进制不会以 root 编译）"
cargo build --release

if ((build_only)); then
  echo "完成：构建产物位于 $repo_dir/target/release/"
  exit 0
fi

command -v sudo >/dev/null || { echo "缺少 sudo；安装部署需要管理员权限" >&2; exit 2; }
echo "==> 安装 systemd、polkit、桌面文件和二进制"
sudo "$repo_dir/deploy/install.sh"

config=/etc/guardd/config.json
if [[ ! -e "$config" ]]; then
  echo "==> 首次安装：根据当前用户的已验证浏览器元数据创建配置"
  setup_args=(/usr/local/bin/guardctl setup --home "$HOME")
  if ((assume_yes)); then
    setup_args+=(--yes)
  fi
  sudo "${setup_args[@]}"
else
  echo "==> 保留已有配置：$config（部署脚本不会覆盖它）"
fi

if ((no_start)); then
  echo "完成：已安装但按 --no-start 保持服务停止。"
  exit 0
fi

echo "==> 启动防护服务"
sudo systemctl daemon-reload
sudo systemctl enable --now guardd
systemctl --user daemon-reload
systemctl --user enable --now guard-notify

echo "==> 验证服务状态"
sudo systemctl --no-pager --full status guardd || true
systemctl --user --no-pager --full status guard-notify || true
echo "Linux 部署完成。首次加入 guardd-users 后可能需要注销并重新登录。"
