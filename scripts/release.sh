#!/usr/bin/env bash
# 构建 release 产物并发布到 GitLab Generic Package Registry + Release。
#
# 发布目标仓库必须与源码仓库区分：本仓库（RainbowXie/rustFrida）只做构建，
# 产物落在 codexcoda/rustfrida（独立公开工程），避免与 SeamlessHook-rustFrida 那条
# 路线共用同一工程而互相覆盖产物。
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: release.sh --version <x.y.z> [--repo PATH] [--ndk PATH]
                  [--gitlab-host HOST] [--project PATH] [--dry-run]

构建 release profile 的 rustfrida + libqbdi_helper.so，打包为
rustfrida-<version>-android-arm64.tar.gz（内含 SHA256SUMS），上传到
Generic Package Registry，并创建同名 GitLab Release。

凭据按序取用：--token、GITLAB_TOKEN、~/.git-credentials。
EOF
}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=""
ndk=""
gitlab_host="100.107.133.118:9080"
project="codexcoda/rustfrida"
token=""
dry_run=0

while (($#)); do
  case "$1" in
    --version) version=${2:?missing value for --version}; shift 2 ;;
    --repo) repo=$(realpath "${2:?missing value for --repo}"); shift 2 ;;
    --ndk) ndk=${2:?missing value for --ndk}; shift 2 ;;
    --gitlab-host) gitlab_host=${2:?missing value for --gitlab-host}; shift 2 ;;
    --project) project=${2:?missing value for --project}; shift 2 ;;
    --token) token=${2:?missing value for --token}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$version" ]]; then
  echo "--version is required" >&2
  exit 2
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "--version must be x.y.z, got: $version" >&2
  exit 2
fi
for required in rust_frida/Cargo.toml agent/Cargo.toml loader/loader.py; do
  if [[ ! -e "$repo/$required" ]]; then
    echo "Not a rustFrida repository: missing $repo/$required" >&2
    exit 1
  fi
done

# cxx 静态库是 libqbdi_helper.so 的链接输入，LFS 指针会让链接产出错误的库。
qbdi_archive="$repo/qbdi/libQBDI.a"
if [[ ! -s "$qbdi_archive" ]]; then
  echo "qbdi/libQBDI.a is missing" >&2
  exit 1
fi
if head -c 64 "$qbdi_archive" | grep -q 'git-lfs'; then
  echo "qbdi/libQBDI.a is still an LFS pointer; run: git lfs pull --include='qbdi/libQBDI.a'" >&2
  exit 1
fi

if [[ -z "$ndk" ]]; then
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "${NDK_PATH:-}"; do
    if [[ -n "$candidate" && -f "$candidate/source.properties" ]]; then
      ndk=$candidate
      break
    fi
  done
fi
if [[ -z "$ndk" ]]; then
  for base in "$HOME/Android/Sdk/ndk" "$HOME/Android/sdk/ndk"; do
    [[ -d "$base" ]] || continue
    ndk=$(find "$base" -mindepth 1 -maxdepth 1 -type d -name '*.*' | sort -V | tail -1)
    [[ -n "$ndk" ]] && break
  done
fi
if [[ -z "$ndk" || ! -f "$ndk/source.properties" ]]; then
  echo "Android NDK not found. Pass --ndk or set ANDROID_NDK_HOME." >&2
  exit 1
fi
ndk=$(realpath "$ndk")

# 工具链目录必须进 PATH：.cargo/config.toml 只写命令名，不写机器专属绝对路径。
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64"
export PATH="$toolchain/bin:$PATH"
export ANDROID_NDK_HOME="$ndk" ANDROID_NDK_ROOT="$ndk" NDK_PATH="$ndk"
export CARGO_BUILD_TARGET="aarch64-linux-android"

cd "$repo"
if [[ ! -f quickjs-hook/quickjs-src/quickjs.c ]]; then
  git submodule update --init --recursive quickjs-hook/quickjs-src
fi
# loader.bin 仅在缺失时构建会因为源码改动被静默忽略；改成源码比产物新就重建。
if [[ ! -f loader/build/loader.bin || loader/loader.c -nt loader/build/loader.bin ]]; then
  python3 loader/loader.py --ndk "$ndk" --api 33
fi
# 独立枚举探针：源码变更后必须重建，否则 probe 模式会跑到旧探针。
if [[ ! -f loader/build/probe.so || loader/probe_so.c -nt loader/build/probe.so ]]; then
  python3 loader/build_probe_so.py --ndk "$ndk" --api 33
fi

echo "== 构建 release 产物 =="
cargo build -p qbdi-helper --release
cargo build -p agent --no-default-features --features quickjs,qbdi --release
cargo build -p rust_frida --features qbdi --release

out_dir="$repo/target/aarch64-linux-android/release"
host_bin="$out_dir/rustfrida"
helper_so="$out_dir/libqbdi_helper.so"
for artifact in "$host_bin" "$helper_so"; do
  if [[ ! -f "$artifact" ]]; then
    echo "expected release artifact missing: $artifact" >&2
    exit 1
  fi
done

# 产物必须是能给 ARM64 Android 用的，否则发布出去只会在设备上失败。
for artifact in "$host_bin" "$helper_so"; do
  if ! file "$artifact" | grep -q 'ARM aarch64'; then
    echo "release artifact is not ARM aarch64: $artifact" >&2
    file "$artifact" >&2
    exit 1
  fi
done

# cdylib 允许带未定义符号链接成功，缺陷会推迟到设备 dlopen 才暴露。
# __clear_cache 由 compiler-rt builtins 提供，bionic 不导出，必须确认已静态链入。
agent_so=$(dirname "$host_bin")/libagent.so
if [[ -f "$agent_so" ]]; then
  nm_tool=$(find "$toolchain/bin" -maxdepth 1 -name 'llvm-nm' | head -1)
  if [[ -n "$nm_tool" ]]; then
    for so in "$agent_so" "$helper_so"; do
      if "$nm_tool" -D --undefined-only "$so" 2>/dev/null | grep -qw '__clear_cache'; then
        echo "undefined __clear_cache in $so: it would fail at dlopen on device" >&2
        echo "compiler-rt builtins were not linked; check build-support/compiler_rt.rs" >&2
        exit 1
      fi
    done
  fi
fi

package="rustfrida"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
install -m 0755 "$host_bin" "$staging/rustfrida"
install -m 0644 "$helper_so" "$staging/libqbdi_helper.so"
(
  cd "$staging"
  sha256sum rustfrida libqbdi_helper.so > SHA256SUMS
)
archive_name="rustfrida-${version}-android-arm64.tar.gz"
archive="$staging/$archive_name"
tar -C "$staging" -czf "$archive" rustfrida libqbdi_helper.so SHA256SUMS

archive_sha=$(sha256sum "$archive" | cut -d' ' -f1)
echo "archive: $archive_name"
echo "sha256:  $archive_sha"

if ((dry_run)); then
  echo "--dry-run: 跳过上传。"
  exit 0
fi

if [[ -z "$token" ]]; then
  token=${GITLAB_TOKEN:-}
fi
if [[ -z "$token" ]]; then
  # 存量 PAT 可能只存在于 git credential store；glab 配置里的 token 会过期。
  # 该 store 会把 host 的冒号写成 %3a，所以两种形式都要匹配。
  host_alt=${gitlab_host//./\.}
  token=$(grep -oP "(?<=codexcoda:)[^@]+(?=@${host_alt//:/%3a}|@${host_alt})" \
    "$HOME/.git-credentials" 2>/dev/null | head -1 || true)
fi
if [[ -z "$token" ]]; then
  echo "no GitLab token: pass --token, set GITLAB_TOKEN, or add ~/.git-credentials" >&2
  exit 1
fi

api="http://$gitlab_host/api/v4"
project_enc=${project//\//%2F}
package_url="$api/projects/$project_enc/packages/generic/$package/$version/$archive_name"

echo "== 上传到 Generic Package Registry =="
curl -sS --fail-with-body \
  -H "PRIVATE-TOKEN: $token" \
  --upload-file "$archive" \
  "$package_url" >/dev/null
echo "uploaded: $package_url"

# 回读并比对 SHA256：上传成功不等于远端字节与本地一致。
remote_sha=$(curl -sS --fail-with-body "$package_url" | sha256sum | cut -d' ' -f1)
if [[ "$remote_sha" != "$archive_sha" ]]; then
  echo "remote archive sha256 mismatch: local=$archive_sha remote=$remote_sha" >&2
  exit 1
fi
echo "remote sha256 verified"

echo "== 创建 GitLab Release =="
tag="v$version"
if curl -sS -o /dev/null -w '%{http_code}' -H "PRIVATE-TOKEN: $token" \
     "$api/projects/$project_enc/repository/tags/$tag" | grep -q '^200$'; then
  echo "tag $tag already exists, skipping tag creation"
else
  curl -sS --fail-with-body -X POST -H "PRIVATE-TOKEN: $token" \
    "$api/projects/$project_enc/repository/tags" \
    --data-urlencode "tag_name=$tag" \
    --data-urlencode "ref=main" \
    --data-urlencode "message=rustfrida $version" >/dev/null
fi

if curl -sS -o /dev/null -w '%{http_code}' -H "PRIVATE-TOKEN: $token" \
     "$api/projects/$project_enc/releases/$tag" | grep -q '^200$'; then
  echo "release $tag already exists, skipping release creation"
else
  curl -sS --fail-with-body -X POST -H "PRIVATE-TOKEN: $token" \
    "$api/projects/$project_enc/releases" \
    --data-urlencode "name=rustfrida $version" \
    --data-urlencode "tag_name=$tag" \
    --data-urlencode "ref=main" \
    --data-urlencode "description=rustfrida $version (android arm64). Assets: rustfrida, libqbdi_helper.so, SHA256SUMS." >/dev/null
fi

# 资产链接让使用者不必拼 Generic Registry 路径，换版本时只改 tag。
curl -sS --fail-with-body -X POST -H "PRIVATE-TOKEN: $token" \
  "$api/projects/$project_enc/releases/$tag/assets/links" \
  --data-urlencode "name=$archive_name" \
  --data-urlencode "url=$package_url" >/dev/null

release_url="http://$gitlab_host/$project/-/releases/$tag"
echo
echo "release: $release_url"
echo "asset:   $package_url"
echo "sha256:  $archive_sha"
