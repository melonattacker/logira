#!/usr/bin/env bash
set -euo pipefail

# logira bootstrap installer.
# - Downloads a release tarball + SHA256SUMS.txt from GitHub Releases
# - Verifies sha256
# - Extracts to a temp dir
# - Runs the bundled install-local.sh as root

PROG="logira-install"
REPO_DEFAULT="melonattacker/logira"

usage() {
  cat <<'EOF'
logira bootstrap installer (Linux-only)

Usage:
  curl -fsSL https://raw.githubusercontent.com/melonattacker/logira/main/install.sh | sudo bash
  sudo ./install.sh [options]

Options:
  --version <version>    Install a specific version (vX.Y.Z or X.Y.Z). Default: latest release.
  --prefix-bin <path>    Install binaries under this dir (default: /usr/local/bin).
  --prefix-lib <path>    Install libs under this dir (default: /usr/local/lib/logira).
  --systemd-unit <path>  Install systemd unit to this path (default: /etc/systemd/system/logirad.service).
  --env-file <path>      Write environment file to this path (default: /etc/logira/logirad.env).
  -h, --help             Show this help.

Environment:
  LOGIRA_GH_REPO         Override GitHub repo "owner/repo" (default: melonattacker/logira).
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

is_root() {
  [ "$(id -u)" -eq 0 ]
}

os_check() {
  local os
  os="$(uname -s 2>/dev/null || true)"
  [ "$os" = "Linux" ] || die "Linux only (uname -s=$os)"
}

arch_slug() {
  local m
  m="$(uname -m 2>/dev/null || true)"
  case "$m" in
    x86_64) echo "linux-amd64" ;;
    aarch64|arm64) echo "linux-arm64" ;;
    *) die "unsupported architecture: $m (supported: x86_64, aarch64/arm64)" ;;
  esac
}

github_api_get_tag() {
  # Prints resolved tag (e.g. v1.2.3) based on --version or latest.
  local repo="$1"
  local tag_input="$2"

  if [ -n "$tag_input" ]; then
    if [[ "$tag_input" != v* ]]; then
      tag_input="v${tag_input}"
    fi
    echo "$tag_input"
    return 0
  fi

  local url="https://api.github.com/repos/${repo}/releases/latest"
  local body
  body="$(curl -fsSL "$url")" || die "failed to fetch latest release from GitHub API"

  local tag
  tag="$(printf '%s' "$body" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [ -n "$tag" ] || die "failed to resolve latest tag (GitHub API response did not contain tag_name)"
  echo "$tag"
}

main() {
  local repo="${LOGIRA_GH_REPO:-$REPO_DEFAULT}"
  local version=""
  local prefix_bin=""
  local prefix_lib=""
  local systemd_unit=""
  local env_file=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --version)
        [ $# -ge 2 ] || die "$1 requires an argument"
        version="$2"
        shift 2
        ;;
      --prefix-bin)
        [ $# -ge 2 ] || die "--prefix-bin requires an argument"
        prefix_bin="$2"
        shift 2
        ;;
      --prefix-lib)
        [ $# -ge 2 ] || die "--prefix-lib requires an argument"
        prefix_lib="$2"
        shift 2
        ;;
      --systemd-unit)
        [ $# -ge 2 ] || die "--systemd-unit requires an argument"
        systemd_unit="$2"
        shift 2
        ;;
      --env-file)
        [ $# -ge 2 ] || die "--env-file requires an argument"
        env_file="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  need_cmd bash
  need_cmd curl
  need_cmd tar
  need_cmd sha256sum
  need_cmd uname
  need_cmd mktemp
  need_cmd grep
  need_cmd sed
  need_cmd head

  os_check
  is_root || die "must be run as root (use: curl ... | sudo bash)"

  local arch
  arch="$(arch_slug)"

  local resolved_tag
  resolved_tag="$(github_api_get_tag "$repo" "$version")"

  local tar_name="logira_${resolved_tag}_${arch}.tar.gz"
  local sums_name="SHA256SUMS.txt"
  local base_url="https://github.com/${repo}/releases/download/${resolved_tag}"

  local tmp
  tmp="$(mktemp -d)"
  trap 'if [ -n "${tmp:-}" ] && [ -d "${tmp:-}" ]; then rm -rf -- "$tmp"; fi' EXIT

  echo "$PROG: repo=$repo tag=$resolved_tag arch=$arch" >&2
  echo "$PROG: downloading $tar_name" >&2
  curl -fsSL -o "${tmp}/${tar_name}" "${base_url}/${tar_name}" || die "download failed: ${base_url}/${tar_name}"
  echo "$PROG: downloading $sums_name" >&2
  curl -fsSL -o "${tmp}/${sums_name}" "${base_url}/${sums_name}" || die "download failed: ${base_url}/${sums_name}"

  echo "$PROG: verifying sha256" >&2
  (
    cd "$tmp"
    # Verify only the tarball line. If missing, fail.
    grep -F "  ${tar_name}" "${sums_name}" >/dev/null 2>&1 || die "SHA256SUMS.txt does not contain ${tar_name}"
    grep -F "  ${tar_name}" "${sums_name}" | sha256sum -c -
  ) || die "sha256 verification failed"

  echo "$PROG: extracting" >&2
  tar -xzf "${tmp}/${tar_name}" -C "$tmp"

  local pkg_dir="${tmp}/logira_${resolved_tag}_${arch}"
  [ -d "$pkg_dir" ] || die "expected extracted directory not found: $pkg_dir"
  [ -x "${pkg_dir}/install-local.sh" ] || die "expected installer not found: ${pkg_dir}/install-local.sh"

  echo "$PROG: running install-local.sh" >&2
  local args=()
  if [ -n "$prefix_bin" ]; then args+=(--prefix-bin "$prefix_bin"); fi
  if [ -n "$prefix_lib" ]; then args+=(--prefix-lib "$prefix_lib"); fi
  if [ -n "$systemd_unit" ]; then args+=(--systemd-unit "$systemd_unit"); fi
  if [ -n "$env_file" ]; then args+=(--env-file "$env_file"); fi

  bash "${pkg_dir}/install-local.sh" "${args[@]}"
  echo "$PROG: done" >&2
}

main "$@"
