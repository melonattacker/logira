#!/usr/bin/env bash
set -euo pipefail

# logira local installer (bundled inside the release tarball).
# This script assumes a fixed directory layout next to itself:
#   bin/logira
#   bin/logirad
#   bpf/exec/trace_bpfel.o
#   bpf/net/trace_bpfel.o
#   bpf/file/trace_bpfel.o
#   systemd/logirad.service

PROG="logira-install-local"

usage() {
  cat <<'EOF'
logira local installer (run as root)

Usage:
  sudo ./install-local.sh [options]

Options:
  --prefix-bin <path>    Install binaries under this dir (default: /usr/local/bin).
  --prefix-lib <path>    Install libs under this dir (default: /usr/local/lib/logira).
  --systemd-unit <path>  Install systemd unit to this path (default: /etc/systemd/system/logirad.service).
  --env-file <path>      Write environment file to this path (default: /etc/logira/logirad.env).
  -h, --help             Show this help.
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

escape_sed_repl() {
  # Escape '&' and '\' and delimiter '|' for safe sed replacement.
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

main() {
  local prefix_bin="/usr/local/bin"
  local prefix_lib="/usr/local/lib/logira"
  local systemd_unit="/etc/systemd/system/logirad.service"
  local env_file="/etc/logira/logirad.env"

  while [ $# -gt 0 ]; do
    case "$1" in
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

  need_cmd install
  need_cmd mkdir
  need_cmd sed
  need_cmd systemctl
  need_cmd mktemp
  need_cmd basename
  need_cmd grep
  need_cmd chmod
  need_cmd dirname

  is_root || die "must be run as root"

  local script_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

  local src_logira="${script_dir}/bin/logira"
  local src_logirad="${script_dir}/bin/logirad"
  local src_exec_o="${script_dir}/bpf/exec/trace_bpfel.o"
  local src_net_o="${script_dir}/bpf/net/trace_bpfel.o"
  local src_file_o="${script_dir}/bpf/file/trace_bpfel.o"
  local src_unit="${script_dir}/systemd/logirad.service"

  [ -f "$src_logira" ] || die "missing file: $src_logira"
  [ -f "$src_logirad" ] || die "missing file: $src_logirad"
  [ -f "$src_exec_o" ] || die "missing file: $src_exec_o"
  [ -f "$src_net_o" ] || die "missing file: $src_net_o"
  [ -f "$src_file_o" ] || die "missing file: $src_file_o"
  [ -f "$src_unit" ] || die "missing file: $src_unit"

  echo "$PROG: installing binaries to $prefix_bin" >&2
  install -d -m 0755 "$prefix_bin"
  install -m 0755 "$src_logira" "${prefix_bin}/logira"
  install -m 0755 "$src_logirad" "${prefix_bin}/logirad"

  echo "$PROG: installing BPF objects to $prefix_lib/bpf" >&2
  install -d -m 0755 "${prefix_lib}/bpf/exec" "${prefix_lib}/bpf/net" "${prefix_lib}/bpf/file"
  install -m 0644 "$src_exec_o" "${prefix_lib}/bpf/exec/trace_bpfel.o"
  install -m 0644 "$src_net_o" "${prefix_lib}/bpf/net/trace_bpfel.o"
  install -m 0644 "$src_file_o" "${prefix_lib}/bpf/file/trace_bpfel.o"

  echo "$PROG: writing env file to $env_file" >&2
  install -d -m 0755 "$(dirname -- "$env_file")"
  cat >"$env_file" <<EOF
LOGIRA_EXEC_BPF_OBJ=${prefix_lib}/bpf/exec/trace_bpfel.o
LOGIRA_NET_BPF_OBJ=${prefix_lib}/bpf/net/trace_bpfel.o
LOGIRA_FILE_BPF_OBJ=${prefix_lib}/bpf/file/trace_bpfel.o
EOF
  chmod 0644 "$env_file"

  echo "$PROG: installing systemd unit to $systemd_unit" >&2
  install -d -m 0755 "$(dirname -- "$systemd_unit")"

  # Patch unit template to use chosen prefixes and env file.
  local esc_prefix_bin esc_env_file
  esc_prefix_bin="$(escape_sed_repl "$prefix_bin")"
  esc_env_file="$(escape_sed_repl "$env_file")"

  # Ensure template contains the lines we intend to patch.
  grep -qE '^[[:space:]]*ExecStart=' "$src_unit" || die "unit template missing ExecStart= line: $src_unit"
  grep -qE '^[[:space:]]*EnvironmentFile=' "$src_unit" || die "unit template missing EnvironmentFile= line: $src_unit"

  local tmp_unit
  tmp_unit="$(mktemp)"
  trap 'if [ -n "${tmp_unit:-}" ] && [ -e "${tmp_unit:-}" ]; then rm -f -- "$tmp_unit"; fi' EXIT

  sed \
    -e "s|^[[:space:]]*ExecStart=.*$|ExecStart=${esc_prefix_bin}/logirad|g" \
    -e "s|^[[:space:]]*EnvironmentFile=.*$|EnvironmentFile=-${esc_env_file}|g" \
    "$src_unit" >"$tmp_unit"

  install -m 0644 "$tmp_unit" "$systemd_unit"

  local unit_name
  unit_name="$(basename -- "$systemd_unit")"

  echo "$PROG: enabling and starting $unit_name" >&2
  systemctl daemon-reload
  systemctl enable --now "$unit_name"

  echo >&2
  systemctl status "$unit_name" --no-pager >&2 || true
  echo >&2
  "${prefix_bin}/logira" status >&2 || true

  echo "$PROG: done" >&2
}

main "$@"
