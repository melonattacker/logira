#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
logira_bin=${LOGIRA_BIN:-"$repo_root/logira"}
output=${1:-"$repo_root/research/action-residual/baseline-runs.jsonl"}
samples=${SAMPLES_PER_SCENARIO:-5}

if ! command -v jq >/dev/null 2>&1; then
  echo "collect_baseline.sh requires jq" >&2
  exit 1
fi
if ! command -v codex >/dev/null 2>&1; then
  echo "collect_baseline.sh requires codex" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")" "$repo_root/.logira-research-fixture"
touch "$output"

scenarios=(
  simple_printf
  git_status
  git_diff_stat
  go_test
  make_test
  python_subprocess
  bash_pipeline
  workspace_file
)

command_for() {
  case "$1" in
    simple_printf) printf '%s' 'printf "BASELINE_PRINTF\n"' ;;
    git_status) printf '%s' 'git status --short >/dev/null' ;;
    git_diff_stat) printf '%s' 'git diff --stat >/dev/null' ;;
    go_test) printf '%s' 'go test ./...' ;;
    make_test) printf '%s' 'make test' ;;
    python_subprocess) printf '%s' 'python3 -c '\''import subprocess; subprocess.run(["/usr/bin/true"], check=True)'\''' ;;
    bash_pipeline) printf '%s' 'printf x | tr x y >/dev/null' ;;
    workspace_file) printf '%s' 'printf baseline > .logira-research-fixture/normal-file.txt; printf append >> .logira-research-fixture/normal-file.txt' ;;
    *) echo "unknown scenario: $1" >&2; return 1 ;;
  esac
}

latest_run_id() {
  "$logira_bin" runs --json | jq -r 'sort_by(.start_ts) | last | .run_id'
}

cd "$repo_root"
for scenario in "${scenarios[@]}"; do
  existing=$(jq -r --arg scenario "$scenario" 'select(.scenario == $scenario) | .sample' "$output" | wc -l)
  sample=$((existing + 1))
  while (( sample <= samples )); do
    runtime_command=$(command_for "$scenario")
    prompt="Run exactly this one shell command and then finish. Do not combine it with another command: $runtime_command"
    echo "[baseline] $scenario $sample/$samples" >&2
    "$logira_bin" run --agent codex --net=false --summary off -- \
      codex exec --json --sandbox danger-full-access --ephemeral "$prompt" >/dev/null
    run_id=$(latest_run_id)
    jq -cn \
      --arg scenario "$scenario" \
      --argjson sample "$sample" \
      --arg run_id "$run_id" \
      --arg runtime_command "$runtime_command" \
      '{scenario:$scenario,sample:$sample,run_id:$run_id,runtime_command:$runtime_command}' >>"$output"
    sample=$((sample + 1))
  done
done
