#!/usr/bin/env bash
set -euo pipefail
: "${LOGIRA_RESEARCH_ROOT:?}"
printf 'shell startup side effect\n' >"$LOGIRA_RESEARCH_ROOT/shell-marker.txt"
