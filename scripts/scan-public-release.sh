#!/usr/bin/env bash
set -euo pipefail
if ! command -v gitleaks >/dev/null; then
  tool_dir=$(mktemp -d)
  trap 'rm -rf -- "$tool_dir"' EXIT
  GOBIN="$tool_dir" go install github.com/zricethezav/gitleaks/v8@v8.30.0
  export PATH="$tool_dir:$PATH"
fi
if [[ $1 == source ]]; then
  gitleaks git --redact=100 --no-banner --log-opts='HEAD' .

  git ls-files -z | python3 scripts/scan-release-material.py --tracked
else
  gitleaks dir --redact=100 --no-banner --max-target-megabytes 32 "$1"
  "${2:-python3}" scripts/scan-release-material.py "$1"
fi
