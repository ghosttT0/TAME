#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p .external results

if [ ! -f /root/.diffagent_api.env ]; then
  cat >&2 <<'EOF'
Missing /root/.diffagent_api.env .

Create it with at least:
  export DEEPSEEK_API_KEY=...
  export DEEPSEEK_BASE_URL=https://api.deepseek.com
  export DEEPSEEK_MODEL=deepseek-chat

Then rerun this script.
EOF
  exit 1
fi

set -a
. /root/.diffagent_api.env
set +a

if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
  echo "DEEPSEEK_API_KEY is empty in /root/.diffagent_api.env" >&2
  exit 1
fi

export AIT_LOGINJECT_REPO_FALLBACK="${AIT_LOGINJECT_REPO_FALLBACK:-$ROOT/.external/log-interpretation-prompt-injection}"

python3 - <<'PY'
from loginject.real_dataset import ensure_repo
path = ensure_repo()
print(f"AIT repo ready: {path}")
PY

echo "Repro setup complete."
echo "Next steps:"
echo "  bash experiments/frozen_benchmark.sh"
echo "  bash experiments/run_tame_ablations.sh"
