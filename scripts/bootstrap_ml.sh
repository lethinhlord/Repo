#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo 'Node.js is required for workflow regression tests; install nodejs before isolation.' >&2
  exit 1
fi
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'

python3 -m venv .venv-ml
.venv-ml/bin/python -m pip install --upgrade pip
.venv-ml/bin/python -m pip install --requirement requirements.lock
.venv-ml/bin/python -m pip install --requirement requirements-ml.lock
.venv-ml/bin/python - <<'PY'
import sklearn
import xgboost

assert sklearn.__version__ == "1.9.1"
assert xgboost.__version__ == "3.4.1"
print(f"scikit-learn={sklearn.__version__}")
print(f"xgboost={xgboost.__version__}")
print("Week 3 ML toolchain is pinned and importable; no training was performed.")
PY
