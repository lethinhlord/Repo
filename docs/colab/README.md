# Colab client for the approved 48-run development dataset

Open [development_48runs_colab.ipynb](development_48runs_colab.ipynb) and save a
copy in Drive. It pins the already approved training source
`0fcacb145146eb9657739e76b56a870f75818ac1` and reads the same three staged files
from `MyDrive/DATN/development-3day-data/processed-development-v1`.

This client fixes the environment passed to isolated training subprocesses:
`MPLBACKEND=Agg`. Colab's kernel can export
`module://matplotlib_inline.backend_inline`; the isolated Python environment
has no inline backend entry point. Matplotlib 3.11.2 reads that variable during
its initial import, before the later `matplotlib.use("Agg")` call can run.

## Resume an existing failed session

If the EDA subprocess failed with that backend error, add a code cell before
the failed EDA cell and run:

```python
train_env["MPLBACKEND"] = "Agg"
```

Rerun the failed EDA cell, then continue through the normal quality gate and
training cells in order. Do not rerun the environment-creation cell in the same
session: it intentionally refuses existing tool/training directories. Other
errors need their own traceback; do not remove assertions or quality checks.

No data upload or dataset rebuild is needed for this backend correction.

## Source and review boundary

This is a Colab host client, stored with documentation. It checks out the exact
approved processing source before running any dataset/EDA/quality/training
commands. Its code cells differ from the original pinned notebook only in
the default approved SHA and the child backend environment variable. The EDA,
plots, dependency locks, full quality gate, grouped model training and export
code are unchanged.

The original source notebook and its immutable release remain available.
Neither the approved processing hash nor the exact dataset manifest, source
policy, feature schema, model selection or split is changed by this client.

The client does not establish external validation or automation readiness.
