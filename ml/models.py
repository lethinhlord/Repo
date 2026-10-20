from __future__ import annotations

from typing import Any

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


def build_candidates(config: dict[str, Any], *, random_seed: int) -> dict[str, Any]:
    model_config = config["models"]
    logistic = model_config["logistic_regression"]
    forest = model_config["random_forest"]
    boosting = model_config["xgboost"]
    return {
        "logistic_regression": Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "model",
                    LogisticRegression(
                        C=float(logistic["C"]),
                        max_iter=int(logistic["max_iter"]),
                        class_weight="balanced",
                        random_state=random_seed,
                    ),
                ),
            ]
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=int(forest["n_estimators"]),
            min_samples_leaf=int(forest["min_samples_leaf"]),
            max_features=forest["max_features"],
            class_weight="balanced_subsample",
            random_state=random_seed,
            n_jobs=1,
        ),
        "xgboost": XGBClassifier(
            objective="binary:logistic",
            eval_metric="logloss",
            tree_method="hist",
            n_estimators=int(boosting["n_estimators"]),
            max_depth=int(boosting["max_depth"]),
            learning_rate=float(boosting["learning_rate"]),
            subsample=float(boosting["subsample"]),
            colsample_bytree=float(boosting["colsample_bytree"]),
            random_state=random_seed,
            n_jobs=1,
        ),
    }
