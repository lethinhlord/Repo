from types import SimpleNamespace

import pytest

from ml.dataset import DatasetError, _assign_cohort_folds


def test_feasible_mixed_cohorts_cover_each_fold():
    a=('account',0)
    b=('account',1)
    c=('c2',0)
    d=('c2',1)
    planted=[[{a,b},{d},{c}], [{d},{a,c},{b}], [{d},{a},{b},{c}], [{b,c,d},{a}], [{c},{a,b,d}]]
    rows={}
    for i, pattern in enumerate(p for fold in planted for p in fold):
        for family,label in pattern:
            scenario=f'{i}-{family}-{label}'
            for repeat in range(2):
                rid=f'{scenario}-{repeat}'
                rows[rid]=SimpleNamespace(scenario_id=scenario,cohort_id=str(i),family=family,label=label)
    folds=_assign_cohort_folds(rows,5,42)
    for fold in range(5):
        assert {(r.family,r.label) for k,r in rows.items() if folds[k]==fold} == {a,b,c,d}
    assert all(
        len({folds[k] for k,r in rows.items() if r.cohort_id==cohort})==1
        for cohort in {r.cohort_id for r in rows.values()}
    )


def test_infeasible_cohort_constraints_are_proved():
    rows = {}
    a=('account',0)
    b=('account',1)
    c=('c2',0)
    for i, pattern in enumerate(({a,b}, {a,c}, {b,c})):
        for family,label in pattern:
            key=f'{i}-{family}-{label}'
            rows[key]=SimpleNamespace(scenario_id=key,cohort_id=str(i),family=family,label=label)
    with pytest.raises(DatasetError, match='infeasible'):
        _assign_cohort_folds(rows,2,42)
