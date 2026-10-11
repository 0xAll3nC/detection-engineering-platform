from __future__ import annotations

import pytest

from detection_platform.sigma.evaluator import UnsupportedSigmaFeature, evaluate_condition

R = {"selection_a": True, "selection_b": False, "filter_x": False, "filter_y": True}


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("selection_a", True),
        ("selection_b", False),
        ("selection_a and selection_b", False),
        ("selection_a or selection_b", True),
        ("not selection_b", True),
        ("not not selection_a", True),
        ("selection_a and not filter_x", True),
        ("selection_a and not filter_y", False),
        ("1 of selection_*", True),
        ("2 of selection_*", False),
        ("all of selection_*", False),
        ("all of selection_* and not filter_x", False),
        ("(1 of selection_*) and not filter_x", True),
        ("1 of them", True),
        ("all of them", False),
        ("selection_b or selection_a and filter_x", False),  # and binds tighter than or
        ("(selection_b or selection_a) and not filter_x", True),
    ],
)
def test_condition_semantics(condition, expected):
    assert evaluate_condition(condition, R) is expected


@pytest.mark.parametrize(
    "condition",
    [
        "selection_a and",
        "(selection_a",
        "selection_a )",
        "unknown_selection",
        "1 of nomatch_*",
        "selection_a | count() > 5",
        "__import__('os')",
    ],
)
def test_invalid_or_unsupported_conditions_raise(condition):
    with pytest.raises(UnsupportedSigmaFeature):
        evaluate_condition(condition, R)
