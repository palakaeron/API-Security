from decimal import Decimal

import pytest
from app.detectors.base import Severity
from app.risk_scoring import (
    calculate_risk_score,
    get_scoring_methodology_version,
    map_risk_severity,
    normalize_confidence,
)


@pytest.mark.parametrize(
    ("factors", "expected_score", "expected_severity"),
    [
        ((85, 80, 95), 85.5, Severity.HIGH),  # BOLA
        ((80, 90, 95), 86.0, Severity.HIGH),  # BFLA
        ((75, 80, 80), 77.5, Severity.HIGH),  # BOPLA read
        ((100, 90, 95), 96.0, Severity.CRITICAL),  # BOPLA write
        ((100, 95, 95), 97.5, Severity.CRITICAL),  # broken auth bypass
        ((95, 85, 100), 93.0, Severity.CRITICAL),  # JWT weak secret
        ((50, 60, 75), 58.0, Severity.MEDIUM),  # JWT missing claims
        ((20, 35, 80), 36.5, Severity.LOW),  # missing security headers
        ((60, 85, 80), 71.5, Severity.HIGH),  # GraphQL introspection
    ],
)
def test_representative_scores(factors, expected_score, expected_severity) -> None:
    result = calculate_risk_score(*factors)

    assert result.risk_score == expected_score
    assert result.risk_severity is expected_severity
    assert result.scoring_version == "1.0"


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, Severity.INFO),
        (0.1, Severity.LOW),
        (39.9, Severity.LOW),
        (40, Severity.MEDIUM),
        (69.9, Severity.MEDIUM),
        (70, Severity.HIGH),
        (89.9, Severity.HIGH),
        (90, Severity.CRITICAL),
        (100, Severity.CRITICAL),
    ],
)
def test_severity_boundaries(score, expected) -> None:
    assert map_risk_severity(score) is expected


def test_rounding_is_decimal_half_up() -> None:
    # 0.05 is exactly the midpoint and must round upward to 0.1.
    result = calculate_risk_score(0.1, 0, 0)
    assert result.risk_score == 0.1

    result = calculate_risk_score(Decimal("89.9"), Decimal("89.9"), Decimal("90.0"))
    assert result.risk_score == 89.9


@pytest.mark.parametrize("value", [0, 100, Decimal("42.5")])
def test_confidence_normalization_accepts_valid_values(value) -> None:
    assert normalize_confidence(value) == float(value)


@pytest.mark.parametrize(
    "factors",
    [
        (-0.1, 50, 50),
        (50, 100.1, 50),
        (50, 50, -1),
        (None, 50, 50),
        (50, None, 50),
        (50, 50, None),
        (float("nan"), 50, 50),
        (50, float("inf"), 50),
        (50, 50, float("-inf")),
        (True, 50, 50),
        ("50", 50, 50),
    ],
)
def test_invalid_factors_are_rejected(factors) -> None:
    with pytest.raises(ValueError):
        calculate_risk_score(*factors)


@pytest.mark.parametrize("value", [-1, 100.1, None, float("nan"), float("inf")])
def test_invalid_confidence_is_rejected(value) -> None:
    with pytest.raises(ValueError):
        normalize_confidence(value)


def test_invalid_severity_score_is_rejected() -> None:
    with pytest.raises(ValueError):
        map_risk_severity(100.1)


def test_scoring_methodology_version() -> None:
    assert get_scoring_methodology_version() == "1.0"
