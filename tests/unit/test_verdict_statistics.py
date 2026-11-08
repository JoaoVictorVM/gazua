import math

import pytest

from gazua.verdicts.statistics import log_binomial_cdf, upper_bound


def direct_cdf(successes: int, trials: int, probability: float) -> float:
    """An independent sum, without logarithms, for small n."""
    return math.fsum(
        math.comb(trials, index) * probability**index * (1 - probability) ** (trials - index)
        for index in range(successes + 1)
    )


@pytest.mark.parametrize(
    ("successes", "trials", "expected"),
    [
        (0, 5, 0.4507197283),
        (0, 20, 0.1391083407),
        (1, 5, 0.6574083180),
        (0, 1, 0.95),
        (5, 5, 1.0),
        (20, 20, 1.0),
    ],
)
def test_exact_upper_bound_reference_cases(successes: int, trials: int, expected: float) -> None:
    bound = upper_bound(successes, trials)

    assert bound is not None
    assert abs(bound - expected) <= 1e-10
    assert upper_bound(0, 0) is None


def test_upper_bound_solves_binomial_tail() -> None:
    for trials in range(1, 16):
        for successes in range(trials):
            bound = upper_bound(successes, trials)
            assert bound is not None
            assert abs(direct_cdf(successes, trials, bound) - 0.05) <= 1e-9
            assert direct_cdf(successes, trials, bound - 1e-10) > 0.05 - 1e-12
            assert direct_cdf(successes, trials, bound + 1e-10) < 0.05 + 1e-12
    for successes, trials in ((0, 300), (1, 300), (150, 300), (299, 300), (1, 1000), (999, 1000)):
        bound = upper_bound(successes, trials)
        assert bound is not None
        assert math.isfinite(bound)
        assert successes / trials <= bound <= 1
        assert abs(math.exp(log_binomial_cdf(successes, trials, bound)) - 0.05) <= 1e-9
    assert log_binomial_cdf(3, 3, 1.0) == 0.0
    assert log_binomial_cdf(2, 3, 1.0) == -math.inf
    assert log_binomial_cdf(0, 3, 0.0) == 0.0


@pytest.mark.parametrize(
    ("successes", "trials", "error"),
    [
        (True, 5, TypeError),
        (1, True, TypeError),
        (1.0, 5, TypeError),
        ("1", 5, TypeError),
        (-1, 5, ValueError),
        (1, -5, ValueError),
        (6, 5, ValueError),
    ],
)
def test_invalid_counts_are_rejected(successes: object, trials: object, error: type) -> None:
    with pytest.raises(error):
        upper_bound(successes, trials)  # type: ignore[arg-type]
