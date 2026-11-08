"""One-sided exact (Clopper-Pearson) upper bound of an attack rate, with the standard library.

For ``k`` successes in ``n`` evaluated repetitions the bound ``U`` solves
``P(Binomial(n, U) <= k) = 1 - confidence``. The tail is summed in the log domain and inverted
by bisection, so large ``n`` stays finite. A failure to converge is an error, never a rounded
value that would look safer than the data allows.
"""

from __future__ import annotations

import math

CONFIDENCE = 0.95
ENDPOINT_TOLERANCE = 1e-12
MAX_ITERATIONS = 128


class StatisticsError(ArithmeticError):
    """The bound could not be computed to the required precision."""


def check_counts(successes: object, trials: object) -> tuple[int, int]:
    """Counts as plain integers, refusing booleans, negatives and more successes than trials."""
    if type(successes) is not int or type(trials) is not int:
        raise TypeError("Counts are integers.")
    if successes < 0 or trials < 0 or successes > trials:
        raise ValueError("Counts satisfy 0 <= successes <= trials.")
    return successes, trials


def log_binomial_cdf(successes: int, trials: int, probability: float) -> float:
    """``log P(X <= successes)`` for ``X ~ Binomial(trials, probability)``."""
    if probability <= 0.0:
        return 0.0
    if probability >= 1.0:
        return 0.0 if successes >= trials else -math.inf
    log_p, log_q = math.log(probability), math.log1p(-probability)
    base = math.lgamma(trials + 1)
    terms = [
        base
        - math.lgamma(index + 1)
        - math.lgamma(trials - index + 1)
        + index * log_p
        + (trials - index) * log_q
        for index in range(successes + 1)
    ]
    peak = max(terms)
    if peak == -math.inf:
        return -math.inf
    return peak + math.log(math.fsum(math.exp(term - peak) for term in terms))


def upper_bound(successes: int, trials: int, confidence: float = CONFIDENCE) -> float | None:
    """The one-sided upper bound, or None when nothing was evaluated."""
    successes, trials = check_counts(successes, trials)
    if not 0.0 < confidence < 1.0:
        raise ValueError("The confidence is between 0 and 1.")
    if trials == 0:
        return None
    if successes == trials:
        return 1.0
    alpha = 1.0 - confidence
    if successes == 0:
        return 1.0 - alpha ** (1.0 / trials)
    target = math.log(alpha)
    low, high = successes / trials, 1.0
    if log_binomial_cdf(successes, trials, low) <= target:
        low = 0.0
    for _ in range(MAX_ITERATIONS):
        middle = (low + high) / 2
        if log_binomial_cdf(successes, trials, middle) > target:
            low = middle
        else:
            high = middle
        if high - low <= ENDPOINT_TOLERANCE:
            break
    else:
        raise StatisticsError("The upper bound did not converge.")
    bound = (low + high) / 2
    if not math.isfinite(bound) or not successes / trials <= bound <= 1.0:
        raise StatisticsError("The upper bound is outside its valid range.")
    return bound
