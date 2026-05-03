"""Aggregates signal results into a final score and verdict."""

from models import SignalResult

# Thresholds are checked highest-first; first match wins. Scores below 10 fall through to "Safe".
VERDICT_THRESHOLDS = [
    (70, "Malicious"),
    (30, "High Risk"),
    (10, "Suspicious"),
]


def _verdict(score: int) -> str:
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return "Safe"


def score_email(results: list) -> dict:
    """Aggregate signal results into a final score and verdict.

    Returns a dict with keys:
      - score: int (sum of weights of triggered signals)
      - verdict: str (one of "Safe", "Suspicious", "High Risk", "Malicious")
      - signals: list of dicts for each result (all signals, triggered and not)
    """
    score = sum(r.weight for r in results if r.triggered)
    return {
        "score": score,
        "verdict": _verdict(score),
        "signals": [
            {
                "name": r.signal_name,
                "triggered": r.triggered,
                "explanation": r.explanation,
                "weight": r.weight,
            }
            for r in results
        ],
    }
