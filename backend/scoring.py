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
      - trump_card_triggered: bool
      - trump_signals: list of signal names that fired as trump cards
    """
    score = sum(r.weight for r in results if r.triggered)

    trump_signals = [r.signal_name for r in results if r.triggered and r.trump_card]
    trump_card_triggered = bool(trump_signals)

    # Trump cards override the verdict regardless of additive score — a known-malicious
    # attachment or URL is always Malicious even if no other signals fired.
    verdict = "Malicious" if trump_card_triggered else _verdict(score)

    return {
        "score": score,
        "verdict": verdict,
        "signals": [
            {
                "name": r.signal_name,
                "triggered": r.triggered,
                "explanation": r.explanation,
                "weight": r.weight,
                "trump_card": r.trump_card,
            }
            for r in results
        ],
        "trump_card_triggered": trump_card_triggered,
        "trump_signals": trump_signals,
    }
