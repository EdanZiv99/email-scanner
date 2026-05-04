"""Aggregates signal results into a final score and verdict."""

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


def compute_verdict_and_score(signal_dicts: list) -> dict:
    """Compute score and verdict from a list of signal dicts.

    Each dict must have at minimum: triggered (bool), weight (int),
    trump_card (bool), name (str).
    """
    score = sum(s["weight"] for s in signal_dicts if s.get("triggered"))
    trump_signals = [s["name"] for s in signal_dicts if s.get("triggered") and s.get("trump_card")]
    trump_card_triggered = bool(trump_signals)
    verdict = "Malicious" if trump_card_triggered else _verdict(score)
    return {
        "score": score,
        "verdict": verdict,
        "trump_card_triggered": trump_card_triggered,
        "trump_signals": trump_signals,
    }


def score_email(results: list) -> dict:
    """Aggregate signal results into a final score and verdict.

    Returns a dict with keys:
      - score: int (sum of weights of triggered signals)
      - verdict: str (one of "Safe", "Suspicious", "High Risk", "Malicious")
      - signals: list of dicts for each result (all signals, triggered and not)
      - trump_card_triggered: bool
      - trump_signals: list of signal names that fired as trump cards
    """
    signal_dicts = [
        {
            "name": r.signal_name,
            "category": r.category,
            "triggered": r.triggered,
            "explanation": r.explanation,
            "weight": r.weight,
            "trump_card": r.trump_card,
            "metadata": r.metadata,
        }
        for r in results
    ]
    computed = compute_verdict_and_score(signal_dicts)
    return {
        **computed,
        "signals": signal_dicts,
    }
