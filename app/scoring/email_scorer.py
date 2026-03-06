from app.models import ModuleResult


def compute_verdict(score: int) -> str:
    if score <= 25:
        return "Safe"
    elif score <= 50:
        return "Suspicious"
    elif score <= 74:
        return "Likely Phishing"
    else:
        return "Phishing"


def score_email(modules: list[ModuleResult]) -> tuple[int, str]:
    """Compute aggregate risk score from email module results. Returns (score, verdict)."""
    total = sum(m.score_contribution for m in modules)
    total = min(total, 100)
    return total, compute_verdict(total)
