from app.models import ModuleResult


# Per-module weights — controls how much each module influences the final score.
# Weights for active modules are normalized to sum to 1.0 at scoring time.
MODULE_WEIGHTS: dict[str, float] = {
    # Primary signals
    "cloudflare_radar": 0.22,
    "google_safe_browsing": 0.18,
    "alienvault_otx": 0.14,
    "ipqualityscore": 0.14,
    "urlscan": 0.09,
    "virustotal": 0.05,
    "shodan_internetdb": 0.05,
    "whois_age": 0.03,
    "ssl_check": 0.02,
    # Contextual / heuristic signals
    "phishtank": 0.02,
    "redirect_chain": 0.01,
    "keyword_detection": 0.01,
    "lookalike_domain": 0.01,
    "ip_geolocation": 0.01,
    "url_structure": 0.01,
    "page_content": 0.01,
}

# Maximum score_contribution each module can emit.
# Used to normalize raw contributions to a 0–100 severity scale.
MODULE_MAX_SCORE: dict[str, int] = {
    "cloudflare_radar": 50,
    "google_safe_browsing": 40,
    "alienvault_otx": 25,
    "ipqualityscore": 50,
    "urlscan": 30,
    "virustotal": 35,
    "shodan_internetdb": 35,
    "whois_age": 20,
    "ssl_check": 15,
    "phishtank": 40,
    "redirect_chain": 10,
    "keyword_detection": 15,
    "lookalike_domain": 25,
    "ip_geolocation": 10,
    "url_structure": 20,
    "page_content": 25,
}

_DEFAULT_WEIGHT = 0.01
_DEFAULT_MAX_SCORE = 50


def compute_verdict(score: int) -> str:
    if score <= 25:
        return "Safe"
    elif score <= 50:
        return "Suspicious"
    elif score <= 74:
        return "Likely Phishing"
    else:
        return "Phishing"


def score_url(modules: list[ModuleResult]) -> tuple[int, str]:
    """Compute weighted aggregate risk score from module results.

    1. Exclude modules with status 'skipped' or 'disabled'.
    2. Normalize each module's score_contribution to 0–100 using its known max.
    3. Normalize weights of active modules so they sum to 1.0.
    4. Final score = sum(normalized_severity * normalized_weight), capped at 100.

    Returns (score, verdict).
    """
    active = [m for m in modules if m.status not in ("skipped", "disabled")]

    if not active:
        return 0, compute_verdict(0)

    # Gather raw weights for active modules
    raw_weights = {
        m.module: MODULE_WEIGHTS.get(m.module, _DEFAULT_WEIGHT)
        for m in active
    }
    weight_sum = sum(raw_weights.values())

    # Normalize so active weights sum to 1.0
    if weight_sum > 0:
        normalized_weights = {k: v / weight_sum for k, v in raw_weights.items()}
    else:
        n = len(active)
        normalized_weights = {m.module: 1.0 / n for m in active}

    # Weighted score using normalized severity per module
    total = 0.0
    for m in active:
        max_score = MODULE_MAX_SCORE.get(m.module, _DEFAULT_MAX_SCORE)
        # Normalize module's raw contribution to 0–100 severity
        severity = (m.score_contribution / max_score * 100) if max_score > 0 else 0
        severity = min(severity, 100)
        total += severity * normalized_weights.get(m.module, 0)

    score = min(int(round(total)), 100)
    return score, compute_verdict(score)
