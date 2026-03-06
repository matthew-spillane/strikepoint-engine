from app.config import settings
from app.models import ModuleResult

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "paypal", "apple", "amazon", "microsoft", "password",
    "signin", "credential", "suspend", "validate",
]


async def scan(url: str) -> ModuleResult:
    if not settings.keyword_detection_enabled:
        return ModuleResult(module="keyword_detection", status="skipped")

    try:
        url_lower = url.lower()
        matched = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]

        raw_score = len(matched) * 5
        score = min(raw_score, 15)  # cap at 15

        return ModuleResult(
            module="keyword_detection",
            status="completed",
            findings={"matched_keywords": matched, "count": len(matched)},
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="keyword_detection", status="error", findings={"error": str(e)})
