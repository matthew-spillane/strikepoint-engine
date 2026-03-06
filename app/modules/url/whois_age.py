from datetime import datetime, timezone
from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

try:
    import whois as python_whois
except ImportError:
    python_whois = None  # type: ignore[assignment]


async def scan(url: str) -> ModuleResult:
    if not settings.whois_enabled:
        return ModuleResult(module="whois_age", status="skipped")

    if python_whois is None:
        return ModuleResult(module="whois_age", status="skipped", findings={"error": "python-whois not installed"})

    try:
        domain = urlparse(url).hostname or ""
        w = python_whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return ModuleResult(
                module="whois_age",
                status="completed",
                findings={"domain": domain, "creation_date": None, "age_days": None},
                score_contribution=0,
            )

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        if age_days < 30:
            score = 20
            risk = "high"
        elif age_days < 180:
            score = 10
            risk = "medium"
        else:
            score = 0
            risk = "low"

        return ModuleResult(
            module="whois_age",
            status="completed",
            findings={
                "domain": domain,
                "creation_date": creation_date.isoformat(),
                "age_days": age_days,
                "risk": risk,
            },
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="whois_age", status="error", findings={"error": str(e)})
