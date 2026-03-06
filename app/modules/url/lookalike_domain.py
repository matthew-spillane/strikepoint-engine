from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

try:
    from rapidfuzz import fuzz
except ImportError:
    try:
        from thefuzz import fuzz  # type: ignore[no-redef]
    except ImportError:
        fuzz = None  # type: ignore[assignment]

POPULAR_BRANDS = [
    "google", "facebook", "paypal", "apple", "amazon", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "chase",
    "wellsfargo", "bankofamerica",
]

SIMILARITY_THRESHOLD = 80


async def scan(url: str) -> ModuleResult:
    if not settings.lookalike_domain_enabled:
        return ModuleResult(module="lookalike_domain", status="skipped")

    if fuzz is None:
        return ModuleResult(module="lookalike_domain", status="skipped", findings={"error": "fuzz library not installed"})

    try:
        hostname = urlparse(url).hostname or ""
        # Strip TLD for comparison — take the main domain part
        domain_parts = hostname.split(".")
        # Use the second-level domain for matching
        if len(domain_parts) >= 2:
            domain_name = domain_parts[-2]
        else:
            domain_name = hostname

        matches = []
        for brand in POPULAR_BRANDS:
            # Skip exact matches — that's likely the real site
            if domain_name.lower() == brand:
                continue
            similarity = fuzz.ratio(domain_name.lower(), brand)
            if similarity >= SIMILARITY_THRESHOLD:
                matches.append({"brand": brand, "similarity": similarity})

        detected = len(matches) > 0

        return ModuleResult(
            module="lookalike_domain",
            status="completed",
            findings={"matches": matches, "domain_checked": domain_name},
            score_contribution=25 if detected else 0,
        )
    except Exception as e:
        return ModuleResult(module="lookalike_domain", status="error", findings={"error": str(e)})
