from urllib.parse import quote_plus

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


async def scan(url: str) -> ModuleResult:
    if not settings.ipqualityscore_enabled:
        return ModuleResult(module="ipqualityscore", status="skipped")

    if httpx is None:
        return ModuleResult(module="ipqualityscore", status="skipped", findings={"error": "httpx not installed"})

    try:
        encoded_url = quote_plus(url)
        api_key = settings.IPQUALITYSCORE_API_KEY
        endpoint = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(endpoint, params={"strictness": 0})
            resp.raise_for_status()
            data = resp.json()

        if not data.get("success", False):
            return ModuleResult(
                module="ipqualityscore",
                status="skipped",
                findings={"detail": data.get("message", "IPQS returned success=false")},
            )

        # Extract fields
        is_unsafe = data.get("unsafe", False)
        is_phishing = data.get("phishing", False)
        is_malware = data.get("malware", False)
        is_suspicious = data.get("suspicious", False)
        risk_score = data.get("risk_score", 0)
        domain_age = data.get("domain_age", {})
        domain_age_human = domain_age.get("human") if isinstance(domain_age, dict) else None
        dns_valid = data.get("dns_valid", True)
        is_parking = data.get("parking", False)
        is_spamming = data.get("spamming", False)
        category = data.get("category")
        domain_rank = data.get("domain_rank", 0)
        risky_tld = data.get("risky_tld", False)

        # Scoring
        score = 0

        if is_phishing or is_malware:
            score += 35

        if is_unsafe:
            score += 30

        if is_suspicious:
            score += 15

        if risk_score >= 85:
            score += 25
        elif risk_score >= 50:
            score += 15

        if is_parking or is_spamming:
            score += 10

        if domain_rank == 0:
            score += 5

        if risky_tld:
            score += 10

        findings = {
            "unsafe": is_unsafe,
            "phishing": is_phishing,
            "malware": is_malware,
            "suspicious": is_suspicious,
            "risk_score": risk_score,
            "domain_age": domain_age_human,
            "dns_valid": dns_valid,
            "parking": is_parking,
            "spamming": is_spamming,
            "category": category,
            "domain_rank": domain_rank,
            "risky_tld": risky_tld,
        }

        return ModuleResult(
            module="ipqualityscore",
            status="completed",
            findings=findings,
            score_contribution=min(score, 50),
        )
    except Exception as e:
        return ModuleResult(module="ipqualityscore", status="error", findings={"error": str(e)})
