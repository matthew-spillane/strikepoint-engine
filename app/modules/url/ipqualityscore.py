import json
import logging
import traceback
from urllib.parse import quote_plus

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


async def scan(url: str) -> ModuleResult:
    if not settings.ipqualityscore_enabled:
        return ModuleResult(module="ipqualityscore", status="skipped")

    if httpx is None:
        return ModuleResult(module="ipqualityscore", status="skipped", findings={"error": "httpx not installed"})

    try:
        api_key = (settings.IPQUALITYSCORE_API_KEY or "").strip()
        if not api_key:
            return ModuleResult(
                module="ipqualityscore",
                status="skipped",
                findings={"detail": "IPQUALITYSCORE_API_KEY not configured"},
            )

        encoded_url = quote_plus(url)
        endpoint = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"
        masked_endpoint = endpoint.replace(api_key, "***")

        logger.info("[IPQS] Request URL: %s", masked_endpoint)
        logger.info("[IPQS] Params: strictness=0")

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(endpoint, params={"strictness": 0})
            logger.info("[IPQS] Response status: %d", resp.status_code)
            logger.info("[IPQS] Response body (first 500 chars): %s", resp.text[:500])

            resp.raise_for_status()

            raw_text = resp.text.strip()
            if not raw_text:
                logger.error("[IPQS] Empty response body for URL: %s", url)
                return ModuleResult(
                    module="ipqualityscore",
                    status="error",
                    findings={"error": "Empty response from IPQS API"},
                )

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError) as je:
                logger.error("[IPQS] JSON decode failed: %s — raw body: %s", je, resp.text[:500])
                return ModuleResult(
                    module="ipqualityscore",
                    status="error",
                    findings={"error": f"Invalid JSON from IPQS: {je}", "response_body": resp.text[:500]},
                )

        if not isinstance(data, dict):
            logger.error("[IPQS] Response JSON is not a dict: %r", type(data).__name__)
            return ModuleResult(
                module="ipqualityscore",
                status="error",
                findings={"error": "IPQS returned non-dict JSON", "response_body": resp.text[:500]},
            )

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
        logger.error("[IPQS] Exception: %s\n%s", e, traceback.format_exc())
        return ModuleResult(module="ipqualityscore", status="error", findings={"error": str(e), "traceback": traceback.format_exc()})
