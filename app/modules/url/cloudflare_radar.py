import asyncio
import logging
import traceback

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

POLL_INTERVAL = 10
POLL_TIMEOUT = 60

SUSPICIOUS_CATEGORIES = {"gambling", "adult", "newly registered", "malware", "phishing", "spam"}


async def scan(url: str) -> ModuleResult:
    if not settings.cloudflare_radar_enabled:
        return ModuleResult(module="cloudflare_radar", status="skipped")

    if httpx is None:
        return ModuleResult(module="cloudflare_radar", status="skipped", findings={"error": "httpx not installed"})

    try:
        account_id = settings.CLOUDFLARE_ACCOUNT_ID
        headers = {
            "Authorization": f"Bearer {settings.CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json",
        }
        base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2"

        submit_url = f"{base_url}/scan"
        logger.info("[CF_RADAR] Submit URL: %s", submit_url)
        logger.info("[CF_RADAR] Account ID: %s", account_id)
        logger.info("[CF_RADAR] Token present: %s", bool(settings.CLOUDFLARE_API_TOKEN))

        async with httpx.AsyncClient(timeout=15) as client:
            # Submit scan with unlisted visibility
            submit = await client.post(
                submit_url,
                json={"url": url, "visibility": "Unlisted"},
                headers=headers,
            )
            logger.info(
                "[CF_RADAR] Submission response: status=%d body=%s",
                submit.status_code,
                submit.text[:500],
            )
            submit.raise_for_status()
            submit_data = submit.json()

            result_field = submit_data.get("result")
            if not isinstance(result_field, dict):
                logger.error(
                    "[CF_RADAR] Submission 'result' is not a dict (type=%s): %s",
                    type(result_field).__name__,
                    submit.text[:500],
                )
                return ModuleResult(
                    module="cloudflare_radar",
                    status="error",
                    findings={
                        "error": "Unexpected submission response format",
                        "response_body": submit.text[:500],
                    },
                )

            scan_id = result_field.get("uuid")
            if not scan_id:
                logger.error(
                    "[CF_RADAR] Submission missing uuid key: %s", submit.text[:500]
                )
                return ModuleResult(
                    module="cloudflare_radar",
                    status="error",
                    findings={
                        "error": "No scan ID (uuid) in submission response",
                        "response_body": submit.text[:500],
                    },
                )

            logger.info("[CF_RADAR] Scan submitted, uuid=%s — starting poll", scan_id)

            # Poll for results
            elapsed = 0
            while elapsed < POLL_TIMEOUT:
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL

                poll_url = f"{base_url}/result/{scan_id}"
                poll = await client.get(poll_url, headers=headers)
                logger.info(
                    "[CF_RADAR] Poll attempt %d/%ds: status=%d body=%s",
                    elapsed,
                    POLL_TIMEOUT,
                    poll.status_code,
                    poll.text[:500],
                )
                if poll.status_code == 200:
                    poll_body = poll.json()
                    data = poll_body.get("result")
                    # Intermediate responses may return result as a string
                    # (e.g. "pending"); only parse when we get a full dict.
                    if isinstance(data, dict):
                        logger.info("[CF_RADAR] Got final dict result, parsing")
                        return _parse_result(data)
                    logger.info(
                        "[CF_RADAR] Poll returned non-dict result (type=%s), continuing",
                        type(data).__name__,
                    )

            logger.warning("[CF_RADAR] Polling timed out after %ds", POLL_TIMEOUT)
            return ModuleResult(
                module="cloudflare_radar",
                status="skipped",
                findings={"detail": "Polling timed out"},
            )
    except Exception as e:
        logger.error("[CF_RADAR] Exception: %s\n%s", e, traceback.format_exc())
        return ModuleResult(module="cloudflare_radar", status="error", findings={"error": str(e), "traceback": traceback.format_exc()})


def _parse_result(data: dict) -> ModuleResult:
    """Extract relevant fields from Cloudflare Radar scan result and compute score."""
    verdicts = data.get("verdicts", {}).get("overall", {})
    meta = data.get("meta", {}).get("processors", {})
    page = data.get("page", {})
    lists = data.get("lists", {})

    is_malicious = verdicts.get("malicious", False)
    phishing_info = meta.get("phishing", {})
    phishing_detected = bool(phishing_info) and phishing_info.get("detected", False)
    domain_categories = meta.get("domainCategories", [])
    radar_rank = meta.get("radarRank", {}).get("rank", 0)
    technologies = meta.get("wappa", [])
    redirect_chain = page.get("history", [])
    certificates = lists.get("certificates", [])
    hosting_country = page.get("country")
    hosting_asn = page.get("asn")

    # Extract category names for readability
    category_names = []
    for cat in domain_categories:
        name = cat.get("name", "") if isinstance(cat, dict) else str(cat)
        category_names.append(name.lower())

    # Scoring
    score = 0

    if is_malicious:
        score += 35

    if phishing_detected:
        score += 35

    suspicious_cats = [c for c in category_names if any(s in c for s in SUSPICIOUS_CATEGORIES)]
    if suspicious_cats:
        score += 15

    if radar_rank == 0 or radar_rank is None:
        score += 10

    findings = {
        "malicious": is_malicious,
        "phishing_detected": phishing_detected,
        "phishing_info": phishing_info if phishing_info else None,
        "domain_categories": category_names,
        "suspicious_categories": suspicious_cats if suspicious_cats else None,
        "radar_rank": radar_rank,
        "redirect_chain": redirect_chain if redirect_chain else None,
        "certificates": certificates if certificates else None,
        "technologies": [t.get("name", t) if isinstance(t, dict) else t for t in technologies[:20]] if technologies else None,
        "hosting_country": hosting_country,
        "hosting_asn": hosting_asn,
    }

    return ModuleResult(
        module="cloudflare_radar",
        status="completed",
        findings=findings,
        score_contribution=min(score, 50),
    )
