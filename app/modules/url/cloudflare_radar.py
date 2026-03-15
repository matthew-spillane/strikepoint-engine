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
        # Correct Cloudflare URL Scanner endpoint (no /v2, no /result)
        base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner"

        submit_url = f"{base_url}/scan"
        logger.info("[CF_RADAR] Submit URL: %s", submit_url)
        logger.info("[CF_RADAR] Account ID present: %s", bool(account_id))
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

            if not isinstance(submit_data, dict):
                logger.error("[CF_RADAR] Submission JSON is not a dict: %r", type(submit_data).__name__)
                return ModuleResult(
                    module="cloudflare_radar",
                    status="error",
                    findings={"error": "Unexpected submission response type", "response_body": submit.text[:500]},
                )

            # uuid may be at submit_data["result"]["uuid"] (envelope) or submit_data["uuid"] (flat)
            result_field = submit_data.get("result", submit_data)
            if isinstance(result_field, dict):
                scan_id = result_field.get("uuid")
            else:
                scan_id = submit_data.get("uuid")

            if not scan_id:
                logger.error("[CF_RADAR] No uuid found in submission response: %s", submit.text[:500])
                return ModuleResult(
                    module="cloudflare_radar",
                    status="error",
                    findings={"error": "No scan ID (uuid) in submission response", "response_body": submit.text[:500]},
                )

            logger.info("[CF_RADAR] Scan submitted, uuid=%s — starting poll", scan_id)

            # Poll for results — correct endpoint is /scan/{uuid}
            elapsed = 0
            while elapsed < POLL_TIMEOUT:
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL

                poll_url = f"{base_url}/scan/{scan_id}"
                poll = await client.get(poll_url, headers=headers)
                logger.info(
                    "[CF_RADAR] Poll %d/%ds: status=%d body=%s",
                    elapsed,
                    POLL_TIMEOUT,
                    poll.status_code,
                    poll.text[:500],
                )

                if poll.status_code == 200:
                    poll_body = poll.json()

                    # Guard: poll.json() might return a string (e.g. "pending")
                    if not isinstance(poll_body, dict):
                        logger.info("[CF_RADAR] Poll returned non-dict JSON (%s), continuing", type(poll_body).__name__)
                        continue

                    # Scan data may be at top level or nested under "result"
                    scan_data = poll_body.get("result", poll_body)
                    if not isinstance(scan_data, dict):
                        # "result" was a string status like "pending"
                        scan_data = poll_body

                    # Check if we have actual scan data (not just a status wrapper)
                    if isinstance(scan_data, dict) and any(
                        k in scan_data for k in ("verdicts", "scan", "page", "meta")
                    ):
                        logger.info("[CF_RADAR] Got final scan data, parsing")
                        return _parse_result(scan_data)

                    logger.info("[CF_RADAR] Poll 200 but no scan data keys yet, continuing")

                elif poll.status_code >= 400:
                    logger.info("[CF_RADAR] Poll returned %d, scan still processing", poll.status_code)

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
    verdicts = data.get("verdicts", {})
    if isinstance(verdicts, dict):
        verdicts = verdicts.get("overall", {})
    if not isinstance(verdicts, dict):
        verdicts = {}

    meta = data.get("meta", {})
    if isinstance(meta, dict):
        meta = meta.get("processors", {})
    if not isinstance(meta, dict):
        meta = {}

    page = data.get("page", {})
    if not isinstance(page, dict):
        page = {}

    lists = data.get("lists", {})
    if not isinstance(lists, dict):
        lists = {}

    is_malicious = verdicts.get("malicious", False)
    phishing_info = meta.get("phishing", {})
    phishing_detected = bool(phishing_info) and isinstance(phishing_info, dict) and phishing_info.get("detected", False)
    domain_categories = meta.get("domainCategories", [])
    radar_rank_obj = meta.get("radarRank", {})
    radar_rank = radar_rank_obj.get("rank", 0) if isinstance(radar_rank_obj, dict) else 0
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
