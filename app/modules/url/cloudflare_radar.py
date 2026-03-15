import asyncio

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

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

        async with httpx.AsyncClient(timeout=15) as client:
            # Submit scan with unlisted visibility
            submit = await client.post(
                f"{base_url}/scan",
                json={"url": url, "visibility": "Unlisted"},
                headers=headers,
            )
            submit.raise_for_status()
            submit_data = submit.json()

            scan_id = submit_data.get("result", {}).get("uuid")
            if not scan_id:
                return ModuleResult(
                    module="cloudflare_radar",
                    status="error",
                    findings={"error": "No scan ID returned from submission"},
                )

            # Poll for results
            elapsed = 0
            while elapsed < POLL_TIMEOUT:
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL

                poll = await client.get(f"{base_url}/result/{scan_id}", headers=headers)
                if poll.status_code == 200:
                    data = poll.json().get("result", {})
                    return _parse_result(data)

            return ModuleResult(
                module="cloudflare_radar",
                status="skipped",
                findings={"detail": "Polling timed out"},
            )
    except Exception as e:
        return ModuleResult(module="cloudflare_radar", status="error", findings={"error": str(e)})


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
