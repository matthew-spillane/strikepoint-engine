import email
import re
from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

UNCOMMON_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".buzz", ".gq", ".icu"}
MAX_URLS = 10


def _suspicion_score(url: str) -> int:
    """Score a URL by how suspicious it looks. Higher = scan first."""
    score = 0
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Non-HTTPS
    if parsed.scheme != "https":
        score += 3

    # IP-based host
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 4

    # Uncommon TLD
    for tld in UNCOMMON_TLDS:
        if hostname.endswith(tld):
            score += 3
            break

    # Long URL
    if len(url) > 100:
        score += 2

    # Excessive subdomains
    if hostname.count(".") >= 3:
        score += 2

    # URL-encoded characters
    if "%" in url:
        score += 1

    # @ symbol
    if "@" in url:
        score += 3

    return score


async def scan(raw_email: str, url_scan_func=None) -> ModuleResult:
    """Extract URLs from email body and optionally run them through URL scanning."""
    if not settings.link_extraction_enabled:
        return ModuleResult(module="link_extraction", status="skipped")

    try:
        msg = email.message_from_string(raw_email)

        # Get body text
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode("utf-8", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode("utf-8", errors="replace")

        # Extract URLs
        url_pattern = r'https?://[^\s<>"\')\]}>]+'
        urls = list(set(re.findall(url_pattern, body)))

        # Prioritize most suspicious-looking URLs and cap at MAX_URLS
        urls_ranked = sorted(urls, key=_suspicion_score, reverse=True)
        urls_to_scan = urls_ranked[:MAX_URLS]

        # Run URL scans if a scanning function is provided
        url_results = []
        if url_scan_func and urls_to_scan:
            for u in urls_to_scan:
                result = await url_scan_func(u)
                url_results.append(result)

        # Score: based on highest URL risk found
        max_url_score = 0
        if url_results:
            max_url_score = max(r.get("risk_score", 0) for r in url_results)

        findings = {
            "urls_found": urls,
            "url_count": len(urls),
            "urls_scanned": len(urls_to_scan),
            "url_scan_results": url_results if url_results else None,
            "highest_url_risk": max_url_score,
        }
        if len(urls) > MAX_URLS:
            findings["note"] = f"Only top {MAX_URLS} most suspicious URLs were scanned out of {len(urls)} found"

        return ModuleResult(
            module="link_extraction",
            status="completed",
            findings=findings,
            score_contribution=min(max_url_score, 40),
        )
    except Exception as e:
        return ModuleResult(module="link_extraction", status="error", findings={"error": str(e)})
