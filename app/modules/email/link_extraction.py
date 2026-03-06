import email
import re

from app.config import settings
from app.models import ModuleResult


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

        # Run URL scans if a scanning function is provided
        url_results = []
        if url_scan_func and urls:
            for u in urls[:10]:  # Limit to 10 URLs
                result = await url_scan_func(u)
                url_results.append(result)

        # Score: based on highest URL risk found
        max_url_score = 0
        if url_results:
            max_url_score = max(r.get("risk_score", 0) for r in url_results)

        return ModuleResult(
            module="link_extraction",
            status="completed",
            findings={
                "urls_found": urls,
                "url_count": len(urls),
                "url_scan_results": url_results if url_results else None,
                "highest_url_risk": max_url_score,
            },
            score_contribution=min(max_url_score, 40),
        )
    except Exception as e:
        return ModuleResult(module="link_extraction", status="error", findings={"error": str(e)})
