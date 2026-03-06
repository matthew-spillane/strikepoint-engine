import re
from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

MAX_CONTENT_SIZE = 50 * 1024  # 50KB


async def scan(url: str) -> ModuleResult:
    if not settings.page_content_enabled:
        return ModuleResult(module="page_content", status="skipped")

    if httpx is None:
        return ModuleResult(module="page_content", status="skipped", findings={"error": "httpx not installed"})

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, max_redirects=5) as client:
            resp = await client.get(url)
            html = resp.text[:MAX_CONTENT_SIZE]

        findings: dict = {}
        flags: list[str] = []
        score = 0

        # Password input fields
        has_password_input = bool(re.search(r'<input[^>]*type=["\']?password', html, re.IGNORECASE))
        findings["has_password_input"] = has_password_input

        # Login form indicators
        login_patterns = [
            r'<form[^>]*login',
            r'<form[^>]*signin',
            r'<form[^>]*log.?in',
            r'name=["\']?password',
            r'id=["\']?password',
        ]
        has_login_form = any(re.search(p, html, re.IGNORECASE) for p in login_patterns)
        findings["has_login_form"] = has_login_form

        # Form actions pointing to external domains
        source_domain = urlparse(url).hostname or ""
        form_actions = re.findall(r'<form[^>]*action=["\']?(https?://[^"\'>\s]+)', html, re.IGNORECASE)
        external_actions = [
            a for a in form_actions
            if urlparse(a).hostname and urlparse(a).hostname != source_domain
        ]
        findings["external_form_actions"] = external_actions

        if has_login_form and external_actions:
            flags.append("login_form_external_action")
            score += 20

        # Brand keyword mentions in page content — capped at +5 to avoid false positives
        brand_keywords = [
            "paypal", "apple", "amazon", "microsoft", "netflix",
            "google", "facebook", "instagram", "chase", "wellsfargo",
            "bank of america",
        ]
        brand_mentions = [kw for kw in brand_keywords if kw in html.lower()]
        findings["brand_mentions"] = brand_mentions
        if brand_mentions:
            # Only +5 max — brand mentions alone are not strong phishing signals
            flags.append("brand_keywords_in_content")
            score += 5

        findings["flags"] = flags

        return ModuleResult(
            module="page_content",
            status="completed",
            findings=findings,
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="page_content", status="error", findings={"error": str(e)})
