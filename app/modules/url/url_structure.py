import re
from urllib.parse import urlparse, unquote

from app.config import settings
from app.models import ModuleResult

UNCOMMON_TLDS = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf"]


async def scan(url: str) -> ModuleResult:
    if not settings.url_structure_enabled:
        return ModuleResult(module="url_structure", status="skipped")

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        flags: list[str] = []

        # Excessive subdomains (3+)
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 3:
            flags.append("excessive_subdomains")

        # IP-based URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            flags.append("ip_based_url")

        # URL length over 100
        if len(url) > 100:
            flags.append("long_url")

        # URL-encoded characters
        if url != unquote(url):
            flags.append("url_encoded_chars")

        # Uncommon TLDs
        for tld in UNCOMMON_TLDS:
            if hostname.endswith(tld):
                flags.append(f"uncommon_tld_{tld}")
                break

        # @ symbol in URL
        if "@" in url:
            flags.append("at_symbol_in_url")

        raw_score = len(flags) * 5
        score = min(raw_score, 20)  # cap at 20

        return ModuleResult(
            module="url_structure",
            status="completed",
            findings={"flags": flags, "flag_count": len(flags)},
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="url_structure", status="error", findings={"error": str(e)})
