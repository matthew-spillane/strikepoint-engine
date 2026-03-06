from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

MAX_HOPS = 10


async def scan(url: str) -> ModuleResult:
    if not settings.redirect_chain_enabled:
        return ModuleResult(module="redirect_chain", status="skipped")

    if httpx is None:
        return ModuleResult(module="redirect_chain", status="skipped", findings={"error": "httpx not installed"})

    try:
        chain: list[str] = [url]
        current = url

        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            for _ in range(MAX_HOPS):
                resp = await client.get(current)
                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    # Handle relative redirects
                    if location.startswith("/"):
                        parsed = urlparse(current)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    chain.append(location)
                    current = location
                else:
                    break

        hop_count = len(chain) - 1
        domains = [urlparse(u).hostname for u in chain]
        unique_domains = set(domains)
        cross_domain = len(unique_domains) > 1

        suspicious = hop_count > 3 or cross_domain
        score = 10 if suspicious else 0

        return ModuleResult(
            module="redirect_chain",
            status="completed",
            findings={
                "chain": chain,
                "hop_count": hop_count,
                "cross_domain": cross_domain,
                "unique_domains": list(unique_domains),
            },
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="redirect_chain", status="error", findings={"error": str(e)})
