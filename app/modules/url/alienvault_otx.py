from urllib.parse import quote

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


async def scan(url: str) -> ModuleResult:
    if not settings.otx_enabled:
        return ModuleResult(module="alienvault_otx", status="skipped")

    if httpx is None:
        return ModuleResult(module="alienvault_otx", status="skipped", findings={"error": "httpx not installed"})

    api_key = settings.OTX_API_KEY
    if not api_key:
        return ModuleResult(
            module="alienvault_otx",
            status="skipped",
            findings={"detail": "OTX_API_KEY not configured"},
        )

    try:
        encoded_url = quote(url, safe="")
        headers = {"X-OTX-API-KEY": api_key}

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general",
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        tags = list({tag for p in pulses[:10] for tag in p.get("tags", [])})

        if pulse_count >= 4:
            score = 25
        elif pulse_count >= 1:
            score = 15
        else:
            score = 0

        return ModuleResult(
            module="alienvault_otx",
            status="completed",
            findings={"pulse_count": pulse_count, "tags": tags[:20]},
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="alienvault_otx", status="error", findings={"error": str(e)})
