from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


async def scan(url: str) -> ModuleResult:
    if not settings.phishtank_enabled:
        return ModuleResult(module="phishtank", status="skipped")

    if httpx is None:
        return ModuleResult(module="phishtank", status="skipped", findings={"error": "httpx not installed"})

    try:
        data = {
            "url": url,
            "format": "json",
        }
        if settings.PHISHTANK_API_KEY:
            data["app_key"] = settings.PHISHTANK_API_KEY

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=data,
            )
            resp.raise_for_status()
            result = resp.json()

        results = result.get("results", {})
        in_database = results.get("in_database", False)
        is_phish = results.get("valid", False) if in_database else False

        return ModuleResult(
            module="phishtank",
            status="completed",
            findings={"in_database": in_database, "is_phish": is_phish},
            score_contribution=40 if is_phish else 0,
        )
    except Exception as e:
        return ModuleResult(module="phishtank", status="error", findings={"error": str(e)})
