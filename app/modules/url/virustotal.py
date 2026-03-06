import base64

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


async def scan(url: str) -> ModuleResult:
    if not settings.virustotal_enabled:
        return ModuleResult(module="virustotal", status="skipped")

    if httpx is None:
        return ModuleResult(module="virustotal", status="skipped", findings={"error": "httpx not installed"})

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            )

            if resp.status_code == 404:
                return ModuleResult(
                    module="virustotal",
                    status="completed",
                    findings={"flagged_engines": 0, "total_engines": 0, "detail": "URL not found in VT database"},
                    score_contribution=0,
                )

            resp.raise_for_status()
            data = resp.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        flagged = malicious + suspicious

        return ModuleResult(
            module="virustotal",
            status="completed",
            findings={
                "flagged_engines": flagged,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
            },
            score_contribution=35 if flagged > 0 else 0,
        )
    except Exception as e:
        return ModuleResult(module="virustotal", status="error", findings={"error": str(e)})
