from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]


async def scan(url: str) -> ModuleResult:
    if not settings.google_safe_browsing_enabled:
        return ModuleResult(module="google_safe_browsing", status="skipped")

    if httpx is None:
        return ModuleResult(module="google_safe_browsing", status="skipped", findings={"error": "httpx not installed"})

    try:
        payload = {
            "client": {"clientId": "strikepoint-engine", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        matches = data.get("matches", [])
        flagged = len(matches) > 0
        threat_types = [m.get("threatType") for m in matches] if matches else []

        return ModuleResult(
            module="google_safe_browsing",
            status="completed",
            findings={"flagged": flagged, "threat_types": threat_types},
            score_contribution=40 if flagged else 0,
        )
    except Exception as e:
        return ModuleResult(module="google_safe_browsing", status="error", findings={"error": str(e)})
