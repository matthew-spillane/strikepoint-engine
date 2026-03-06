import asyncio

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

POLL_INTERVAL = 3
POLL_TIMEOUT = 30


async def scan(url: str) -> ModuleResult:
    if not settings.urlscan_enabled:
        return ModuleResult(module="urlscan", status="skipped")

    if httpx is None:
        return ModuleResult(module="urlscan", status="skipped", findings={"error": "httpx not installed"})

    try:
        headers = {"API-Key": settings.URLSCAN_API_KEY, "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=15) as client:
            submit = await client.post(
                "https://urlscan.io/api/v1/scan/",
                json={"url": url, "visibility": "unlisted"},
                headers=headers,
            )
            submit.raise_for_status()
            result_url = submit.json().get("api")

            if not result_url:
                return ModuleResult(module="urlscan", status="error", findings={"error": "No result URL returned"})

            elapsed = 0
            while elapsed < POLL_TIMEOUT:
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL
                poll = await client.get(result_url)
                if poll.status_code == 200:
                    data = poll.json()
                    verdicts = data.get("verdicts", {}).get("overall", {})
                    is_malicious = verdicts.get("malicious", False)
                    score = verdicts.get("score", 0)
                    screenshot = data.get("task", {}).get("screenshotURL")
                    report_url = data.get("task", {}).get("reportURL")

                    return ModuleResult(
                        module="urlscan",
                        status="completed",
                        findings={
                            "malicious": is_malicious,
                            "score": score,
                            "screenshot_url": screenshot,
                            "report_url": report_url,
                        },
                        score_contribution=30 if is_malicious else 0,
                    )

            return ModuleResult(
                module="urlscan",
                status="skipped",
                findings={"detail": "Polling timed out"},
            )
    except Exception as e:
        return ModuleResult(module="urlscan", status="error", findings={"error": str(e)})
