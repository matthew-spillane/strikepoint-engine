import logging
import traceback
from urllib.parse import quote, urlparse

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


async def scan(url: str) -> ModuleResult:
    if not settings.otx_enabled:
        return ModuleResult(module="alienvault_otx", status="skipped")

    if httpx is None:
        return ModuleResult(module="alienvault_otx", status="skipped", findings={"error": "httpx not installed"})

    api_key = (settings.OTX_API_KEY or "").strip()
    if not api_key:
        return ModuleResult(
            module="alienvault_otx",
            status="skipped",
            findings={"detail": "OTX_API_KEY / ALIENVAULT_API_KEY not configured"},
        )

    try:
        encoded_url = quote(url, safe="")
        headers = {"X-OTX-API-KEY": api_key}
        url_endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general"

        logger.info("[OTX] URL indicator endpoint: %s", url_endpoint)

        pulse_count = 0
        pulses = []
        tags = []

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url_endpoint, headers=headers)
            logger.info("[OTX] URL lookup: status=%d body=%s", resp.status_code, resp.text[:300])

            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                pulses = data.get("pulse_info", {}).get("pulses", [])
                tags = list({tag for p in pulses[:10] for tag in p.get("tags", [])})
                logger.info("[OTX] URL lookup result: pulse_count=%d", pulse_count)
            elif resp.status_code in (400, 404):
                # OTX returns 400/404 for URLs it hasn't indexed — not an error
                logger.info("[OTX] URL not in OTX database (status %d), trying hostname fallback", resp.status_code)
            else:
                # Unexpected status — log but don't crash
                logger.warning("[OTX] Unexpected status %d from URL lookup: %s", resp.status_code, resp.text[:300])

            # OTX often indexes phishing/malware under hostname indicator only.
            # Fall back to hostname if URL lookup returned 0 pulses or wasn't found.
            if pulse_count == 0:
                hostname = urlparse(url).hostname or ""
                if hostname:
                    hostname_endpoint = f"https://otx.alienvault.com/api/v1/indicators/hostname/{hostname}/general"
                    logger.info("[OTX] Trying hostname fallback: %s", hostname_endpoint)
                    h_resp = await client.get(hostname_endpoint, headers=headers)
                    logger.info(
                        "[OTX] Hostname lookup: status=%d body=%s",
                        h_resp.status_code,
                        h_resp.text[:300],
                    )
                    if h_resp.status_code == 200:
                        h_data = h_resp.json()
                        h_pulse_count = h_data.get("pulse_info", {}).get("count", 0)
                        h_pulses = h_data.get("pulse_info", {}).get("pulses", [])
                        logger.info("[OTX] Hostname fallback: pulse_count=%d", h_pulse_count)
                        if h_pulse_count > 0:
                            pulse_count = h_pulse_count
                            pulses = h_pulses
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
        logger.error("[OTX] Exception: %s\n%s", e, traceback.format_exc())
        return ModuleResult(module="alienvault_otx", status="error", findings={"error": str(e)})
