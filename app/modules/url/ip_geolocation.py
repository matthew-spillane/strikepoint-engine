import socket
from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

ABUSED_VPS_PROVIDERS = [
    "digitalocean", "linode", "vultr", "akamai connected cloud",
]


async def scan(url: str) -> ModuleResult:
    if not settings.ip_geolocation_enabled:
        return ModuleResult(module="ip_geolocation", status="skipped")

    if httpx is None:
        return ModuleResult(module="ip_geolocation", status="skipped", findings={"error": "httpx not installed"})

    try:
        hostname = urlparse(url).hostname or ""
        ip = socket.gethostbyname(hostname)

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://ipinfo.io/{ip}/json")
            resp.raise_for_status()
            data = resp.json()

        country = data.get("country", "Unknown")
        org = data.get("org", "Unknown")

        on_abused_vps = any(
            provider in org.lower() for provider in ABUSED_VPS_PROVIDERS
        )

        return ModuleResult(
            module="ip_geolocation",
            status="completed",
            findings={
                "ip": ip,
                "country": country,
                "org": org,
                "abused_vps": on_abused_vps,
            },
            score_contribution=10 if on_abused_vps else 0,
        )
    except Exception as e:
        return ModuleResult(module="ip_geolocation", status="error", findings={"error": str(e)})
