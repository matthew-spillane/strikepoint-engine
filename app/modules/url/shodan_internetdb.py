import socket
from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

HIGH_RISK_TAGS = {"malicious", "scanner", "tor"}
MEDIUM_RISK_TAGS = {"vpn"}


async def scan(url: str) -> ModuleResult:
    if not settings.shodan_internetdb_enabled:
        return ModuleResult(module="shodan_internetdb", status="skipped")

    if httpx is None:
        return ModuleResult(module="shodan_internetdb", status="skipped", findings={"error": "httpx not installed"})

    try:
        hostname = urlparse(url).hostname or ""
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            return ModuleResult(
                module="shodan_internetdb",
                status="skipped",
                findings={"detail": f"DNS resolution failed for {hostname}"},
            )

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")

            if resp.status_code == 404:
                return ModuleResult(
                    module="shodan_internetdb",
                    status="skipped",
                    findings={"detail": f"No InternetDB record for {ip}"},
                )

            resp.raise_for_status()
            data = resp.json()

        ports = data.get("ports", [])
        tags = data.get("tags", [])
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        cpes = data.get("cpes", [])

        # Scoring
        score = 0
        tags_lower = {t.lower() for t in tags}

        if tags_lower & HIGH_RISK_TAGS:
            score += 25

        if tags_lower & MEDIUM_RISK_TAGS:
            score += 10

        if len(vulns) >= 5:
            score += 20
        elif len(vulns) >= 1:
            score += 15

        return ModuleResult(
            module="shodan_internetdb",
            status="completed",
            findings={
                "ip": ip,
                "ports": ports,
                "tags": tags,
                "vulns": vulns,
                "hostnames": hostnames,
                "cpes": cpes,
                "high_risk_tags": list(tags_lower & HIGH_RISK_TAGS) if tags_lower & HIGH_RISK_TAGS else None,
            },
            score_contribution=min(score, 35),
        )
    except Exception as e:
        return ModuleResult(module="shodan_internetdb", status="error", findings={"error": str(e)})
