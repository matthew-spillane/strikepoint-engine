import logging
import socket
import traceback
from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

HIGH_RISK_TAGS = {"malicious", "scanner", "tor"}
MEDIUM_RISK_TAGS = {"vpn"}


async def scan(url: str) -> ModuleResult:
    if not settings.shodan_internetdb_enabled:
        return ModuleResult(module="shodan_internetdb", status="skipped")

    if httpx is None:
        return ModuleResult(module="shodan_internetdb", status="skipped", findings={"error": "httpx not installed"})

    try:
        hostname = urlparse(url).hostname or ""
        logger.info("[SHODAN] Resolving hostname: %s", hostname)
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            logger.warning("[SHODAN] DNS resolution failed for %s", hostname)
            return ModuleResult(
                module="shodan_internetdb",
                status="skipped",
                findings={"detail": f"DNS resolution failed for {hostname}"},
            )

        request_url = f"https://internetdb.shodan.io/{ip}"
        logger.info("[SHODAN] Resolved IP: %s", ip)
        logger.info("[SHODAN] Request URL: %s", request_url)

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(request_url)
            logger.info(
                "[SHODAN] Response: status=%d body=%s",
                resp.status_code,
                resp.text[:500],
            )

            if resp.status_code == 404:
                return ModuleResult(
                    module="shodan_internetdb",
                    status="completed",
                    findings={"ip": ip, "detail": f"No InternetDB record for {ip}"},
                    score_contribution=0,
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
        logger.error("[SHODAN] Exception: %s\n%s", e, traceback.format_exc())
        return ModuleResult(module="shodan_internetdb", status="error", findings={"error": str(e), "traceback": traceback.format_exc()})
