import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.config import settings
from app.models import ModuleResult


async def scan(url: str) -> ModuleResult:
    if not settings.ssl_check_enabled:
        return ModuleResult(module="ssl_check", status="skipped")

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if parsed.scheme == "http":
            return ModuleResult(
                module="ssl_check",
                status="completed",
                findings={"has_ssl": False, "detail": "URL uses HTTP, no SSL"},
                score_contribution=15,
            )

        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return ModuleResult(
                module="ssl_check",
                status="completed",
                findings={"has_ssl": False, "detail": "No certificate returned"},
                score_contribution=15,
            )

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_parts.get("organizationName", "Unknown")
        expired = not_after < datetime.now(timezone.utc)

        return ModuleResult(
            module="ssl_check",
            status="completed",
            findings={
                "has_ssl": True,
                "issuer": issuer,
                "expires": not_after.isoformat(),
                "expired": expired,
            },
            score_contribution=10 if expired else 0,
        )
    except Exception as e:
        return ModuleResult(module="ssl_check", status="error", findings={"error": str(e)})
