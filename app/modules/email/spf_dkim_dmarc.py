import email
import re

from app.config import settings
from app.models import ModuleResult


async def scan(raw_email: str) -> ModuleResult:
    if not settings.spf_dkim_dmarc_enabled:
        return ModuleResult(module="spf_dkim_dmarc", status="skipped")

    try:
        msg = email.message_from_string(raw_email)
        auth_results = msg.get_all("Authentication-Results") or []
        combined = " ".join(auth_results).lower()

        def check_result(protocol: str) -> str:
            pattern = rf'{protocol}=(\w+)'
            match = re.search(pattern, combined)
            if match:
                return match.group(1)
            return "missing"

        spf = check_result("spf")
        dkim = check_result("dkim")
        dmarc = check_result("dmarc")

        flags: list[str] = []
        score = 0

        for name, result in [("spf", spf), ("dkim", dkim), ("dmarc", dmarc)]:
            if result == "fail":
                flags.append(f"{name}_fail")
                score += 15
            elif result == "missing":
                flags.append(f"{name}_missing")
                score += 5

        return ModuleResult(
            module="spf_dkim_dmarc",
            status="completed",
            findings={"spf": spf, "dkim": dkim, "dmarc": dmarc, "flags": flags},
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="spf_dkim_dmarc", status="error", findings={"error": str(e)})
