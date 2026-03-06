import email
import re

from app.config import settings
from app.models import ModuleResult

URGENCY_PATTERNS = [
    r"immediate\s+action",
    r"act\s+now",
    r"urgent",
    r"expires?\s+(today|soon|immediately)",
    r"within\s+\d+\s+hours?",
    r"account\s+(will be|has been)\s+(suspended|closed|locked|terminated)",
    r"limited\s+time",
    r"final\s+(warning|notice)",
]

CREDENTIAL_REQUEST_PATTERNS = [
    r"(verify|confirm|update)\s+(your\s+)?(account|identity|password|information)",
    r"(enter|provide)\s+(your\s+)?(password|credentials|ssn|social\s+security)",
    r"click\s+(here|below)\s+to\s+(verify|confirm|login|sign\s*in)",
    r"reset\s+your\s+password",
]

IMPERSONATION_PATTERNS = [
    r"(paypal|apple|amazon|microsoft|google|netflix|chase|wellsfargo|bank\s*of\s*america)\s+(support|team|security|service)",
    r"(customer\s+service|security\s+team|account\s+department)",
    r"dear\s+(valued\s+)?(customer|user|member|client)",
]


async def scan(raw_email: str) -> ModuleResult:
    if not settings.content_analysis_enabled:
        return ModuleResult(module="content_analysis", status="skipped")

    try:
        msg = email.message_from_string(raw_email)

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode("utf-8", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode("utf-8", errors="replace")

        body_lower = body.lower()
        flags: list[str] = []
        score = 0

        # Urgency language
        urgency_matches = [p for p in URGENCY_PATTERNS if re.search(p, body_lower)]
        if urgency_matches:
            flags.append("urgency_language")
            score += min(len(urgency_matches) * 5, 15)

        # Credential requests
        cred_matches = [p for p in CREDENTIAL_REQUEST_PATTERNS if re.search(p, body_lower)]
        if cred_matches:
            flags.append("credential_request")
            score += min(len(cred_matches) * 10, 20)

        # Impersonation indicators
        impersonation_matches = [p for p in IMPERSONATION_PATTERNS if re.search(p, body_lower)]
        if impersonation_matches:
            flags.append("impersonation_indicators")
            score += min(len(impersonation_matches) * 10, 15)

        return ModuleResult(
            module="content_analysis",
            status="completed",
            findings={
                "flags": flags,
                "urgency_indicators": len(urgency_matches),
                "credential_request_indicators": len(cred_matches),
                "impersonation_indicators": len(impersonation_matches),
            },
            score_contribution=min(score, 50),
        )
    except Exception as e:
        return ModuleResult(module="content_analysis", status="error", findings={"error": str(e)})
