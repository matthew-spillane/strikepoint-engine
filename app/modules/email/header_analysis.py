import email
import re

from app.config import settings
from app.models import ModuleResult


async def scan(raw_email: str) -> ModuleResult:
    if not settings.header_analysis_enabled:
        return ModuleResult(module="header_analysis", status="skipped")

    try:
        msg = email.message_from_string(raw_email)

        from_header = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        received = msg.get_all("Received") or []

        # Extract email addresses
        def extract_email(header_value: str) -> str:
            match = re.search(r'[\w.+-]+@[\w.-]+', header_value)
            return match.group(0).lower() if match else ""

        from_addr = extract_email(from_header)
        reply_to_addr = extract_email(reply_to)
        return_path_addr = extract_email(return_path)

        flags: list[str] = []

        # Display name vs actual sending address mismatch
        display_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
        if display_match:
            display_name = display_match.group(1).strip().lower()
            # Check if display name contains an email-like string different from actual
            display_email = extract_email(display_name)
            if display_email and display_email != from_addr:
                flags.append("display_name_email_mismatch")

        # Reply-To mismatch
        if reply_to_addr and from_addr and reply_to_addr != from_addr:
            flags.append("reply_to_mismatch")

        # Return-Path mismatch
        if return_path_addr and from_addr and return_path_addr != from_addr:
            flags.append("return_path_mismatch")

        score = len(flags) * 10

        return ModuleResult(
            module="header_analysis",
            status="completed",
            findings={
                "from": from_header,
                "from_address": from_addr,
                "reply_to": reply_to,
                "return_path": return_path,
                "received_hops": len(received),
                "flags": flags,
            },
            score_contribution=score,
        )
    except Exception as e:
        return ModuleResult(module="header_analysis", status="error", findings={"error": str(e)})
