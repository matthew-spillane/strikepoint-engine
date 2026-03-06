import json

from app.config import settings
from app.models import AIVerdict, ModuleResult

try:
    import anthropic
except ImportError:
    anthropic = None  # type: ignore[assignment]

SYSTEM_PROMPT = """You are a senior cybersecurity threat analyst at Strikepoint Security. Your job is to analyze scan results from multiple security modules and provide an independent phishing/threat assessment.

Key guidelines:
- Look holistically at ALL signal results together, not individual signals in isolation.
- Make an independent phishing judgment even if reputation APIs (VirusTotal, Google Safe Browsing) return clean — attackers rotate URLs faster than databases update.
- Explicitly call out brand impersonation patterns (e.g., "login-microsoft.com" impersonating Microsoft).
- Consider the combination of signals: a new domain + login form + brand keywords is far more suspicious than any single signal.
- Write your explanation in 2–3 sentences of plain English that a non-technical user can understand.

You MUST return a valid JSON object with exactly these fields:
{
  "verdict": "Safe" | "Suspicious" | "Likely Phishing" | "Phishing",
  "confidence": "Low" | "Medium" | "High",
  "explanation": "2-3 sentence explanation in plain English"
}

Return ONLY the JSON object, no other text."""


async def analyze(scan_type: str, target: str, modules: list[ModuleResult], risk_score: int, verdict: str) -> AIVerdict:
    if not settings.anthropic_enabled:
        return AIVerdict()

    if anthropic is None:
        return AIVerdict()

    try:
        module_summaries = []
        for m in modules:
            module_summaries.append({
                "module": m.module,
                "status": m.status,
                "findings": m.findings,
                "score_contribution": m.score_contribution,
            })

        user_message = f"""Analyze this {scan_type} scan:

Target: {target}
Aggregate Risk Score: {risk_score}/100
System Verdict: {verdict}

Module Results:
{json.dumps(module_summaries, indent=2)}

Provide your independent assessment as a JSON object."""

        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )

        text = response.content[0].text.strip()
        # Parse JSON from response
        data = json.loads(text)

        return AIVerdict(
            verdict=data.get("verdict"),
            confidence=data.get("confidence"),
            explanation=data.get("explanation"),
        )
    except Exception:
        return AIVerdict()
