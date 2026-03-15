import asyncio

from fastapi import APIRouter

from app.models import EmailScanRequest, ScanResponse, ModuleResult
from app.modules.email import (
    header_analysis,
    spf_dkim_dmarc,
    link_extraction,
    content_analysis,
)
from app.scoring.email_scorer import score_email
from app.modules.shared.ai_analyst import analyze
from app.routes.safelink import run_url_pipeline

router = APIRouter(prefix="/safemail", tags=["SafeMail"])

# Modules too slow for bulk email URL scanning
EMAIL_URL_SKIP_MODULES = {"urlscan", "cloudflare_radar"}

SAFEMAIL_TIMEOUT = 30  # seconds


async def _scan_url_for_email(url: str) -> dict:
    """Run URL scan pipeline for a URL found in an email, skipping slow modules."""
    try:
        _, risk_score, verdict = await run_url_pipeline(url, skip_modules=EMAIL_URL_SKIP_MODULES)
        return {
            "url": url,
            "risk_score": risk_score,
            "verdict": verdict,
        }
    except Exception as e:
        return {"url": url, "risk_score": 0, "verdict": "Error", "error": str(e)}


@router.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest):
    raw = request.raw_email

    # Create actual tasks so we can inspect their state on timeout
    async_tasks = [
        asyncio.create_task(header_analysis.scan(raw)),
        asyncio.create_task(spf_dkim_dmarc.scan(raw)),
        asyncio.create_task(link_extraction.scan(raw, url_scan_func=_scan_url_for_email)),
        asyncio.create_task(content_analysis.scan(raw)),
    ]

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*async_tasks, return_exceptions=True),
            timeout=SAFEMAIL_TIMEOUT,
        )
        partial = False

    except asyncio.TimeoutError:
        # Timeout — collect whatever results completed so far
        partial = True
        results = []
        for task in async_tasks:
            if task.done() and not task.cancelled():
                exc = task.exception()
                results.append(exc if exc else task.result())
            else:
                task.cancel()
                results.append(None)

    module_names = ["header_analysis", "spf_dkim_dmarc", "link_extraction", "content_analysis"]
    module_results = []
    for i, result in enumerate(results):
        if result is None:
            module_results.append(ModuleResult(
                module=module_names[i],
                status="timeout",
                findings={"error": "Module did not complete within timeout"},
            ))
        elif isinstance(result, Exception):
            module_results.append(ModuleResult(
                module=module_names[i],
                status="error",
                findings={"error": str(result)},
            ))
        else:
            module_results.append(result)

    risk_score, verdict = score_email(module_results)

    # Skip AI analyst if we're already running out of time
    if partial:
        from app.models import AIVerdict
        ai_verdict = AIVerdict()
    else:
        ai_verdict = await analyze("email", "email content", module_results, risk_score, verdict)

    response = ScanResponse(
        modules=module_results,
        risk_score=risk_score,
        verdict=verdict,
        ai_verdict=ai_verdict,
    )

    if partial:
        # Attach a note about partial results — add to each timeout module's findings
        for m in response.modules:
            if m.status == "timeout":
                m.findings = m.findings or {}
                m.findings["note"] = "Analysis was partial due to 30-second timeout"

    return response
