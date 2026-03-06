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
from app.routes.safelink import scan_url as run_url_scan
from app.models import URLScanRequest

router = APIRouter(prefix="/safemail", tags=["SafeMail"])


async def _scan_url_for_email(url: str) -> dict:
    """Run the full URL scan pipeline for a URL found in an email."""
    try:
        request = URLScanRequest(url=url)
        result = await run_url_scan(request)
        return {
            "url": url,
            "risk_score": result.risk_score,
            "verdict": result.verdict,
        }
    except Exception as e:
        return {"url": url, "risk_score": 0, "verdict": "Error", "error": str(e)}


@router.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest):
    raw = request.raw_email

    # Run non-link modules in parallel
    tasks = [
        header_analysis.scan(raw),
        spf_dkim_dmarc.scan(raw),
        link_extraction.scan(raw, url_scan_func=_scan_url_for_email),
        content_analysis.scan(raw),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    module_results = []
    module_names = ["header_analysis", "spf_dkim_dmarc", "link_extraction", "content_analysis"]
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            module_results.append(ModuleResult(
                module=module_names[i],
                status="error",
                findings={"error": str(result)},
            ))
        else:
            module_results.append(result)

    risk_score, verdict = score_email(module_results)

    ai_verdict = await analyze("email", "email content", module_results, risk_score, verdict)

    return ScanResponse(
        modules=module_results,
        risk_score=risk_score,
        verdict=verdict,
        ai_verdict=ai_verdict,
    )
