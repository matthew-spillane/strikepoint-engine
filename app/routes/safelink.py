import asyncio

from fastapi import APIRouter

from app.models import URLScanRequest, ScanResponse
from app.modules.url import (
    virustotal,
    google_safe_browsing,
    urlscan,
    alienvault_otx,
    phishtank,
    whois_age,
    ssl_check,
    redirect_chain,
    keyword_detection,
    lookalike_domain,
    ip_geolocation,
    url_structure,
    page_content,
)
from app.scoring.url_scorer import score_url
from app.modules.shared.ai_analyst import analyze

router = APIRouter(prefix="/safelink", tags=["SafeLink"])

URL_MODULES = [
    virustotal,
    google_safe_browsing,
    urlscan,
    alienvault_otx,
    phishtank,
    whois_age,
    ssl_check,
    redirect_chain,
    keyword_detection,
    lookalike_domain,
    ip_geolocation,
    url_structure,
    page_content,
]


@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: URLScanRequest):
    url = request.url

    # Run all modules in parallel
    tasks = [module.scan(url) for module in URL_MODULES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Convert exceptions to error results
    module_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            from app.models import ModuleResult
            module_results.append(ModuleResult(
                module=URL_MODULES[i].__name__.split(".")[-1],
                status="error",
                findings={"error": str(result)},
            ))
        else:
            module_results.append(result)

    # Compute score and verdict
    risk_score, verdict = score_url(module_results)

    # AI analyst verdict
    ai_verdict = await analyze("URL", url, module_results, risk_score, verdict)

    return ScanResponse(
        url=url,
        modules=module_results,
        risk_score=risk_score,
        verdict=verdict,
        ai_verdict=ai_verdict,
    )
