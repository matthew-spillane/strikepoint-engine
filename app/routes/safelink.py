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


async def run_url_pipeline(url: str, skip_modules: set[str] | None = None) -> tuple[list, int, str]:
    """Run URL scan modules, optionally skipping some. Returns (module_results, risk_score, verdict)."""
    modules_to_run = URL_MODULES
    if skip_modules:
        modules_to_run = [m for m in URL_MODULES if m.__name__.split(".")[-1] not in skip_modules]

    tasks = [module.scan(url) for module in modules_to_run]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    module_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            from app.models import ModuleResult
            module_results.append(ModuleResult(
                module=modules_to_run[i].__name__.split(".")[-1],
                status="error",
                findings={"error": str(result)},
            ))
        else:
            module_results.append(result)

    risk_score, verdict = score_url(module_results)
    return module_results, risk_score, verdict


@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: URLScanRequest):
    url = request.url

    module_results, risk_score, verdict = await run_url_pipeline(url)

    # AI analyst verdict
    ai_verdict = await analyze("URL", url, module_results, risk_score, verdict)

    return ScanResponse(
        url=url,
        modules=module_results,
        risk_score=risk_score,
        verdict=verdict,
        ai_verdict=ai_verdict,
    )
