from pydantic import BaseModel, HttpUrl


class URLScanRequest(BaseModel):
    url: str


class EmailScanRequest(BaseModel):
    raw_email: str


class ModuleResult(BaseModel):
    module: str
    status: str  # "completed", "skipped", "error"
    findings: dict | None = None
    score_contribution: int = 0


class AIVerdict(BaseModel):
    verdict: str | None = None
    confidence: str | None = None
    explanation: str | None = None


class ScanResponse(BaseModel):
    url: str | None = None
    modules: list[ModuleResult]
    risk_score: int
    verdict: str
    ai_verdict: AIVerdict | None = None


class HealthResponse(BaseModel):
    status: str
    modules: dict
