from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import HealthResponse

app = FastAPI(
    title="Strikepoint Engine",
    description="Unified backend for Strikepoint Security tools",
    version="1.0.0",
)

# CORS — configured immediately after app creation, before routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import and register routes
from app.routes.safelink import router as safelink_router
from app.routes.safemail import router as safemail_router

app.include_router(safelink_router)
app.include_router(safemail_router)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        modules=settings.module_status(),
    )
