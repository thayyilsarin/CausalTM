"""CausalTM - Main application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes.health import router as health_router
from src.api.routes.scans import router as scans_router
from src.api.routes.reports import router as reports_router
from src.core.config import get_config


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    config = get_config()

    # Ensure storage directories exist
    for dir_path in [
        config.storage.scans_dir,
        config.storage.reports_dir,
        config.storage.diagrams_dir,
        config.git.temp_dir,
    ]:
        Path(dir_path).mkdir(parents=True, exist_ok=True)

    yield

    # Cleanup on shutdown (if needed)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    config = get_config()

    app = FastAPI(
        title="CausalTM",
        description=(
            "Causal AI-driven automated STRIDE threat modeling. "
            "Correlates SAST/DAST findings with code architecture "
            "to generate Data Flow Diagrams and threat reports."
        ),
        version=config.version,
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routers
    app.include_router(health_router, prefix="/api/v1", tags=["health"])
    app.include_router(scans_router, prefix="/api/v1", tags=["scans"])
    app.include_router(reports_router, prefix="/api/v1", tags=["reports"])

    return app


app = create_app()


def cli():
    """CLI entry point to run the server."""
    import uvicorn

    config = get_config()
    uvicorn.run(
        "src.main:app",
        host=config.host,
        port=config.port,
        reload=config.debug,
    )


if __name__ == "__main__":
    cli()
