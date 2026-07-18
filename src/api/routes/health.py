"""Health check endpoint."""

from fastapi import APIRouter

from src.core.config import get_config

router = APIRouter()


@router.get("/health")
async def health_check():
    """Check if the service is running."""
    config = get_config()
    return {
        "status": "healthy",
        "service": config.app_name,
        "version": config.version,
    }


@router.get("/health/ready")
async def readiness_check():
    """Check if the service is ready to accept requests."""
    # TODO: Check database, redis, and other dependencies
    return {
        "status": "ready",
        "components": {
            "api": "up",
            "storage": "up",
            "analyzer": "up",
            "causal_engine": "up",
        },
    }
