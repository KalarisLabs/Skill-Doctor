"""
FastAPI application factory for Skill Doctor API.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from skill_doctor import __version__


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    yield
    # Shutdown


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Skill Doctor API",
        description="Multi-layer security platform for AI agent skill files",
        version=__version__,
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check endpoint
    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__}

    # TODO: Add scan endpoints
    # TODO: Add report endpoints

    return app


# Module-level app instance for uvicorn
# Usage: uvicorn skill_doctor.api.main:app --reload
app = create_app()
