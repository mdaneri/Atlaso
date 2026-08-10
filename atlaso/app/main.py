"""Construct the FastAPI application and manage process lifecycle hooks."""

from contextlib import asynccontextmanager
import asyncio
import logging
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from atlaso import __version__
from atlaso.app.api.network_boot import public_router as network_boot_public_router
from atlaso.app.api.network_boot import router as network_boot_api_router
from atlaso.app.api.v1 import router as api_v1_router
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal, init_db
from atlaso.app.operational_logging import configure_operational_logging
from atlaso.app.oidc import admin_router as oidc_admin_router
from atlaso.app.oidc import public_router as oidc_public_router
from atlaso.app.openapi import API_VALIDATION_RESPONSES, OPENAPI_TAGS
from atlaso.app.problem import install_problem_handlers
from atlaso.app.seed import seed_initial_data
from atlaso.app.services.monitoring import start_monitor_sampler
from atlaso.app.services.networking import sync_host_physical_interfaces
from atlaso.app.services.network_boot import (
    ensure_environment_rows,
    recover_interrupted_network_boot_media_swaps,
    register_bundled_inventory_media,
)
from atlaso.app.services.oidc import validate_enabled_provider_at_startup
from atlaso.app.ui import (
    active_appliance_apply_job,
    cleanup_transient_secret_staging_files,
    ensure_ca_state,
    initialize_factory_appliance_apply_baseline,
    invalidate_appliance_apply_status_projection,
    recover_interrupted_appliance_apply_jobs,
    recover_interrupted_vcf_depot_software_id_jobs,
    recover_interrupted_vcf_helper_jobs,
)
from atlaso.app.ui import router as ui_router
from atlaso.app.web_terminal import router as web_terminal_router

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
REQUEST_LOGGER = logging.getLogger("atlaso.operational")
APPLIANCE_LOCK_EXEMPT_PATHS = {
    "/login",
    "/logout",
    "/PROD/login",
    "/PROD/logout",
    "/ca/login",
    "/requests/login",
    "/requests/logout",
    "/api/v1/auth/login",
}


def configure_logging(db: Session | None = None) -> None:
    """Update logging.

    Args:
        db: Active database session.
    """
    configure_operational_logging(db)


def refresh_startup_host_inventory(db: Session, *, environment: str) -> None:
    """Handle refresh startup host inventory.

    Args:
        db: Active database session.
        environment: Environment supplied by the caller.
    """
    if environment == "appliance":
        sync_host_physical_interfaces(db)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown.

    Args:
        app: App consumed by lifespan.
    """
    settings = get_settings()
    cleanup_transient_secret_staging_files()
    configure_logging()
    init_db()
    with SessionLocal() as db:
        configure_logging(db)
        appliance_mode = settings.environment == "appliance"
        seed_initial_data(db, include_examples=not appliance_mode, appliance_mode=appliance_mode)
        ensure_environment_rows(db)
        recovered_media_swaps = recover_interrupted_network_boot_media_swaps(db)
        if recovered_media_swaps:
            REQUEST_LOGGER.warning(
                "Recovered %s interrupted Network Boot media swap(s) before serving requests.",
                recovered_media_swaps,
            )
        register_bundled_inventory_media(db)
        db.commit()
        recover_interrupted_appliance_apply_jobs(db)
        recover_interrupted_vcf_depot_software_id_jobs(db)
        recover_interrupted_vcf_helper_jobs(db)
        refresh_startup_host_inventory(db, environment=settings.environment)
        if appliance_mode:
            ensure_ca_state(db)
        initialize_factory_appliance_apply_baseline(db)
        validate_enabled_provider_at_startup(db)
    monitor_sampler = start_monitor_sampler()
    try:
        yield
    finally:
        if monitor_sampler:
            monitor_sampler.stop()


def create_app() -> FastAPI:
    """Create app.

    Returns:
        The created app.
    """
    settings = get_settings()
    appliance_mutation_lock = asyncio.Lock()
    app = FastAPI(
        title="Atlaso API",
        version=__version__,
        summary="REST API for the Atlaso Linux infrastructure appliance.",
        description=(
            "Manage the Atlaso appliance through the versioned `/api/v1` REST API. "
            "Create a least-privilege bearer token in the Authentication interface, then use the operation "
            "descriptions and schemas below to inspect or change Atlaso state. Browser UI routes and service "
            "protocol endpoints remain documented in their operator guides and are intentionally excluded here."
        ),
        openapi_version="3.1.0",
        openapi_tags=OPENAPI_TAGS,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie=settings.session_cookie_name,
        same_site="lax",
        https_only=False,
    )

    @app.middleware("http")
    async def appliance_apply_lock_middleware(request: Request, call_next):
        """Return appliance apply lock middleware.

        Args:
            request: Incoming HTTP request.
            call_next: Call next supplied by the caller.
        """
        if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
            return await call_next(request)
        async with appliance_mutation_lock:
            with SessionLocal() as db:
                active_job = active_appliance_apply_job(db)
                cancellation_path = f"/tasks/{active_job.id}/cancel" if active_job is not None else ""
                exempt = (
                    request.url.path in APPLIANCE_LOCK_EXEMPT_PATHS
                    or request.url.path.startswith("/pxe/inventory/")
                    or request.url.path == cancellation_path
                )
                if active_job is not None and not exempt:
                    return JSONResponse(
                        {
                            "detail": (
                                f"Appliance apply task {active_job.id} is {active_job.status}. "
                                "Changes are locked until the master task reaches a terminal state."
                            ),
                            "job_id": active_job.id,
                            "status": active_job.status,
                        },
                        status_code=423,
                    )
            response = await call_next(request)
            if response.status_code < 400:
                invalidate_appliance_apply_status_projection()
            return response

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        """Return request id middleware.

        Args:
            request: Incoming HTTP request.
            call_next: Call next supplied by the caller.
        """
        request.state.request_id = request.headers.get("X-Request-ID", f"req_{uuid4().hex[:12]}")
        try:
            response = await call_next(request)
        except Exception:
            REQUEST_LOGGER.exception(
                "Unhandled request exception request_id=%s method=%s path=%s",
                request.state.request_id,
                request.method,
                request.url.path,
            )
            raise
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    install_problem_handlers(app)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(api_v1_router, responses=API_VALIDATION_RESPONSES)
    app.include_router(network_boot_api_router, responses=API_VALIDATION_RESPONSES)
    app.include_router(network_boot_public_router, include_in_schema=False)
    app.include_router(oidc_admin_router, responses=API_VALIDATION_RESPONSES)
    app.include_router(oidc_public_router, include_in_schema=False)
    app.include_router(web_terminal_router, include_in_schema=False)
    app.include_router(ui_router, include_in_schema=False)

    return app


app = create_app()
