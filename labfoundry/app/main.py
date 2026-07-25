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

from labfoundry import __version__
from labfoundry.app.api.v1 import router as api_v1_router
from labfoundry.app.config import get_settings
from labfoundry.app.database import SessionLocal, init_db
from labfoundry.app.operational_logging import configure_operational_logging
from labfoundry.app.oidc import admin_router as oidc_admin_router
from labfoundry.app.oidc import public_router as oidc_public_router
from labfoundry.app.problem import install_problem_handlers
from labfoundry.app.seed import seed_initial_data
from labfoundry.app.services.monitoring import start_monitor_sampler
from labfoundry.app.services.networking import sync_host_physical_interfaces
from labfoundry.app.services.oidc import validate_enabled_provider_at_startup
from labfoundry.app.ui import (
    active_appliance_apply_job,
    ensure_ca_state,
    initialize_factory_appliance_apply_baseline,
    recover_interrupted_appliance_apply_jobs,
    recover_interrupted_vcf_helper_jobs,
)
from labfoundry.app.ui import router as ui_router
from labfoundry.app.web_terminal import router as web_terminal_router

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
REQUEST_LOGGER = logging.getLogger("labfoundry.operational")
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
    configure_operational_logging(db)


def refresh_startup_host_inventory(db: Session, *, environment: str) -> None:
    if environment == "appliance":
        sync_host_physical_interfaces(db)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging()
    init_db()
    with SessionLocal() as db:
        configure_logging(db)
        appliance_mode = settings.environment == "appliance"
        seed_initial_data(db, include_examples=not appliance_mode, appliance_mode=appliance_mode)
        recover_interrupted_appliance_apply_jobs(db)
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
    settings = get_settings()
    appliance_mutation_lock = asyncio.Lock()
    app = FastAPI(
        title="LabFoundry API",
        version=__version__,
        summary="REST API for the LabFoundry Linux infrastructure appliance.",
        openapi_version="3.1.0",
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
        if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
            return await call_next(request)
        async with appliance_mutation_lock:
            with SessionLocal() as db:
                active_job = active_appliance_apply_job(db)
                cancellation_path = f"/tasks/{active_job.id}/cancel" if active_job is not None else ""
                exempt = request.url.path in APPLIANCE_LOCK_EXEMPT_PATHS or request.url.path == cancellation_path
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
            return await call_next(request)

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
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
    app.include_router(api_v1_router)
    app.include_router(oidc_admin_router)
    app.include_router(oidc_public_router)
    app.include_router(web_terminal_router)
    app.include_router(ui_router)

    return app


app = create_app()
