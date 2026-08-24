"""Test appliance-maintenance management UI transports."""

import json

from sqlalchemy import select

from atlaso.app.adapters.system import AdapterResult
from tests.routers.ui.helpers import login


def _csrf_from_page(page_text: str) -> str:
    """Return the CSRF value from a rendered management page.

    Args:
        page_text: Rendered management-page markup.

    Returns:
        Embedded CSRF token value.
    """
    return page_text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_appliance_maintenance_routers_own_exact_transport_sets():
    """Keep both historical maintenance route groups in their established order."""
    from atlaso.app import ui

    def identities(router):
        """Return stable route identities for one extracted router.

        Args:
            router: FastAPI router whose transports are inspected.

        Returns:
            Ordered path, method, and route-name tuples.
        """
        return [
            (
                route.path,
                tuple(sorted((route.methods or set()) - {"HEAD"})),
                route.name,
            )
            for route in router.routes
        ]

    assert identities(ui.appliance_maintenance_power_router) == [
        (
            "/ui/management/appliance/power/{action}",
            ("POST",),
            "appliance_power_action",
        )
    ]
    assert identities(ui.appliance_maintenance_update_router) == [
        (
            "/ui/management/appliance-update/availability",
            ("GET",),
            "appliance_update_availability",
        ),
        (
            "/ui/management/appliance-update",
            ("GET",),
            "appliance_update_page",
        ),
        (
            "/ui/management/appliance-update/settings",
            ("POST",),
            "update_appliance_update_settings",
        ),
        (
            "/ui/management/appliance-update/sources/{source_id}",
            ("POST",),
            "update_appliance_update_source",
        ),
        (
            "/ui/management/appliance-update/sources",
            ("POST",),
            "create_appliance_update_source",
        ),
        (
            "/ui/management/appliance-update/sources/{source_id}/delete",
            ("POST",),
            "delete_appliance_update_source",
        ),
        (
            "/ui/management/appliance-update/packages",
            ("POST",),
            "create_managed_update_package",
        ),
        (
            "/ui/management/appliance-update/packages/{package_id}",
            ("POST",),
            "update_managed_update_package",
        ),
        (
            "/ui/management/appliance-update/packages/{package_id}/delete",
            ("POST",),
            "delete_managed_update_package",
        ),
        (
            "/ui/management/appliance-update/source-sync",
            ("POST",),
            "sync_appliance_update_sources",
        ),
        (
            "/ui/management/appliance-update/check",
            ("POST",),
            "check_appliance_update",
        ),
        (
            "/ui/management/appliance-update/run",
            ("POST",),
            "run_appliance_update",
        ),
    ]
    for route in (
        *ui.appliance_maintenance_power_router.routes,
        *ui.appliance_maintenance_update_router.routes,
    ):
        assert getattr(ui, route.name) is route.endpoint
    assert callable(ui._managed_package_from_form)
    assert callable(ui.submit_appliance_update)


def test_appliance_update_availability_is_authenticated_no_store_and_not_openapi(client):
    """Keep the sanitized indicator projection browser-only and uncached.

    Args:
        client: Test application HTTP client.
    """
    anonymous = client.get(
        "/ui/management/appliance-update/availability",
        follow_redirects=False,
    )
    assert anonymous.status_code in {302, 303, 307, 401}

    login(client)
    response = client.get("/ui/management/appliance-update/availability")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["schema_version"] == 1
    serialized = json.dumps(response.json())
    assert "commands" not in serialized
    assert "credentials" not in serialized
    assert "helper" not in serialized

    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    assert "/ui/management/appliance-update/availability" not in openapi.json()["paths"]


def test_appliance_power_action_creates_task_before_scheduling(client, monkeypatch):
    """Preserve task persistence before delayed helper scheduling.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest helper used to replace the facade compatibility seam.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job, JobStatus

    observed: list[tuple[str, str]] = []

    class PowerAdapter:
        """Capture the persisted task state before scheduling."""

        def schedule_appliance_power(self, action: str) -> AdapterResult:
            """Return one successful delayed power schedule result.

            Args:
                action: Requested appliance power operation.

            Returns:
                Successful adapter result.
            """
            with SessionLocal() as db:
                job = db.execute(
                    select(Job).where(Job.type == f"appliance-{action}")
                ).scalar_one()
                observed.append((job.status, action))
            return AdapterResult(
                command=[
                    "sudo",
                    "-n",
                    "/opt/atlaso/bin/atlaso-helper",
                    "appliance-power",
                    action,
                    "--real",
                ],
                dry_run=False,
                stdout="scheduled",
            )

    login(client)
    page = client.get("/ui/management/dashboard")
    csrf = _csrf_from_page(page.text)
    monkeypatch.setattr(ui, "SystemAdapter", PowerAdapter)

    response = client.post(
        "/ui/management/appliance/power/reboot",
        data={"csrf": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(
        "/ui/management/tasks?job_id=job_"
    )
    assert observed == [(JobStatus.RUNNING.value, "reboot")]
    with SessionLocal() as db:
        job = db.execute(
            select(Job).where(Job.type == "appliance-reboot")
        ).scalar_one()
        payload = json.loads(job.result or "{}")
        assert job.status == JobStatus.SUCCEEDED.value
        assert job.progress_percent == 100
        assert payload["action"] == "reboot"
        assert payload["scheduled"] is True
        assert payload["delay_seconds"] == 5
        actions = set(
            db.execute(
                select(AuditEvent.action).where(AuditEvent.resource_id == job.id)
            ).scalars()
        )
        assert actions == {
            "submit_appliance_reboot",
            "schedule_appliance_reboot",
        }

    tasks = client.get(response.headers["location"])
    assert tasks.status_code == 200
    assert "Appliance Reboot" in tasks.text


def test_appliance_shutdown_reports_helper_failure(client, monkeypatch):
    """Preserve fail-closed task evidence when delayed scheduling fails.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest helper used to replace the facade compatibility seam.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    class FailingPowerAdapter:
        """Return an unavailable delayed-scheduling result."""

        def schedule_appliance_power(self, action: str) -> AdapterResult:
            """Return a failed scheduling result.

            Args:
                action: Requested appliance power operation.

            Returns:
                Failed adapter result.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-power", action],
                dry_run=False,
                stderr="systemd-run unavailable",
                returncode=127,
            )

    login(client)
    page = client.get("/ui/management/dashboard")
    csrf = _csrf_from_page(page.text)
    monkeypatch.setattr(ui, "SystemAdapter", FailingPowerAdapter)

    response = client.post(
        "/ui/management/appliance/power/shutdown",
        data={"csrf": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        job = db.execute(
            select(Job).where(Job.type == "appliance-shutdown")
        ).scalar_one()
        payload = json.loads(job.result or "{}")
        assert job.status == JobStatus.FAILED.value
        assert job.error == "Appliance shutdown scheduling failed."
        assert payload["scheduled"] is False


def test_update_submission_keeps_facade_monkeypatch_seam(client, monkeypatch):
    """Resolve the stable facade submission helper at request time.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest helper used to replace the facade compatibility seam.
    """
    from fastapi.responses import JSONResponse

    from atlaso.app import ui

    observed: dict[str, object] = {}

    def submit(**kwargs):
        """Capture the extracted transport's facade-helper call.

        Args:
            **kwargs: Submission arguments from the transport.

        Returns:
            Synthetic accepted response.
        """
        observed.update(kwargs)
        return JSONResponse({"status": "synthetic"}, status_code=202)

    monkeypatch.setattr(ui, "submit_appliance_update", submit)
    login(client)
    page = client.get("/ui/management/appliance-update")
    csrf = _csrf_from_page(page.text)

    response = client.post(
        "/ui/management/appliance-update/check",
        headers={"Accept": "application/json"},
        data={"csrf": csrf, "selected_streams": ["photon_os"]},
    )

    assert response.status_code == 202
    assert response.json() == {"status": "synthetic"}
    assert observed["mode"] == "check"
    assert observed["selected_streams"] == ["photon_os"]


def test_powershell_check_rejects_unsynchronized_repository(client):
    """Reject PowerShell checks until repository synchronization succeeds.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ui/management/appliance-update")
    csrf = _csrf_from_page(page.text)

    response = client.post(
        "/ui/management/appliance-update/check",
        headers={"Accept": "application/json"},
        data={"csrf": csrf, "selected_streams": ["powershell_modules"]},
    )

    assert response.status_code == 422
    assert "Synchronize PowerShell repository PSGallery" in response.json()["detail"]
    availability = client.get(
        "/ui/management/appliance-update/availability"
    )
    assert availability.status_code == 200
    assert availability.headers["cache-control"] == "no-store"
    stream = next(
        row for row in availability.json()["streams"]
        if row["id"] == "powershell_modules"
    )
    assert stream["source_sync"]["ready"] is False
    assert stream["source_sync"]["state"] == "required"
    assert "Synchronize repositories" in stream["source_sync"]["reason"]


def test_photon_check_rejects_unsynchronized_repository(client):
    """Reject Photon checks until managed repository synchronization succeeds.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import UpdateSource

    login(client)
    with SessionLocal() as db:
        source = UpdateSource(
            kind="photon",
            name="Managed Photon",
            url="https://packages.example.test/photon",
            enabled=True,
            settings_json=json.dumps(
                {"managed": True, "gpgcheck": True, "tls_verify": True}
            ),
            validation_status="not_checked",
        )
        db.add(source)
        db.flush()
        source_name = source.name
        db.commit()

    page = client.get("/ui/management/appliance-update")
    csrf = _csrf_from_page(page.text)
    response = client.post(
        "/ui/management/appliance-update/check",
        headers={"Accept": "application/json"},
        data={"csrf": csrf, "selected_streams": ["photon_os"]},
    )

    assert response.status_code == 422
    assert source_name in response.json()["detail"]
    availability = client.get(
        "/ui/management/appliance-update/availability"
    )
    assert availability.status_code == 200
    stream = next(
        row for row in availability.json()["streams"]
        if row["id"] == "photon_os"
    )
    assert stream["source_sync"]["ready"] is False
    assert stream["source_sync"]["state"] == "required"
    assert source_name in stream["source_sync"]["reason"]


def test_appliance_update_settings_validate_urls(client):
    """Preserve Appliance Update settings URL validation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ui/management/appliance-update")
    csrf = _csrf_from_page(page.text)
    response = client.post(
        "/ui/management/appliance-update/settings",
        data={
            "csrf": csrf,
            "photon_source": "configured Photon repositories",
            "atlaso_manifest_url": "not-a-url",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert response.status_code == 422
    assert "Atlaso manifest URL must be an http or https URL" in response.text


def test_appliance_update_settings_reject_embedded_credentials(client):
    """Preserve rejection of secret-bearing update repository URLs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ui/management/appliance-update")
    csrf = _csrf_from_page(page.text)
    response = client.post(
        "/ui/management/appliance-update/settings",
        data={
            "csrf": csrf,
            "photon_source": "configured Photon repositories",
            "atlaso_manifest_url": (
                "https://user:token@example.test/manifest.json"
            ),
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert response.status_code == 422
    assert "must not include embedded credentials" in response.text


def test_source_sync_json_submission_queues_without_page_render(client):
    """Preserve the asynchronous JSON source-sync transport contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ui/management/appliance-update")
    csrf = _csrf_from_page(page.text)

    response = client.post(
        "/ui/management/appliance-update/source-sync",
        data={"csrf": csrf},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    assert response.json()["status"] == "pending"
    assert response.json()["mode"] == "source_sync"
    assert response.json()["job_id"].startswith("job_")


def test_source_sync_rejects_reserved_gallery_custom_url_before_queueing(client):
    """Reject an invalid reserved gallery definition before creating a task.

    Args:
        client: Test application HTTP client.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, UpdateSource

    login(client)
    page = client.get("/ui/management/appliance-update")
    csrf = _csrf_from_page(page.text)
    with SessionLocal() as db:
        source = db.execute(
            select(UpdateSource).where(
                UpdateSource.kind == "powershell",
                UpdateSource.name == "PSGallery",
            )
        ).scalar_one()
        source.name = "pSgAlLeRy"
        source.url = "https://packages.example.test/api/v2"
        db.add(source)
        db.commit()
        before = len(db.execute(select(Job)).scalars().all())

    response = client.post(
        "/ui/management/appliance-update/source-sync",
        data={"csrf": csrf},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 422
    assert "PSGallery is reserved for the built-in PowerShell Gallery" in response.json()["detail"]
    assert "choose a different repository name" in response.json()["detail"]
    with SessionLocal() as db:
        assert len(db.execute(select(Job)).scalars().all()) == before
