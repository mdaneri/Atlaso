"""Test Automation management UI transports."""

from sqlalchemy import select

from tests.routers.ui.helpers import login


def csrf_from_page(text: str) -> str:
    """Return the CSRF token rendered in a management page.

    Args:
        text: Rendered management page content containing the CSRF input.
    """
    return text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_automation_router_owns_exact_transport_set():
    """Keep Automation routes and the contextual VCF schedule boundary exact."""
    from atlaso.app import ui

    assert [
        (route.path, tuple(sorted((route.methods or set()) - {"HEAD"})), route.name)
        for route in ui.automation_router.routes
    ] == [
        ("/ui/management/automation", ("GET",), "automation_page"),
        (
            "/ui/management/automation/schedules",
            ("POST",),
            "create_automation_schedule",
        ),
        (
            "/ui/management/vcf-offline-depot/profiles/{profile_id}/schedules",
            ("POST",),
            "create_contextual_vcf_depot_schedule",
        ),
        (
            "/ui/management/automation/schedules/{schedule_id}/edit",
            ("POST",),
            "edit_automation_schedule",
        ),
        (
            "/ui/management/automation/schedules/{schedule_id}/run",
            ("POST",),
            "run_automation_schedule_now",
        ),
        (
            "/ui/management/automation/schedules/{schedule_id}/toggle",
            ("POST",),
            "toggle_automation_schedule",
        ),
        (
            "/ui/management/automation/schedules/{schedule_id}/delete",
            ("POST",),
            "delete_automation_schedule",
        ),
        (
            "/ui/management/automation/scripts",
            ("POST",),
            "create_automation_script_from_ui",
        ),
        (
            "/ui/management/automation/scripts/{script_id}/revisions",
            ("POST",),
            "create_automation_script_revision_from_ui",
        ),
        (
            "/ui/management/automation/scripts/{script_id}/edit",
            ("POST",),
            "edit_automation_script_from_ui",
        ),
        (
            "/ui/management/automation/scripts/{script_id}/delete",
            ("POST",),
            "delete_automation_script_from_ui",
        ),
        (
            "/ui/management/automation/scripts/revisions/{revision_id}/toggle",
            ("POST",),
            "toggle_automation_script_revision",
        ),
        (
            "/ui/management/automation/scripts/revisions/{revision_id}/run",
            ("POST",),
            "run_automation_script_revision",
        ),
    ]


def test_vcf_schedule_profile_selector_shows_disabled_profiles_and_actionable_guidance(
    client,
):
    """Verify that vcf schedule profile selector shows disabled profiles and actionable guidance.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfDepotDownloadProfile

    login(client)
    with SessionLocal() as db:
        for profile in db.execute(select(VcfDepotDownloadProfile)).scalars().all():
            profile.enabled = False
        enabled = VcfDepotDownloadProfile(
            name="Enabled schedule profile", profile_type="metadata", enabled=True
        )
        disabled = VcfDepotDownloadProfile(
            name="Disabled schedule profile", profile_type="metadata", enabled=False
        )
        db.add_all([enabled, disabled])
        db.commit()
        enabled_id = enabled.id
        disabled_id = disabled.id

    page = client.get("/automation")
    assert page.status_code == 200
    assert '<option value="" disabled selected>Choose a profile</option>' in page.text
    assert (
        f'<option value="{enabled_id}" >Enabled schedule profile</option>' in page.text
    )
    assert (
        f'<option value="{disabled_id}" disabled>Disabled schedule profile · disabled</option>'
        in page.text
    )
    assert "Only enabled profiles can be scheduled." in page.text
    assert (
        '<a href="/ui/management/vcf-offline-depot">Manage profiles in VCF Offline Depot</a>'
        in page.text
    )

    with SessionLocal() as db:
        db.get(VcfDepotDownloadProfile, enabled_id).enabled = False
        db.commit()

    page = client.get("/automation")
    assert (
        '<option value="" disabled selected>No enabled profiles</option>' in page.text
    )
    assert "All configured download profiles are disabled." in page.text
    assert (
        '<a href="/ui/management/vcf-offline-depot">Enable a profile in VCF Offline Depot</a>'
        in page.text
    )


def test_managed_script_wizard_reports_a_malformed_bash_shebang(client):
    """Verify that managed script wizard reports a malformed bash shebang.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript

    login(client)
    csrf = csrf_from_page(client.get("/automation").text)
    response = client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "malformed-shebang",
            "interpreter": "bash",
            "timeout_seconds": "60",
            "content": "!/bin/bash\r\necho no\r\n",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "A Bash shebang must start with #!; add the missing # or remove the shebang line."
    )
    with SessionLocal() as db:
        assert (
            db.execute(
                select(AutomationScript).where(
                    AutomationScript.name == "malformed-shebang"
                )
            ).scalar_one_or_none()
            is None
        )
