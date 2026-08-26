"""Test docs behavior."""

import json
import re
import subprocess
from pathlib import Path

import pytest

from scripts import (
    build_docs,
    generate_embedded_screenshot_sections,
    generate_screenshot_gallery,
    generate_screenshot_manifest,
)
from scripts.check_docs import (
    markdown_sources,
    validate_legacy_browser_routes,
    validate_page,
    validate_screenshots,
)
from scripts.overlay_docs_site import overlay


def test_documentation_homepage_preserves_paths_and_popular_guides() -> None:
    """Verify that the homepage keeps section paths and a focused operator guide list."""
    root = Path(__file__).resolve().parents[1]
    homepage = (root / "docs" / "index.md").read_text(encoding="utf-8")
    choose_section = homepage.split("## Choose your path\n", 1)[1].split("## Popular guides\n", 1)[0]
    popular_section = homepage.split("## Popular guides\n", 1)[1].split("## Safety boundary\n", 1)[0]

    assert re.findall(r"\]\(([^)]+)\)", choose_section) == [
        "getting-started/index.md",
        "operate/index.md",
        "services/index.md",
        "reference/index.md",
        "contribute/index.md",
        "project/index.md",
    ]
    assert re.findall(r"\]\(([^)]+)\)", popular_section) == [
        "operate/appliance-console.md",
        "operate/api.md",
        "operate/appliance-update.md",
        "services/dns.md",
        "services/ipxe.md",
        "services/vaults.md",
        "services/oidc-provider.md",
        "services/vsphere-key-providers.md",
    ]


def test_documentation_workflow_runs_on_every_main_push() -> None:
    """Verify that documentation publication is not limited by changed paths."""
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "docs.yml").read_text(encoding="utf-8")
    push_trigger = workflow.split("  push:\n", 1)[1].split("  workflow_dispatch:\n", 1)[0]

    assert "    branches:\n      - main\n" in push_trigger
    assert "paths:" not in push_trigger
    assert "paths-ignore:" not in push_trigger


def test_documentation_workflows_use_deterministic_build_wrapper() -> None:
    """Verify CI and publication cannot bypass the cache-safe strict build."""
    root = Path(__file__).resolve().parents[1]
    for relative in (".github/workflows/ci.yml", ".github/workflows/docs.yml"):
        workflow = (root / relative).read_text(encoding="utf-8")
        assert "python scripts/build_docs.py" in workflow
        assert "zensical build --clean --strict" not in workflow


def test_documentation_guide_uses_docs_interpreter_for_docs_checks() -> None:
    """Verify the isolated docs environment runs every dependency-backed docs check."""
    root = Path(__file__).resolve().parents[1]
    guide = (root / "docs" / "contribute" / "documentation-authoring.md").read_text(encoding="utf-8")

    assert ".\\.venv-docs\\Scripts\\python.exe scripts/build_docs.py" in guide
    assert ".\\.venv-docs\\Scripts\\python.exe scripts/check_docs.py" in guide


def test_documentation_build_resets_only_recognized_zensical_cache(tmp_path: Path) -> None:
    """Verify the wrapper clears its owned cache and rejects an unknown cache.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    cache = tmp_path / ".cache"
    cache.mkdir()
    (cache / ".gitignore").write_text("*\n", encoding="utf-8")
    (cache / "autorefs.json").write_text("{}\n", encoding="utf-8")
    (cache / "objects.inv").write_bytes(b"")
    (cache / "123456789").write_text("stale", encoding="utf-8")

    build_docs.reset_zensical_cache(tmp_path)

    assert not cache.exists()
    cache.mkdir()
    (cache / ".gitignore").write_text("*\n", encoding="utf-8")
    (cache / "unrelated-entry").write_text("keep", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unrecognized Zensical cache"):
        build_docs.reset_zensical_cache(tmp_path)
    assert (cache / "unrelated-entry").read_text(encoding="utf-8") == "keep"

    (cache / build_docs.CACHE_MARKER_NAME).write_text(
        build_docs.CACHE_MARKER_CONTENT,
        encoding="utf-8",
    )
    build_docs.reset_zensical_cache(tmp_path)
    assert not cache.exists()

    build_docs.initialize_zensical_cache(tmp_path)
    assert (cache / build_docs.CACHE_MARKER_NAME).read_text(encoding="utf-8") == (
        build_docs.CACHE_MARKER_CONTENT
    )


@pytest.mark.parametrize(
    "body",
    (
        "Continue to [Current](current.md).\n",
        "Continue to [Current][target].\n\n[target]: current.md\n",
        "Continue to [](current.md).\n",
        "Continue to [outer [inner]](current.md).\n",
        r"Continue to [escaped \]](current.md)." "\n",
        '<div markdown="1">[Current](current.md)</div>\n',
    ),
)
def test_redirect_stub_rejects_redundant_markdown_link(
    tmp_path: Path,
    monkeypatch,
    body: str,
) -> None:
    """Verify redirect sources cannot re-enter Zensical's unstable link index.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        body: Redirect body syntax to reject.
    """
    docs = tmp_path / "docs"
    docs.mkdir()
    redirect = docs / "moved.md"
    redirect.write_text(
        "---\ntitle: Moved\ndescription: Moved.\naudience:\n  - operator\n"
        "status: redirect\nredirect_to: current.md\n---\n\n# Moved\n\n"
        f"{body}",
        encoding="utf-8",
    )
    (docs / "current.md").write_text(
        "---\ntitle: Current\ndescription: Current.\naudience:\n  - operator\n"
        "status: current\n---\n\n# Current\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("scripts.check_docs.DOCS", docs)

    _, findings = validate_page(redirect, set())

    assert [finding.message for finding in findings] == [
        "redirect page body must not duplicate its target as a Markdown link",
    ]


def test_documentation_workflow_only_queues_pages_writer_for_changes() -> None:
    """Verify routine documentation checks cannot displace pending release publishers."""
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "docs.yml").read_text(encoding="utf-8")
    publish_job = workflow.split("  publish:\n", 1)[1]

    assert "    if: needs.verify.outputs.site_changed == 'true'\n" in publish_job
    assert "      group: atlaso-github-pages\n" in publish_job
    assert "      queue: max\n" in publish_job
    assert "      cancel-in-progress: false\n" in publish_job
    assert "  group: atlaso-github-pages\n" not in workflow.split("jobs:\n", 1)[0]


def test_documentation_overlay_preserves_release_repository(tmp_path: Path) -> None:
    """Verify that documentation overlay preserves release repository.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    pages = tmp_path / "pages"
    built = tmp_path / "built"
    (pages / "updates").mkdir(parents=True)
    (pages / "index.html").write_text("release landing", encoding="utf-8")
    (pages / "atlaso-logo.svg").write_text("logo", encoding="utf-8")
    (pages / "updates" / "manifest.json").write_text('{"signed": true}', encoding="utf-8")
    (pages / "docs").mkdir()
    (pages / "docs" / "stale.html").write_text("stale", encoding="utf-8")
    built.mkdir()
    (built / "index.html").write_text("documentation", encoding="utf-8")

    overlay(built, pages)

    assert (pages / "index.html").read_text(encoding="utf-8") == "release landing"
    assert (pages / "atlaso-logo.svg").read_text(encoding="utf-8") == "logo"
    assert json.loads((pages / "updates" / "manifest.json").read_text(encoding="utf-8")) == {"signed": True}
    assert (pages / "docs" / "index.html").read_text(encoding="utf-8") == "documentation"
    assert not (pages / "docs" / "stale.html").exists()


def test_checked_in_screenshot_manifest_is_valid() -> None:
    """Verify that checked in screenshot manifest is valid."""
    assert validate_screenshots() == []


@pytest.mark.parametrize(
    "filename, route, viewport",
    [
        ("ca-management-requests-clean-desktop.webp", "/ca/requests", "1600x1000"),
        ("ca-management-requests-clean-responsive.webp", "/ca/requests", "900x1200"),
    ],
)
def test_screenshot_manifest_generator_recognizes_certificate_request_captures(
    filename: str, route: str, viewport: str
) -> None:
    """Verify Certificate Requests captures retain their canonical metadata.

    Args:
        filename: Reviewed screenshot filename.
        route: Canonical route assigned to the screenshot.
        viewport: Expected screenshot viewport.
    """
    entry = generate_screenshot_manifest.metadata(
        generate_screenshot_manifest.SCREENSHOTS / filename
    )

    assert entry["route"] == route
    assert entry["documentation_page"] == "services/certificate-authority.md"
    assert entry["viewport"] == viewport


def test_screenshot_manifest_generator_rejects_unknown_slugs() -> None:
    """Verify unreviewed screenshot names fail with an actionable error."""
    with pytest.raises(ValueError, match="unknown screenshot slug: unknown-capture"):
        generate_screenshot_manifest.metadata(Path("unknown-capture.webp"))


def test_checked_in_screenshot_generators_are_byte_identical() -> None:
    """Verify the manifest and gallery match their canonical renderers."""
    manifest_text = generate_screenshot_manifest.MANIFEST.read_text(encoding="utf-8")
    payload = json.loads(manifest_text)

    assert generate_screenshot_manifest.render_manifest() == manifest_text
    assert generate_screenshot_gallery.render_gallery(payload) == (
        generate_screenshot_gallery.GALLERY.read_text(encoding="utf-8")
    )


@pytest.mark.parametrize(
    ("generator", "output_attribute"),
    [
        (generate_screenshot_manifest, "MANIFEST"),
        (generate_screenshot_gallery, "GALLERY"),
    ],
)
def test_screenshot_generator_check_mode_rejects_drift(
    tmp_path: Path,
    monkeypatch,
    generator,
    output_attribute: str,
) -> None:
    """Verify check mode detects stale output without rewriting it.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        generator: Screenshot generator module under test.
        output_attribute: Module output-path constant to replace.
    """
    stale_output = tmp_path / "stale-output"
    stale_output.write_text("stale\n", encoding="utf-8")
    monkeypatch.setattr(generator, output_attribute, stale_output)

    with pytest.raises(SystemExit) as exc_info:
        generator.main(["--check"])

    assert exc_info.value.code == 2
    assert stale_output.read_text(encoding="utf-8") == "stale\n"


def test_checked_in_markdown_uses_canonical_browser_routes() -> None:
    """Verify current guidance does not promote temporary root-level browser paths."""
    assert validate_legacy_browser_routes() == []


def test_browser_route_validation_covers_tracked_markdown() -> None:
    """Verify route validation covers every tracked non-vendored Markdown source."""
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.run(
        ["git", "ls-files", "--", "*.md"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    expected = {
        (root / relative).resolve()
        for relative in tracked
        if not relative.startswith("third_party/")
    }

    assert {path.resolve() for path in markdown_sources()} == expected


def test_documentation_check_rejects_retired_browser_routes(tmp_path: Path) -> None:
    """Verify a newly introduced root-level browser route fails validation.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    page = tmp_path / "example.md"
    page.write_text(
        "Open `/dashboard?scope=all` to review appliance state.\n"
        "Open https://atlaso.example/dashboard for the same view.\n"
        "Use the [Dashboard](https://atlaso.example/dashboard?scope=all) bookmark.\n"
        'Open "https://atlaso.example/dashboard" in a browser.\n'
        "Open HTTPS://atlaso.example/dashboard with an uppercase scheme.\n"
        "Open **/dashboard** from emphasized guidance.\n"
        "Open **https://atlaso.example/dashboard** from an emphasized URL.\n"
        "Use <code>/dashboard</code> in raw HTML.\n"
        "Open https://atlaso.example/%64ashboard after decoding.\n"
        "Open /%64ashboard after decoding.\n"
        "Use [Dashboard](//atlaso.example/dashboard) on the current scheme.\n"
        "Open https://atlaso.example/guide/../dashboard after normalization.\n"
        "Open /guide/../dashboard after normalization.\n"
        "Open https://atlaso.example\\dashboard after backslash normalization.\n"
        "Open https:\\atlaso.example\\dashboard after backslash normalization.\n"
        'Use <a href="\\dashboard">Dashboard</a> after root-path normalization.\n'
        "Open /./dashboard after leading-dot normalization.\n"
        "Open \\.\\dashboard after leading-dot normalization.\n"
        "Open https:/dashboard as a same-host path.\n"
        "Open https:\\dashboard as a same-host path.\n"
        "Open https:dashboard as a same-scheme path.\n"
        "Open https:dashboard?scope=all with a query.\n"
        "Open https:/dashboard#review with a fragment.\n",
        encoding="utf-8",
    )

    findings = validate_legacy_browser_routes([page])

    assert len(findings) == 23
    assert findings[0].line == 1
    assert findings[0].message.endswith(": /dashboard?scope=all")
    assert findings[1].line == 2
    assert findings[1].message.endswith(": https://atlaso.example/dashboard")
    assert findings[2].line == 3
    assert findings[2].message.endswith(": https://atlaso.example/dashboard?scope=all")
    assert findings[3].line == 4
    assert findings[3].message.endswith(": https://atlaso.example/dashboard")
    assert findings[4].line == 5
    assert findings[4].message.endswith(": HTTPS://atlaso.example/dashboard")
    assert findings[5].line == 6
    assert findings[5].message.endswith(": /dashboard")
    assert findings[6].line == 7
    assert findings[6].message.endswith(": https://atlaso.example/dashboard")
    assert findings[7].line == 8
    assert findings[7].message.endswith(": /dashboard")
    assert findings[8].line == 9
    assert findings[8].message.endswith(": https://atlaso.example/%64ashboard")
    assert findings[9].line == 10
    assert findings[9].message.endswith(": /%64ashboard")
    assert findings[10].line == 11
    assert findings[10].message.endswith(": //atlaso.example/dashboard")
    assert findings[11].line == 12
    assert findings[11].message.endswith(": https://atlaso.example/guide/../dashboard")
    assert findings[12].line == 13
    assert findings[12].message.endswith(": /guide/../dashboard")
    assert findings[13].line == 14
    assert findings[13].message.endswith(": https://atlaso.example\\dashboard")
    assert findings[14].line == 15
    assert findings[14].message.endswith(": https:\\atlaso.example\\dashboard")
    assert findings[15].line == 16
    assert findings[15].message.endswith(": \\dashboard")
    assert findings[16].line == 17
    assert findings[16].message.endswith(": /./dashboard")
    assert findings[17].line == 18
    assert findings[17].message.endswith(": \\.\\dashboard")
    assert findings[18].line == 19
    assert findings[18].message.endswith(": https:/dashboard")
    assert findings[19].line == 20
    assert findings[19].message.endswith(": https:\\dashboard")
    assert findings[20].line == 21
    assert findings[20].message.endswith(": https:dashboard")
    assert findings[21].line == 22
    assert findings[21].message.endswith(": https:dashboard?scope=all")
    assert findings[22].line == 23
    assert findings[22].message.endswith(": https:/dashboard#review")

    page.write_text(
        "Open `/ui/management/dashboard` or https://atlaso.example/ui/management/dashboard.\n"
        "Read [Vaults](../services/vaults.md) for details.\n"
        "Check [health](//monitor/status) on its protocol-relative authority.\n",
        encoding="utf-8",
    )
    assert validate_legacy_browser_routes([page]) == []


def test_screenshot_canonical_routes_are_idempotent() -> None:
    """Verify documentation generators preserve already canonical browser routes."""
    route = "/ui/management/physical-interfaces"

    assert generate_embedded_screenshot_sections.canonical_route(route) == route
    assert generate_screenshot_gallery.canonical_route(route) == route
    assert generate_embedded_screenshot_sections.route_title(route) == "Physical interfaces"
    assert generate_screenshot_gallery.route_title(route) == "Physical Interfaces"
    assert generate_screenshot_gallery.route_title(
        "/ui/management/vsphere-key-providers"
    ) == "vSphere Key Providers"


def test_embedded_screenshot_generation_is_idempotent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Verify that embedded screenshot generation is idempotent.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    docs = tmp_path / "docs"
    page = docs / "operate" / "example.md"
    page.parent.mkdir(parents=True)
    page.write_text(
        "---\n"
        "title: Example\n"
        "description: Example page.\n"
        "audience:\n"
        "  - operator\n"
        "status: current\n"
        "---\n\n"
        "# Example\n\n"
        "Keep this introduction.\n\n"
        "Keep this second paragraph too.\n\n"
        "## Existing section\n\n"
        "Existing instructions remain intact.\n",
        encoding="utf-8",
    )
    manifest = docs / "assets" / "screenshots" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "screenshots": [
                    {
                        "path": "assets/screenshots/example-desktop.webp",
                        "route": "/example",
                        "caption": "Example desktop state.",
                        "alt": "Example desktop interface.",
                        "documentation_page": "operate/example.md",
                    },
                    {
                        "path": "assets/screenshots/example-responsive.webp",
                        "route": "/example",
                        "caption": "Example responsive state.",
                        "alt": "Example responsive interface.",
                        "documentation_page": "operate/example.md",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(generate_embedded_screenshot_sections, "DOCS", docs)
    monkeypatch.setattr(generate_embedded_screenshot_sections, "MANIFEST", manifest)
    monkeypatch.setattr(
        generate_embedded_screenshot_sections,
        "PRIMARY_IMAGES",
        {"operate/example.md": "example-desktop.webp"},
    )

    generate_embedded_screenshot_sections.main()
    first = page.read_text(encoding="utf-8")
    generate_embedded_screenshot_sections.main()

    assert page.read_text(encoding="utf-8") == first
    assert "Keep this second paragraph too." in first
    assert first.count("## Interface overview") == 1
    assert first.count("## Additional verified states") == 1


def test_appliance_apply_operator_guide_stays_task_focused() -> None:
    """Verify that appliance apply operator guide stays task focused."""
    root = Path(__file__).resolve().parents[1]
    operator_page = (root / "docs" / "operate" / "appliance-apply.md").read_text(encoding="utf-8")
    technical_page = (root / "docs" / "reference" / "appliance-apply-technical.md").read_text(encoding="utf-8")
    headings = {line for line in operator_page.splitlines() if line.startswith("## ")}

    assert {
        "## Before you begin",
        "## Review pending changes",
        "## Submit and monitor",
        "## Verify the result",
        "## Recover from a failed apply",
        "## Safety boundaries",
        "## Complete technical contents",
    } <= headings
    assert len(operator_page.splitlines()) < 200
    assert "../reference/appliance-apply-technical.md" in operator_page
    assert "No original section was removed." in operator_page
    assert "Every helper or adapter command in that component" in operator_page
    technical_headings = {line for line in technical_page.splitlines() if line.startswith("#")}
    assert {
        "## Workflow and execution model",
        "## Appliance and network units",
        "## Infrastructure and security units",
        "## Appliance settings and operations",
        "## State, results, and interface contracts",
        "### Workflow architecture",
        "### Local Users apply",
        "### DNS/DHCP apply",
        "### Job result",
        "### UI expectations",
    } <= technical_headings
