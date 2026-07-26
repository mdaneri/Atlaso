import json
from pathlib import Path

from scripts import generate_embedded_screenshot_sections
from scripts.check_docs import validate_screenshots
from scripts.overlay_docs_site import overlay


def test_documentation_overlay_preserves_release_repository(tmp_path: Path) -> None:
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
    assert validate_screenshots() == []


def test_embedded_screenshot_generation_is_idempotent(
    tmp_path: Path,
    monkeypatch,
) -> None:
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
    } <= headings
    assert len(operator_page.splitlines()) < 200
    assert "../reference/appliance-apply-technical.md" in operator_page
    assert "## Local Users Apply" not in operator_page
    assert "## Local Users Apply" in technical_page
