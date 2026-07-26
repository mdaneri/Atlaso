import json
from pathlib import Path

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
