#!/usr/bin/env python3
"""Validate Atlaso documentation metadata, navigation, links, and media."""

from __future__ import annotations

import importlib.util
import json
import posixpath
import re
import subprocess
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Iterable
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
CONFIG = ROOT / "zensical.toml"
ALLOWED_AUDIENCES = {"operator", "contributor", "maintainer"}
ALLOWED_STATUSES = {"current", "roadmap", "historical", "redirect"}
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
LINK_RE = re.compile(r"!?\[[^\]]+\]\(([^)]+)\)")
IMAGE_RE = re.compile(r"!\[[^\]]+\]\(([^)]+)\)")
ABSOLUTE_URL_RE = re.compile(r'''(?:https?:[\\/]{1,2}|//)[^\s<>()`\[\]"']+''', re.IGNORECASE)
BROWSER_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9.])"
    r"(?P<path>/[A-Za-z0-9%][A-Za-z0-9._~{}%*-]*"
    r"(?:/[A-Za-z0-9._~{}%*-]+)*"
    r"(?:\?[A-Za-z0-9._~{}*=&%+-]*)?)"
)
LEGACY_BROWSER_ROUTE_ALLOWLIST = {
    "docs/project/appliance-console-design-qa.md": {
        "https://192.168.167.219/esx-storage",
    },
    "docs/project/github-project.md": {
        "https://github.com/users/mdaneri/projects/5",
    },
    "docs/project/monitor-apply-ux-design-qa.md": {
        "https://192.168.167.219/monitor",
    },
    "docs/project/ui-compliance-matrix.md": {
        "/services/{service}/logs",
    },
    "docs/reference/full-technical-reference.md": {
        "/certificate-authority/.../downloads",
    },
    "docs/services/ipxe.md": {
        "/esxi-pxe",
    },
    "docs/services/public-services.md": {
        "/certificate-authority/.../downloads/",
    },
    "docs/services/vcf-trust.md": {
        "/vcf-helper/trust-root-ca",
        "/vcf-trust",
        "/vcf-trust/root-ca",
    },
}
MARKDOWN_ROUTE_EXCLUDED_PREFIXES = ("third_party/",)


@dataclass(frozen=True)
class Finding:
    """Represent finding.

    Attributes:
        path: Path maintained by this finding.
        message: Message maintained by this finding.
        line: Line maintained by this finding.
    """
    path: Path
    message: str
    line: int | None = None

    def render(self) -> str:
        """Render operation.

        Returns:
            The render result.
        """
        path = self.path.relative_to(ROOT)
        return f"{path}:{self.line}: {self.message}" if self.line else f"{path}: {self.message}"


def load_ui_routes() -> ModuleType:
    """Load the browser-route contract without importing the Atlaso application package.

    Returns:
        The loaded ``atlaso.app.ui_routes`` module.
    """
    path = ROOT / "atlaso" / "app" / "ui_routes.py"
    spec = importlib.util.spec_from_file_location("_atlaso_ui_routes_for_docs", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load browser-route contract: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def markdown_sources() -> list[Path]:
    """Return every checked-in Markdown source covered by documentation validation."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    relative_paths = result.stdout.decode("utf-8").split("\0")
    return sorted(
        ROOT / relative
        for relative in relative_paths
        if relative
        and not relative.startswith(MARKDOWN_ROUTE_EXCLUDED_PREFIXES)
    )


def browser_route_candidates(line: str) -> list[tuple[str, str]]:
    """Return display values and request paths found in one Markdown line.

    Args:
        line: Markdown source line to inspect.
    """
    candidates: list[tuple[str, str]] = []
    for match in ABSOLUTE_URL_RE.finditer(line):
        candidate = strip_markdown_wrappers(line, match.start(), match.group(0).rstrip(".,:;"))
        browser_url = candidate.replace("\\", "/")
        browser_url = re.sub(r"^(https?:)/+", r"\1//", browser_url, flags=re.IGNORECASE)
        route_path = normalize_browser_path(urlparse(browser_url).path)
        if route_path:
            candidates.append((candidate, route_path))
    for match in BROWSER_PATH_RE.finditer(line):
        candidate = strip_markdown_wrappers(line, match.start("path"), match.group("path").rstrip(".,:;"))
        candidates.append((candidate, normalize_browser_path(urlparse(candidate).path)))
    return candidates


def normalize_browser_path(path: str) -> str:
    """Decode and remove browser-equivalent dot segments from a URL path.

    Args:
        path: Parsed URL path to normalize.

    Returns:
        A decoded absolute path with dot segments removed.
    """
    decoded = unquote(path)
    normalized = posixpath.normpath(decoded)
    return f"/{normalized.lstrip('/')}" if decoded.startswith("/") else normalized


def strip_markdown_wrappers(line: str, start: int, candidate: str) -> str:
    """Remove matching Markdown emphasis delimiters surrounding a URL candidate.

    Args:
        line: Markdown source line containing the candidate.
        start: Candidate start offset in the line.
        candidate: Extracted URL or root-relative path.

    Returns:
        The candidate without matching attached Markdown emphasis delimiters.
    """
    prefix = line[:start]
    for delimiter in ("***", "___", "**", "__", "~~", "*", "_"):
        if prefix.endswith(delimiter) and candidate.endswith(delimiter):
            return candidate[: -len(delimiter)]
    return candidate


def validate_legacy_browser_routes(paths: Iterable[Path] | None = None) -> list[Finding]:
    """Reject unqualified retired browser paths in checked-in Markdown.

    Args:
        paths: Optional Markdown sources to validate instead of the repository inventory.

    Returns:
        Findings for legacy browser paths that are not explicitly allowlisted.
    """
    ui_routes = load_ui_routes()
    findings: list[Finding] = []
    allowed_counts: Counter[tuple[str, str]] = Counter()
    enforce_allowlist_inventory = paths is None
    sources = paths if paths is not None else markdown_sources()
    for path in sources:
        relative = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.as_posix()
        allowed = LEGACY_BROWSER_ROUTE_ALLOWLIST.get(relative, set())
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for candidate, route_path in browser_route_candidates(line):
                if ui_routes.legacy_browser_target(route_path) is None:
                    continue
                if candidate in allowed:
                    allowed_counts[(relative, candidate)] += 1
                    continue
                findings.append(
                    Finding(
                        path,
                        f"retired browser path must use its canonical namespace: {candidate}",
                        number,
                    )
                )
    if enforce_allowlist_inventory:
        for relative, candidates in LEGACY_BROWSER_ROUTE_ALLOWLIST.items():
            for candidate in candidates:
                count = allowed_counts[(relative, candidate)]
                if count != 1:
                    findings.append(
                        Finding(
                            ROOT / relative,
                            f"allowlisted retired browser path must appear exactly once: {candidate} (found {count})",
                        )
                    )
    return findings


def parse_front_matter(path: Path, text: str) -> tuple[dict[str, object], str, list[Finding]]:
    """Parse front matter.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        text: Text to parse, render, or persist.

    Returns:
        The parsed front matter.
    """
    findings: list[Finding] = []
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return {}, text, [Finding(path, "missing YAML front matter", 1)]
    try:
        end = lines.index("---", 1)
    except ValueError:
        return {}, text, [Finding(path, "unclosed YAML front matter", 1)]

    data: dict[str, object] = {}
    current_list: str | None = None
    for number, line in enumerate(lines[1:end], start=2):
        if line.startswith("  - ") and current_list:
            value = line[4:].strip()
            cast = data.setdefault(current_list, [])
            assert isinstance(cast, list)
            cast.append(value)
            continue
        current_list = None
        if not line.strip():
            continue
        if ":" not in line:
            findings.append(Finding(path, "invalid front-matter entry", number))
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value:
            data[key] = value.strip("\"'")
        else:
            data[key] = []
            current_list = key
    return data, "\n".join(lines[end + 1 :]), findings


def headings(text: str) -> list[tuple[int, int, str]]:
    """Return headings.

    Args:
        text: Text content consumed by the operation.
    """
    result: list[tuple[int, int, str]] = []
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            result.append((number, len(match.group(1)), match.group(2).strip().rstrip("#").strip()))
    return result


def slug(value: str) -> str:
    """Return slug.

    Args:
        value: Candidate value consumed by slug.
    """
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"[^\w\s-]", "", value.lower())
    return re.sub(r"[-\s]+", "-", value).strip("-")


def anchors(path: Path) -> set[str]:
    """Return anchors.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    text = path.read_text(encoding="utf-8")
    _, body, _ = parse_front_matter(path, text) if path.is_relative_to(DOCS) else ({}, text, [])
    counts: dict[str, int] = {}
    result: set[str] = set()
    for _, _, title in headings(body):
        base = slug(title)
        count = counts.get(base, 0)
        counts[base] = count + 1
        result.add(base if count == 0 else f"{base}_{count}")
    return result


def nav_paths(value: object) -> set[str]:
    """Return nav paths.

    Args:
        value: Candidate value consumed by nav paths.
    """
    result: set[str] = set()
    if isinstance(value, str):
        result.add(value)
    elif isinstance(value, list):
        for item in value:
            result.update(nav_paths(item))
    elif isinstance(value, dict):
        for item in value.values():
            result.update(nav_paths(item))
    return result


def validate_page(path: Path, nav: set[str]) -> tuple[dict[str, object], list[Finding]]:
    """Validate page.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        nav: Nav supplied by the caller.

    Returns:
        The validate page result.
    """
    text = path.read_text(encoding="utf-8")
    meta, body, findings = parse_front_matter(path, text)
    for field in ("title", "description", "audience", "status"):
        if not meta.get(field):
            findings.append(Finding(path, f"missing required metadata: {field}"))

    audiences = meta.get("audience")
    if not isinstance(audiences, list) or not set(audiences).issubset(ALLOWED_AUDIENCES):
        findings.append(Finding(path, f"audience must use only {sorted(ALLOWED_AUDIENCES)}"))
    status = meta.get("status")
    if status not in ALLOWED_STATUSES:
        findings.append(Finding(path, f"status must be one of {sorted(ALLOWED_STATUSES)}"))

    page_headings = headings(body)
    h1 = [(line, title) for line, level, title in page_headings if level == 1]
    if len(h1) != 1:
        findings.append(Finding(path, "page must contain exactly one level-one heading"))
    elif h1[0][1] != meta.get("title"):
        findings.append(Finding(path, f"level-one heading must match title metadata: {meta.get('title')}", h1[0][0]))

    relative = path.relative_to(DOCS).as_posix()
    if status == "redirect":
        target = meta.get("redirect_to")
        if not isinstance(target, str) or not target:
            findings.append(Finding(path, "redirect page requires redirect_to"))
        elif not (DOCS / target).is_file():
            findings.append(Finding(path, f"redirect target does not exist: {target}"))
    elif relative not in nav:
        findings.append(Finding(path, "canonical page is missing from Zensical navigation"))
    return meta, findings


def validate_links(path: Path) -> list[Finding]:
    """Validate links.

    Args:
        path: Filesystem or URL path to read, validate, or update.

    Returns:
        The validate links result.
    """
    findings: list[Finding] = []
    text = path.read_text(encoding="utf-8")
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in LINK_RE.finditer(line):
            target = match.group(1).strip().strip("<>")
            parsed = urlparse(target)
            if parsed.scheme or target.startswith(("mailto:", "/")):
                continue
            file_part, separator, fragment = target.partition("#")
            destination = path if not file_part else (path.parent / unquote(file_part)).resolve()
            if not destination.is_file():
                findings.append(Finding(path, f"local link target does not exist: {target}", number))
                continue
            if separator and fragment and destination.suffix.lower() == ".md":
                expected = unquote(fragment).lower()
                if expected not in anchors(destination):
                    findings.append(Finding(path, f"Markdown anchor does not exist: {target}", number))
    return findings


def webp_dimensions(path: Path) -> tuple[int, int]:
    """Return webp dimensions.

    Args:
        path: Filesystem or URL path to read, validate, or update.

    Raises:
        ValueError: If an input value is invalid.
    """
    data = path.read_bytes()
    if len(data) < 30 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise ValueError("invalid WebP header")
    offset = 12
    while offset + 8 <= len(data):
        chunk_type = data[offset : offset + 4]
        chunk_size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        payload = data[offset + 8 : offset + 8 + chunk_size]
        if chunk_type == b"VP8X" and len(payload) >= 10:
            width = int.from_bytes(payload[4:7], "little") + 1
            height = int.from_bytes(payload[7:10], "little") + 1
            return width, height
        if chunk_type == b"VP8L" and len(payload) >= 5 and payload[0] == 0x2F:
            bits = int.from_bytes(payload[1:5], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        if chunk_type == b"VP8 " and len(payload) >= 10 and payload[3:6] == b"\x9d\x01\x2a":
            width = int.from_bytes(payload[6:8], "little") & 0x3FFF
            height = int.from_bytes(payload[8:10], "little") & 0x3FFF
            return width, height
        offset += 8 + chunk_size + (chunk_size % 2)
    raise ValueError("WebP dimensions are unavailable")


def webp_has_metadata(path: Path) -> bool:
    """Return webp has metadata.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    data = path.read_bytes()
    offset = 12
    while offset + 8 <= len(data):
        chunk_type = data[offset : offset + 4]
        chunk_size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        if chunk_type in {b"EXIF", b"XMP "}:
            return True
        offset += 8 + chunk_size + (chunk_size % 2)
    return False


def validate_screenshots() -> list[Finding]:
    """Validate screenshots.

    Returns:
        The validate screenshots result.
    """
    manifest_path = DOCS / "assets" / "screenshots" / "manifest.json"
    if not manifest_path.is_file():
        return [Finding(manifest_path, "screenshot manifest is missing")]
    findings: list[Finding] = []
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [Finding(manifest_path, f"invalid screenshot manifest: {exc}")]
    required = {
        "path",
        "route",
        "state",
        "viewport",
        "source_commit",
        "atlaso_version",
        "caption",
        "alt",
        "capture_method",
        "documentation_page",
        "brand_variant",
        "sensitive_data_reviewed",
    }
    listed: set[str] = set()
    for index, entry in enumerate(payload.get("screenshots", []), start=1):
        missing = sorted(required - set(entry))
        if missing:
            findings.append(Finding(manifest_path, f"screenshot {index} missing fields: {', '.join(missing)}"))
            continue
        relative = entry["path"]
        if relative in listed:
            findings.append(Finding(manifest_path, f"screenshot path is listed more than once: {relative}"))
        listed.add(relative)
        image = DOCS / relative
        if image.suffix.lower() != ".webp":
            findings.append(Finding(manifest_path, f"screenshot must be WebP: {relative}"))
        if not image.is_file():
            findings.append(Finding(manifest_path, f"screenshot file is missing: {relative}"))
        elif image.stat().st_size > 1_500_000:
            findings.append(Finding(image, "screenshot exceeds 1.5 MB"))
        elif entry["viewport"] not in {"1600x1000", "900x1200"}:
            findings.append(Finding(manifest_path, f"unsupported screenshot viewport: {entry['viewport']}"))
        else:
            try:
                dimensions = webp_dimensions(image)
            except ValueError as exc:
                findings.append(Finding(image, f"invalid WebP image: {exc}"))
            else:
                expected = tuple(map(int, entry["viewport"].split("x")))
                if dimensions != expected:
                    findings.append(
                        Finding(
                            image,
                            f"screenshot dimensions do not match viewport {entry['viewport']}: {dimensions}",
                        )
                    )
                if webp_has_metadata(image):
                    findings.append(Finding(image, "screenshot contains EXIF or XMP metadata"))
        for field in ("route", "state", "source_commit", "atlaso_version", "caption", "alt", "capture_method"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                findings.append(Finding(manifest_path, f"screenshot has an empty {field}: {relative}"))
        if entry["sensitive_data_reviewed"] is not True:
            findings.append(Finding(manifest_path, f"screenshot is not marked reviewed: {relative}"))
        documentation_page = entry["documentation_page"]
        if not isinstance(documentation_page, str) or not documentation_page.strip():
            findings.append(Finding(manifest_path, f"screenshot has no documentation page: {relative}"))
        else:
            page = DOCS / documentation_page
            if not page.is_file():
                findings.append(Finding(manifest_path, f"screenshot documentation page is missing: {documentation_page}"))
            else:
                linked = {
                    (page.parent / match.group(1)).resolve()
                    for match in IMAGE_RE.finditer(page.read_text(encoding="utf-8"))
                }
                if image.resolve() not in linked:
                    findings.append(
                        Finding(
                            page,
                            f"assigned screenshot is not embedded in this page: {relative}",
                        )
                    )
    files = {
        path.relative_to(DOCS).as_posix()
        for path in (DOCS / "assets" / "screenshots").rglob("*.webp")
    }
    for orphan in sorted(files - listed):
        findings.append(Finding(DOCS / orphan, "screenshot is not listed in the manifest"))
    return findings


def main() -> int:
    """Run the command-line entry point.

    Returns:
        The main result.
    """
    config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    nav = nav_paths(config["project"]["nav"])
    findings: list[Finding] = []
    for path in sorted(DOCS.rglob("*.md")):
        _, page_findings = validate_page(path, nav)
        findings.extend(page_findings)
        findings.extend(validate_links(path))
    findings.extend(validate_legacy_browser_routes())
    findings.extend(validate_screenshots())
    if findings:
        print(f"Documentation checks failed with {len(findings)} issue(s):", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding.render()}", file=sys.stderr)
        return 1
    print(f"Documentation checks passed for {len(list(DOCS.rglob('*.md')))} page(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
