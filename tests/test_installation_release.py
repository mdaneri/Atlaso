"""Exercise installation release admission and publication boundary checks."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(".github/workflows/installation-prerelease.yml").resolve()


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def _admission_code(marker: str) -> str:
    steps = _workflow()["jobs"]["finalize"]["steps"]
    shell = next(step["run"] for step in steps if step.get("id") == "admission")
    snippets = re.findall(r"^\s*python -[^\n]*<<'PY'\n(.*?)^PY$", shell, re.MULTILINE | re.DOTALL)
    return next(code for code in snippets if marker in code)


@pytest.mark.parametrize("sha,tag", [("short", "installation-v0.9.454-rc.1"), ("a" * 40, "v0.9.454"), ("a" * 40, "installation-v0.9.454-rc.0")])
def test_release_identity_rejects_nonexact_or_noninstallation_tags(monkeypatch, tmp_path, sha, tag):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["-", sha, tag])
    with pytest.raises(SystemExit):
        exec(compile(_admission_code("release_sha must"), str(WORKFLOW), "exec"), {})
    assert not (tmp_path / "installation.env").exists()


@pytest.mark.parametrize("assets", [[], [{"name": "installation-artifact-index.json.sig", "size": 20}], [{"name": "unrelated.iso", "size": 20}], [{"name": "installation-inputs.tar.gz", "size": 19 * 1024**3}], [{"name": "installation-inputs.tar.gz", "size": 20}] * 2])
def test_unsigned_admission_rejects_partial_colliding_or_oversized_assets(monkeypatch, tmp_path, assets):
    code = _admission_code("candidate draft is incomplete")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "candidate-release.json").write_text(json.dumps({"assets": assets}))
    with pytest.raises(SystemExit):
        exec(compile(code, str(WORKFLOW), "exec"), {})


def test_publication_requires_the_exact_signed_asset_set(monkeypatch, tmp_path):
    code = _admission_code("candidate contains extra")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "final").mkdir()
    index = {"asset_manifest": {"assets": [{"name": "atlaso.iso.part0001"}]}, "verifier": {"name": "verify-installation.pyz"}}
    (tmp_path / "final/installation-artifact-index.json").write_text(json.dumps(index))
    names = ["atlaso.iso.part0001", "installation-artifact-index.json", "installation-artifact-index.json.sig", "verify-installation.pyz"]
    release = tmp_path / "candidate-release.json"
    release.write_text(json.dumps({"assets": [{"name": name} for name in names]}))
    exec(compile(code, str(WORKFLOW), "exec"), {})
    for altered in (names[:-1], [*names, "installation-inputs.tar.gz"]):
        release.write_text(json.dumps({"assets": [{"name": name} for name in altered]}))
        with pytest.raises(SystemExit):
            exec(compile(code, str(WORKFLOW), "exec"), {})


def test_signing_staging_and_publication_use_separate_protected_gates():
    job = _workflow()["jobs"]["finalize"]
    assert job["runs-on"] == "ubuntu-latest"
    assert job["environment"] == "appliance-release"
    steps = job["steps"]
    admission = next(step for step in steps if step.get("id") == "admission")
    key_step = next(step for step in steps if step.get("name") == "Materialize protected signing key")
    stage = next(step for step in steps if step.get("name") == "Stage only the signed prerelease asset set")
    publication = next(step for step in steps if step.get("name") == "Publish maintainer-validated exact ISO")
    assert steps.index(admission) < steps.index(key_step) < steps.index(stage) < steps.index(publication)
    assert key_step["if"] == stage["if"] == "steps.admission.outputs.build == 'true'"
    assert "inputs.publish" in publication["if"] and "steps.admission.outputs.build != 'true'" in publication["if"]
    assert 'test "$PUBLISH" != true' in admission["run"]
    assert '"$VALIDATED_ISO_SHA256"' in admission["run"]
    assert "--draft=false --prerelease --latest=false" in publication["run"]
    assert not any("cache" in step.get("with", {}) for step in steps)
