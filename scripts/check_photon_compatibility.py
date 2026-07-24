"""Check LabFoundry's runtime shape on Photon OS."""

from __future__ import annotations

import compileall
import importlib
import importlib.metadata
import os
import platform
import sys
import tempfile
from pathlib import Path


DEPENDENCY_IMPORTS = [
    "argon2",
    "cryptography",
    "fastapi",
    "itsdangerous",
    "jinja2",
    "joserfc",
    "jwt",
    "kmip",
    "multipart",
    "pydantic_settings",
    "sqlalchemy",
    "uvicorn",
    "pyVmomi",
    "com.vmware.vcenter",
]

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    print(f"python={platform.python_version()} executable={sys.executable}")
    if sys.version_info[:2] != (3, 14):
        print("Photon compatibility requires Python 3.14", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="labfoundry-photon-") as temp_dir:
        db_path = Path(temp_dir) / "labfoundry.db"
        os.environ.setdefault("LABFOUNDRY_ENVIRONMENT", "photon-compat")
        os.environ.setdefault("LABFOUNDRY_DATABASE_URL", f"sqlite:///{db_path}")
        os.environ.setdefault("LABFOUNDRY_SECRET_KEY", "photon-compat-secret-key-change-me")
        os.environ.setdefault("LABFOUNDRY_BOOTSTRAP_ADMIN_PASSWORD", "photon-compat-admin")
        os.environ.setdefault("LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS", "true")

        for module_name in DEPENDENCY_IMPORTS:
            importlib.import_module(module_name)
            print(f"import ok: {module_name}")
        vcf_sdk_version = importlib.metadata.version("vcf-sdk")
        if vcf_sdk_version != "9.1.0.0":
            print(f"VCF SDK 9.1.0.0 is required; found {vcf_sdk_version}", file=sys.stderr)
            return 1
        print(f"vcf-sdk={vcf_sdk_version}")

        from labfoundry.app.config import get_settings

        get_settings.cache_clear()

        from labfoundry.app.database import SessionLocal, engine, init_db
        from labfoundry.app.seed import seed_initial_data

        init_db()
        with SessionLocal() as db:
            seed_initial_data(db)
        engine.dispose()
        print(f"sqlite init ok: {db_path}")

    labfoundry_package = PROJECT_ROOT / "labfoundry"
    if not compileall.compile_dir(str(labfoundry_package), quiet=1):
        print("compileall failed for labfoundry", file=sys.stderr)
        return 1
    print(f"compileall ok: {labfoundry_package}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
