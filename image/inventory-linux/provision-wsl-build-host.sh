#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 4 ]]; then
  echo "usage: provision-wsl-build-host.sh <contract-version> <base-sha256> <build-user> <package>..." >&2
  exit 2
fi

contract_version="$1"
base_sha256="$2"
build_user="$3"
shift 3
packages=("$@")

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Atlaso WSL build-host provisioning must run as root inside the dedicated distribution." >&2
  exit 3
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends "${packages[@]}"

if ! id -u "${build_user}" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "${build_user}"
fi

build_home="$(getent passwd "${build_user}" | cut -d: -f6)"
if [[ -z "${build_home}" || ! -d "${build_home}" ]]; then
  echo "Atlaso WSL build user does not have a valid home directory." >&2
  exit 4
fi

install -d -o root -g root -m 0755 /var/lib/atlaso-build
python3 - "${contract_version}" "${base_sha256}" "${build_user}" "${packages[@]}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

contract_version, base_sha256, build_user, *packages = sys.argv[1:]
versions = {}
for package in packages:
    version = subprocess.check_output(
        ["dpkg-query", "-W", "-f=${Version}", package],
        text=True,
    ).strip()
    versions[package] = version

marker = {
    "schema_version": 1,
    "contract_version": contract_version,
    "base_sha256": base_sha256,
    "build_user": build_user,
    "package_versions": versions,
}
path = Path("/var/lib/atlaso-build/contract.json")
path.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o644)
PY

chown -R "${build_user}:${build_user}" "${build_home}"
printf 'Atlaso WSL build distribution is provisioned for contract %s.\n' "${contract_version}"
