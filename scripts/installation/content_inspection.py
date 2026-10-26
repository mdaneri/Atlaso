"""Reuse existing offline validators for bounded installed-content measurements."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import textwrap
import zlib
from pathlib import Path
from typing import Any

from scripts import verify_virtualization_guest_wheel as wheel_verifier
from scripts.installation.layout import PROFILE

KINDS = ("assets", "python", "powercli", "rpm", "notices")
SOURCE_MEMBERS = (
    "source/image/common/scripts/provision-atlaso.sh",
    "source/scripts/verify_virtualization_guest_wheel.py",
    "source/image/common/powershell/powercli-lock.json",
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}\Z")
_RUNTIME_ROOTS = {"bin", "releases", "current", ".venv", "build-info.json"}
_RSYNC_EXCLUDES = {".git", ".venv", ".pytest_cache", "data", "test-results"}
_VMWARE_SOURCES = {
    "scripts/appliance/atlaso-vmware-ovf-customize.py",
    "image/vmware-workstation/systemd/atlaso-vmware-ovf-customize.service",
    "image/vmware-workstation/systemd/atlaso-vmware-ovf-prepare.service",
}
_COMMON_KEYS = {"schema", "kind", "iso_sha256"}
_EXPECTED_EXTRA = {
    "assets": {"environment_verifier_sha256", "source_digest", "source_file_count", "trust_names", "trust_digest", "omitted_sources", "deployed_file_count"},
    "python": {"software_verifier_sha256", "environment_verifier_sha256", "release_manifest_sha256", "version", "source_commit", "wheel_sha256"},
    "powercli": {"powercli_script_sha256", "powercli_lock_sha256", "module_count"},
    "rpm": {"package_state_sha256", "allowed_inventory", "required_packages"},
    "notices": {"notice_generator_sha256", "notice_config_sha256", "notice_lock_sha256", "version"},
}


def _canonical_digest(records: dict[str, str]) -> str:
    """Hash a public path/content inventory using the existing module convention.

    Args:
        records: Relative public paths and their SHA-256 content digests.
    """
    return hashlib.sha256("".join(f"{name}\0{records[name]}\n" for name in sorted(records)).encode()).hexdigest()


def _compressed(value: Any) -> str:
    """Encode a bounded public inventory without expanding console commands.

    Args:
        value: Public package records or package names.
    """
    return base64.b64encode(zlib.compress(json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), 9)).decode()


def _decode_inventory(value: str) -> Any:
    """Decode one capped public package inventory.

    Args:
        value: Base64-encoded compressed JSON inventory.
    """
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("content inventory exceeds its encoded bound")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(value, validate=True), 131073)
    if len(raw) > 131072 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("content inventory exceeds its decoded bound")
    return json.loads(raw)


def _package_inventory(value: Any) -> dict[str, list[str]]:
    """Require a bounded public name/version/architecture inventory.

    Args:
        value: Decoded installed or media RPM identity mapping.
    """
    if not isinstance(value, dict) or not 1 <= len(value) <= 1024:
        raise ValueError("content package inventory is invalid")
    for name, identity in value.items():
        if (not isinstance(name, str) or not _PACKAGE.fullmatch(name)
                or not isinstance(identity, list) or len(identity) != 2
                or not isinstance(identity[0], str) or not re.fullmatch(r"[A-Za-z0-9+._:~^-]{1,192}", identity[0])
                or not isinstance(identity[1], str) or identity[1] not in {"x86_64", "noarch"}):
            raise ValueError("content package inventory is invalid")
    return value


def prepare_content_inputs(base: dict[str, Any], manifest: dict, sources: dict[str, bytes]) -> list[dict[str, Any]]:
    """Derive public checks solely from the checksum-admitted ISO inventory.

    Args:
        base: Existing ISO/software expectations returned by the inspector.
        manifest: Original ISO payload manifest whose bytes were admitted.
        sources: Fixed source members independently checked against that manifest.
    """
    files = {item["path"]: item["sha256"] for item in manifest["files"]}
    for name in SOURCE_MEMBERS:
        if name not in sources or hashlib.sha256(sources[name]).hexdigest() != files.get(name):
            raise ValueError("content source differs from admitted ISO")
    reference_digest = hashlib.sha256(Path(wheel_verifier.__file__).read_bytes()).hexdigest()
    if reference_digest != files[SOURCE_MEMBERS[1]]:
        raise ValueError("content adapter requires the original shared verifier contract")
    removals = re.findall(r'run_tdnf "Build-only package removal" --noautoremove remove ([^\r\n]+)', sources[SOURCE_MEMBERS[0]].decode())
    if len(removals) != 1 or not all(_PACKAGE.fullmatch(name) for name in removals[0].split()):
        raise ValueError("shared build-only package removal is ambiguous")
    removed = set(removals[0].split())
    rpms = manifest.get("rpm_inventory")
    packages = manifest.get("packages")
    if not isinstance(rpms, list) or not 1 <= len(rpms) <= 1024 or not isinstance(packages, list):
        raise ValueError("content RPM inventory is missing or excessive")
    allowed = {}
    for item in rpms:
        if (not isinstance(item, dict) or set(item) != {"file", "name", "version", "architecture", "sha256"}
                or not _PACKAGE.fullmatch(str(item["name"])) or item["name"] in allowed
                or not re.fullmatch(r"[A-Za-z0-9+._:~^-]{1,192}", str(item["version"]))
                or item["architecture"] not in {"x86_64", "noarch"}
                or files.get("rpms/" + str(item["file"])) != item["sha256"]):
            raise ValueError("content RPM identity differs from admitted files")
        allowed[item["name"]] = [item["version"], item["architecture"]]
    required = sorted(set(packages) - removed)
    if not required or not set(required) <= allowed.keys():
        raise ValueError("required runtime package set is incomplete")
    lock = json.loads(sources[SOURCE_MEMBERS[2]])
    if lock.get("schema_version") != 2 or not isinstance(lock.get("modules"), dict) or not lock["modules"]:
        raise ValueError("content PowerCLI lock is invalid")
    copied = {}
    for name, checksum in files.items():
        if not name.startswith("source/"):
            continue
        relative = name.removeprefix("source/")
        parts = relative.split("/")
        if (parts[0] in _RUNTIME_ROOTS or any(part in _RSYNC_EXCLUDES or part == "__pycache__" for part in parts)
                or relative.endswith(".pyc")):
            continue
        copied[relative] = checksum
    trust = {name.removeprefix("source/"): checksum for name, checksum in files.items()
             if name.startswith("source/image/common/update-trust/") and name.endswith(".pem")}
    if not copied or not trust or any(not re.fullmatch(r"atlaso-release-[A-Za-z0-9._-]+\.pem", Path(name).name) for name in trust):
        raise ValueError("content source or public trust inventory is incomplete")
    specifications = {
        "assets": {"environment_verifier_sha256": reference_digest, "source_digest": _canonical_digest(copied),
                   "source_file_count": len(copied), "trust_names": sorted(Path(name).name for name in trust),
                   "trust_digest": _canonical_digest(trust), "omitted_sources": sorted(_VMWARE_SOURCES),
                   "deployed_file_count": len((wheel_verifier.DEPLOYED_TEXT_FILES | wheel_verifier.DEPLOYED_BINARY_FILES).keys() - _VMWARE_SOURCES)},
        "python": {**{key: base[key] for key in _EXPECTED_EXTRA["python"] - {"environment_verifier_sha256"}},
                   "environment_verifier_sha256": reference_digest},
        "powercli": {"powercli_script_sha256": files["source/image/common/powershell/provision-powercli.ps1"],
                     "powercli_lock_sha256": files[SOURCE_MEMBERS[2]], "module_count": len(lock["modules"])},
        "rpm": {"package_state_sha256": files["source/image/common/scripts/verify-photon-package-state.py"],
                "allowed_inventory": _compressed(allowed), "required_packages": _compressed(required)},
        "notices": {"notice_generator_sha256": files["source/scripts/generate_third_party_notices.py"],
                    "notice_config_sha256": files["source/scripts/third_party_notices.json"],
                    "notice_lock_sha256": files["source/requirements-appliance.lock"], "version": base["version"]},
    }
    return [{"schema": 1, "kind": kind, "iso_sha256": base["iso_sha256"], **specifications[kind]} for kind in KINDS]


def _validate_expected(expected: dict[str, Any]) -> str:
    """Validate the exact internal expectation shape before command generation.

    Args:
        expected: One content check derived from admitted media.
    """
    if not isinstance(expected, dict):
        raise ValueError("content expectation schema is invalid")
    kind = expected.get("kind")
    if (not isinstance(kind, str) or kind not in KINDS or type(expected.get("schema")) is not int or expected["schema"] != 1 or
            set(expected) != _COMMON_KEYS | _EXPECTED_EXTRA[kind]):
        raise ValueError("content expectation schema is invalid")
    for key, value in expected.items():
        if (key.endswith("_sha256") or key in {"source_digest", "trust_digest"}) and (
                not isinstance(value, str) or not _DIGEST.fullmatch(value)):
            raise ValueError("content expectation digest is invalid")
    if "version" in expected and (not isinstance(expected["version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected["version"])):
        raise ValueError("content expectation version is invalid")
    if "source_commit" in expected and (not isinstance(expected["source_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", expected["source_commit"])):
        raise ValueError("content expectation commit is invalid")
    if kind == "assets":
        names = expected["trust_names"]
        if (not isinstance(names, list) or not 1 <= len(names) <= 16
                or any(not isinstance(name, str) or not re.fullmatch(r"atlaso-release-[A-Za-z0-9._-]+\.pem", name) for name in names)
                or names != sorted(set(names)) or expected["omitted_sources"] != sorted(_VMWARE_SOURCES)
                or type(expected["source_file_count"]) is not int or not 1 <= expected["source_file_count"] <= 10000
                or type(expected["deployed_file_count"]) is not int or not 1 <= expected["deployed_file_count"] <= 100):
            raise ValueError("content source or public trust expectation is invalid")
    if kind == "powercli" and (type(expected["module_count"]) is not int or not 1 <= expected["module_count"] <= 1000):
        raise ValueError("content module count is invalid")
    if kind == "rpm":
        allowed = _package_inventory(_decode_inventory(expected["allowed_inventory"]))
        required = _decode_inventory(expected["required_packages"])
        if (not isinstance(required, list) or not required or any(not isinstance(name, str) for name in required)
                or required != sorted(set(required)) or not set(required) <= allowed.keys()):
            raise ValueError("required content package set is invalid")
    return kind


def guest_content_program(
    expected: dict[str, Any], *, atlaso_root: str | Path = "/opt/atlaso",
    software_root: str | Path = "/var/lib/atlaso/installation-inspection/software",
    temporary_root: str | Path = "/run", site_root: str | Path | None = None,
) -> str:
    """Adapt existing validators to the receipt-bound guest's private console.

    Args:
        expected: Strict public ISO-bound content expectation.
        atlaso_root: Installed source root; injectable only by isolated fixtures.
        software_root: Retained authenticated software; injectable only by fixtures.
        temporary_root: Ephemeral RAM parent; injectable only by fixtures.
        site_root: Explicit fixture site-packages path; live checks use package metadata.
    """
    kind = _validate_expected(expected)
    command_expected = {key: value for key, value in expected.items() if key not in {"allowed_inventory", "required_packages"}}
    prelude = '''import base64,hashlib,importlib.metadata,json,os,re,shutil,stat,subprocess,tarfile,tempfile,types,zlib
from pathlib import Path,PurePosixPath
def read(p,n=16777216):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,"rb") as f:
  z=os.fstat(f.fileno());b=f.read(n+1)
 if not stat.S_ISREG(z.st_mode) or z.st_nlink!=1 or len(b)>n: raise ValueError()
 return b
def checked(rel,key):
 p=a/rel;b=read(p,1048576)
 if hashlib.sha256(b).hexdigest()!=e[key]: raise ValueError()
 return p,b
def load(rel,key,n):
 p,b=checked(rel,key);m=types.ModuleType(n);m.__file__=str(p);exec(compile(b,str(p),"exec"),m.__dict__);return m
def run(args,timeout=60):
 c=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 if c.returncode or len(c.stdout)+len(c.stderr)>1048576: raise ValueError()
 return c.stdout
def digest(d):return hashlib.sha256("".join(k+"\\0"+d[k]+"\\n" for k in sorted(d)).encode()).hexdigest()
'''
    declarations = ("e=" + repr(command_expected) + "\na=Path(" + repr(str(atlaso_root)) + ")\ns=Path(" +
                    repr(str(software_root)) + ")\nt=Path(" + repr(str(temporary_root)) + ")\nsite_override=" +
                    repr(str(site_root) if site_root is not None else None) + "\nprofile_data=" + repr(PROFILE.encode()) + "\n")
    body = 'stage="system-' + kind + '"\n' + prelude + declarations + _PROGRAMS[kind]
    body += '\nr.update(schema=1,kind=e["kind"],iso_sha256=e["iso_sha256"])\nx=json.dumps(r,sort_keys=True,separators=(",",":")).encode()\nif len(x)>4096: raise ValueError()\nprint("ATLASO-INSPECTION:"+base64.b64encode(x).decode()+":END")'
    program = 'try:\n' + textwrap.indent(body, " ") + '\nexcept BaseException:\n print("ATLASO-INSPECTION-FAILED:"+stage)'
    compressed = base64.b64encode(zlib.compress(program.encode(), 9)).decode()
    command = "/opt/atlaso/.venv/bin/python -B -I -c 'exec(__import__(\"zlib\").decompress(__import__(\"base64\").b64decode(\"" + compressed + "\")))'"
    if len(command) > 3500 or not command.isascii():
        raise ValueError("content inspection command exceeds the console bound")
    return command


def validate_content_report(raw: bytes, expected: dict[str, Any]) -> dict[str, Any]:
    """Require all requested checks and reduce output to public measurements.

    Args:
        raw: Bounded JSON recovered from the private guest console.
        expected: Original media-bound expectation for this content kind.
    """
    kind = _validate_expected(expected)
    if not raw or len(raw) > 4096:
        raise ValueError("content report exceeds its bound")
    value = json.loads(raw)
    keys = {
        "assets": {"source_digest", "source_file_count", "deployed_files", "trust_digest", "trust_keys"},
        "python": {"python_payload_sha256", "python_files", "python_distributions"},
        "powercli": {"powercli_lock_sha256", "module_count"},
        "rpm": {"installed_inventory", "firmware_verified", "rpm_files_verified", "package_state_verified"},
        "notices": {"notices_sha256", "notice_inputs_verified"},
    }[kind]
    if (not isinstance(value, dict) or set(value) != _COMMON_KEYS | keys or type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("kind") != kind or value.get("iso_sha256") != expected["iso_sha256"]):
        raise ValueError("content report schema or media identity differs")
    for key, field in value.items():
        if (key.endswith("_sha256") or key.endswith("_digest")) and (not isinstance(field, str) or not _DIGEST.fullmatch(field)):
            raise ValueError("content report digest is invalid")
    for key in {"source_file_count", "deployed_files", "trust_keys", "python_files", "python_distributions", "module_count"} & value.keys():
        if type(value[key]) is not int or not 1 <= value[key] <= 100000:
            raise ValueError("content report count is invalid")
    if kind == "assets" and any(value[key] != expected[key] for key in ("source_digest", "source_file_count", "trust_digest")):
        raise ValueError("installed source or trust differs from media")
    if kind == "assets" and value["trust_keys"] != len(expected["trust_names"]):
        raise ValueError("installed public trust key set differs")
    if kind == "assets" and value["deployed_files"] != expected["deployed_file_count"]:
        raise ValueError("installed shared asset set is incomplete")
    if kind == "powercli" and any(value[key] != expected[key] for key in ("powercli_lock_sha256", "module_count")):
        raise ValueError("installed PowerCLI differs from the original lock")
    if kind == "rpm":
        actual = _package_inventory(_decode_inventory(value["installed_inventory"]))
        allowed = _decode_inventory(expected["allowed_inventory"])
        required = _decode_inventory(expected["required_packages"])
        if (not isinstance(actual, dict) or not 1 <= len(actual) <= 1024 or not isinstance(allowed, dict)
                or not isinstance(required, list) or not set(required) <= actual.keys()
                or any(name not in allowed or identity != allowed[name] for name, identity in actual.items())
                or any(value[key] is not True for key in ("firmware_verified", "rpm_files_verified", "package_state_verified"))):
            raise ValueError("installed RPM closure or file verification differs from media")
        value = {key: field for key, field in value.items() if key != "installed_inventory"}
        value.update(installed_rpms=len(actual), rpm_inventory_sha256=hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(",", ":")).encode()).hexdigest())
    if kind == "notices" and value["notice_inputs_verified"] is not True:
        raise ValueError("installed notices were not reproduced")
    return value


_PROGRAMS = {
    "python": r'''
v=load("image/common/scripts/verify-template-software.py","software_verifier_sha256","_software")
h=load("scripts/verify_virtualization_guest_wheel.py","environment_verifier_sha256","_wheels")
software=v.verify(s,e["release_manifest_sha256"],e["version"],e["source_commit"])
records,distributions=h._expected_environment(s/software["application_wheel"],s/"wheelhouse/cp314",e["wheel_sha256"])
site=Path(site_override) if site_override is not None else Path(importlib.metadata.distribution("atlaso").locate_file(""))
if site_override is None and site.resolve()!=(a/".venv/lib/python3.14/site-packages").resolve(): raise ValueError()
size=sum(v[1] for v in records.values())
if size>1073741824 or size+67108864>shutil.disk_usage(t).free: raise ValueError()
with tempfile.TemporaryDirectory(prefix="atlaso-inspection-",dir=t) as d:
 archive=Path(d)/"site.tar";count=0;total=0
 with tarfile.open(archive,"w") as out:
  for p in sorted(site.rglob("*")):
   z=p.lstat()
   if p.is_symlink() or not(stat.S_ISDIR(z.st_mode) or(stat.S_ISREG(z.st_mode) and z.st_nlink==1)): raise ValueError()
   if p.is_dir(): continue
   count+=1;total+=z.st_size
   if count>100000 or total>1073741824: raise ValueError()
   out.add(p,arcname=p.relative_to(site).as_posix(),recursive=False)
 h._verify_site_packages_archive(archive,records,distributions)
r=dict(python_files=len(records),python_distributions=len(distributions),python_payload_sha256=hashlib.sha256(json.dumps(records,sort_keys=True,separators=(",", ":")).encode()).hexdigest())
''',
    "powercli": r'''
p,b=checked("image/common/powershell/provision-powercli.ps1","powercli_script_sha256")
lp,lb=checked("image/common/powershell/powercli-lock.json","powercli_lock_sha256")
lock=json.loads(lb)
run(["pwsh","-NoLogo","-NoProfile","-NonInteractive","-File",str(p),"-Mode","Validate","-ModuleRoot","/usr/local/share/powershell/Modules","-LockPath",str(lp),"-SuiteVersion",lock["suite_version"]],90)
r=dict(powercli_lock_sha256=hashlib.sha256(lb).hexdigest(),module_count=len(lock["modules"]))
''',
    "rpm": r'''
p,b=checked("image/common/scripts/verify-photon-package-state.py","package_state_sha256")
run(["/usr/bin/python3","-B",str(p),"--guest-platform","none"])
rows=run(["rpm","--noplugins","-qa","--qf","%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"]).decode().splitlines()
installed={}
for row in rows:
 fields=row.split("\t")
 if len(fields)!=3: raise ValueError()
 name,version,arch=fields
 if name=="gpg-pubkey": continue
 if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}",name) or name in installed or arch not in {"x86_64","noarch"}: raise ValueError()
 installed[name]=[version,arch]
 if len(installed)>1024: raise ValueError()
run(["rpm","--noplugins","-Va","--noscripts","--nodeps","--noconfig","--noghost"],90)
run(["rpm","--noplugins","-V","--noscripts","--nodeps","linux-firmware"],60)
r=dict(installed_inventory=base64.b64encode(zlib.compress(json.dumps(installed,sort_keys=True,separators=(",", ":")).encode(),9)).decode(),firmware_verified=True,rpm_files_verified=True,package_state_verified=True)
''',
    "assets": r'''
stage="system-assets-profile"
if read(Path("/etc/atlaso/installation-profile"),128)!=profile_data: raise ValueError()
stage="system-assets-helper"
h=load("scripts/verify_virtualization_guest_wheel.py","environment_verifier_sha256","_assets")
stage="system-assets-source"
records={};pending=[a];total=0
skip={"bin","releases","current",".venv","build-info.json"};excluded={".git",".venv",".pytest_cache","data","test-results","__pycache__"}
while pending:
 for p in sorted(pending.pop().iterdir()):
  rel=p.relative_to(a).as_posix();parts=rel.split("/")
  if parts[0] in skip or any(v in excluded for v in parts) or rel.endswith(".pyc"): continue
  if p.is_symlink(): raise ValueError()
  if p.is_dir(): pending.append(p);continue
  b=read(p);total+=len(b);records[rel]=hashlib.sha256(b).hexdigest()
  if len(records)>10000 or total>536870912: raise ValueError()
if len(records)!=e["source_file_count"] or digest(records)!=e["source_digest"]: raise ValueError()
stage="system-assets-powershell-profile"
omit=set(e["omitted_sources"])
profiles=[p for p in h.POWERSHELL_PROFILE_TARGETS if Path(p).exists()]
if len(profiles)!=1 or Path("/usr/bin/pwsh").resolve().parent/"profile.ps1"!=Path(profiles[0]): raise ValueError()
stage="system-assets-deployed"
verified=0
for source,target in {**h.DEPLOYED_TEXT_FILES,**h.DEPLOYED_BINARY_FILES}.items():
 if source in omit:
  if Path(target.replace("/opt-atlaso/",str(a)+"/",1)).exists(): raise ValueError()
  continue
 actual=profiles[0] if source==h.POWERSHELL_PROFILE_SOURCE else target.replace("/opt-atlaso/",str(a)+"/",1)
 b=read(a/source);b=b.replace(b"\r\n",b"\n") if source in h.DEPLOYED_TEXT_FILES else b
 z=Path(actual).lstat()
 if z.st_uid or z.st_gid or stat.S_IMODE(z.st_mode)!=h.DEPLOYED_FILE_MODES[target] or read(Path(actual))!=b: raise ValueError()
 verified+=1
stage="system-assets-trust"
trust=Path("/etc/atlaso/update-trust.d")
if sorted(p.name for p in trust.iterdir())!=e["trust_names"]: raise ValueError()
trusted={}
for name in e["trust_names"]:
 source="image/common/update-trust/"+name;b=read(a/source);p=trust/name;z=p.lstat()
 if z.st_uid or z.st_gid or stat.S_IMODE(z.st_mode)!=420 or read(p)!=b: raise ValueError()
 trusted[source]=hashlib.sha256(b).hexdigest()
r=dict(source_digest=digest(records),source_file_count=len(records),deployed_files=verified,trust_digest=digest(trusted),trust_keys=len(trusted))
''',
    "notices": r'''
p,b=checked("scripts/generate_third_party_notices.py","notice_generator_sha256")
checked("scripts/third_party_notices.json","notice_config_sha256")
lock,lb=checked("requirements-appliance.lock","notice_lock_sha256")
inventory=run(["rpm","--noplugins","-qa","--qf","%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{LICENSE}\\t%{URL}\\n"])
with tempfile.TemporaryDirectory(prefix="atlaso-inspection-",dir=t) as d:
 inv=Path(d)/"rpms.tsv";out=Path(d)/"notices.md";inv.write_bytes(b"\n".join(sorted(set(inventory.splitlines())))+b"\n")
 run(["/opt/atlaso/.venv/bin/python","-B","-I",str(p),"--version",e["version"],"--output",str(out),"--lock",str(lock),"--python-environment",str(a/".venv"),"--rpm-inventory",str(inv)],90)
 wanted=read(out);actual=read(Path("/usr/share/doc/atlaso/THIRD_PARTY_NOTICES.md"))
 if wanted!=actual: raise ValueError()
r=dict(notices_sha256=hashlib.sha256(actual).hexdigest(),notice_inputs_verified=True)
''',
}
