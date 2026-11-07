"""Exercise certificate peer factory orchestration without starting a VM."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.completed_task_files import WindowsFiles

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/windows/vmware/create-certificate-peer.ps1"
pytestmark = pytest.mark.skipif(
    os.name != "nt" or not shutil.which("pwsh"),
    reason="Windows ownership primitives and PowerShell are required",
)


def ps_literal(value: str | Path) -> str:
    """Quote one non-secret literal for an isolated PowerShell command.

    Args:
        value: Path or string embedded as a PowerShell single-quoted literal.
    """
    return "'" + str(value).replace("'", "''") + "'"


def script_function(name: str) -> str:
    """Return one uniquely defined function body from the factory's PowerShell AST.

    Args:
        name: Factory function name to locate in the parsed script.
    """
    return f"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(SCRIPT)},[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ throw 'Factory script did not parse.' }}
$matches=@($ast.Find({{ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq {ps_literal(name)} }},$true))
if ($matches.Count -ne 1) {{ throw 'Expected one factory function.' }}
. ([scriptblock]::Create($matches[0].Extent.Text))
"""


def run_powershell(command: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a short PowerShell fixture with no inherited command-line startup.

    Args:
        command: Isolated PowerShell source to execute.
        check: Whether a nonzero process result raises an exception.
    """
    return subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=60,
        check=check,
    )


def test_factory_script_is_parseable_and_keeps_plan_before_creation_boundaries():
    """Plan returns before publisher, output creation, LAN, disk, or seed operations."""
    command = f"""
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(SCRIPT)},[ref]$tokens,[ref]$errors)
if ($errors.Count) {{ $errors | Out-String | Write-Error; exit 1 }}
'parsed'
"""
    assert run_powershell(command).stdout.strip() == "parsed"

    source = SCRIPT.read_text(encoding="utf-8")
    plan_start = source.index("if ($Mode -eq 'Plan')")
    plan_end = source.index("if ($Mode -eq 'CleanupPrepared')", plan_start)
    plan_branch = source[plan_start:plan_end]
    assert "return" in plan_branch
    assert "Test-Path -LiteralPath $destination" in plan_branch
    assert "Publish-CertificatePeerRecord" not in plan_branch
    assert "New-CertificatePeerPreparedOutput" not in plan_branch
    assert "Resolve-AtlasoOwnedLanSegment" not in plan_branch
    assert "CopyTo($diskWriter)" not in plan_branch
    assert "create_certificate_peer_seed_iso.py" not in plan_branch
    assert source.index("if ($Mode -eq 'Plan')") < source.index("$publishedIntent = Publish-CertificatePeerRecord")


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "CLOSED"),
        ("isDraft", True),
        ("isCrossRepository", True),
        ("headRefOid", "b" * 40),
        ("headRefName", "another-branch"),
        ("headRepositoryOwner", {"login": "someone-else"}),
    ],
)
def test_pull_request_gate_rejects_mismatched_admission_before_creation(field: str, value: object):
    """The isolated PR gate rejects each changed binding without reaching any provider.

    Args:
        field: Pull-request admission binding modified by the case.
        value: Mismatched value supplied for that binding.
    """
    pr = {
        "state": "OPEN",
        "isDraft": False,
        "isCrossRepository": False,
        "headRefOid": "a" * 40,
        "headRefName": "codex/task-1094",
        "headRepositoryOwner": {"login": "mdaneri"},
    }
    pr[field] = value
    pr_json = json.dumps(pr)
    command = f"""
$ErrorActionPreference='Stop'
function Invoke-AtlasoBoundedProcess {{ param($FilePath,$ArgumentList,$TimeoutSeconds,$Action) return {ps_literal(pr_json)} }}
{script_function('Assert-CertificatePeerPullRequest')}
$context=[pscustomobject]@{{ PullRequestNumber=1118; SourceCommit={ps_literal('a' * 40)}; Branch='codex/task-1094' }}
Assert-CertificatePeerPullRequest -Context $context
throw 'Creation boundary reached'
"""
    result = run_powershell(command, check=False)
    assert result.returncode != 0
    assert "exact open same-repository PR head" in result.stderr
    assert "Creation boundary reached" not in result.stderr


def test_pull_request_gate_accepts_only_the_exact_open_same_repository_head():
    """A matching PR response passes the gate without invoking a real gh process."""
    pr = json.dumps(
        {
            "state": "OPEN",
            "isDraft": False,
            "isCrossRepository": False,
            "headRefOid": "a" * 40,
            "headRefName": "codex/task-1094",
            "headRepositoryOwner": {"login": "mdaneri"},
        }
    )
    command = f"""
$ErrorActionPreference='Stop'
function Invoke-AtlasoBoundedProcess {{ param($FilePath,$ArgumentList,$TimeoutSeconds,$Action) return {ps_literal(pr)} }}
{script_function('Assert-CertificatePeerPullRequest')}
$context=[pscustomobject]@{{ PullRequestNumber=1118; SourceCommit={ps_literal('a' * 40)}; Branch='codex/task-1094' }}
Assert-CertificatePeerPullRequest -Context $context
'admitted'
"""
    assert run_powershell(command).stdout.strip().endswith("admitted")


def test_create_publishes_intent_and_original_before_output_payload_and_seed():
    """Source ordering binds every created artifact to durable intent and original receipts."""
    source = SCRIPT.read_text(encoding="utf-8")
    intent = source.index("$publishedIntent = Publish-CertificatePeerRecord")
    output = source.index("$outputPin = New-CertificatePeerPreparedOutput", intent)
    lan = source.index("$segment = Resolve-AtlasoOwnedLanSegment", output)
    original_publish = source.index("$publishedOriginal = Publish-CertificatePeerRecord", lan)
    disk_copy = source.index("$sourceStream.CopyTo($diskWriter)", original_publish)
    seed = source.index("create_certificate_peer_seed_iso.py", disk_copy)
    assert intent < output < lan < original_publish < disk_copy < seed

    original_start = source.rindex("$original = [ordered]@{", lan, original_publish)
    original_record = source[original_start:original_publish]
    for binding in (
        "phase = 'original-certificate-peer-created'",
        "task_id = $context.TaskId",
        "repository = $context.Repository",
        "pr = $validation.pr",
        "source_commit = $head",
        "root_identity = (ConvertTo-CertificatePeerNativeIdentity $directoryIdentity)",
        "persistent_vm_identity_sha256 = (Get-AtlasoTestVmOwnershipCleanupIdentityHash $cleanupIdentity)",
        "intent_sha256 = $publishedIntent.Sha256",
        "lan_receipt_sha256 = $segment.ReceiptSha256",
    ):
        assert binding in original_record

    # The failure path preserves the original root and receipts; the only finally block
    # releases local handles and contains no VM/LAN remover or retry operation.
    tail = source[source.index("finally {", seed) :]
    assert "Remove-Atlaso" not in tail
    assert "Remove-AtlasoWorkstationLanSegment" not in source
    assert "retry" not in tail.lower()


def test_factory_record_helper_publishes_real_receipt_outside_removal_root(tmp_path: Path):
    """The factory's wrapper reaches the durable publisher with an actual Windows identity.

    Args:
        tmp_path: Pytest-owned root for the output and durable receipt directories.
    """
    evidence = tmp_path / "evidence"
    output = tmp_path / "new-peer"
    evidence.mkdir()
    output.mkdir()
    record = {
        "schema": 1,
        "kind": "vm-creation-intent",
        "phase": "certificate-peer-pending",
        "task_id": "synthetic-task",
        "repository": "mdaneri/Atlaso",
        "pr": 1118,
        "source_commit": "a" * 40,
        "root_path": str(output),
    }
    vmware = ROOT / "scripts/windows/vmware"
    command = f"""
$ErrorActionPreference='Stop'
Import-Module {ps_literal(vmware / 'Atlaso.WorkstationCleanup.psm1')} -Force
. {ps_literal(vmware / 'Atlaso.TestVmOwnership.ps1')}
{script_function('Publish-CertificatePeerRecord')}
$context=[pscustomobject]@{{ Enabled=$true; InvocationId=''; EvidenceDirectory={ps_literal(evidence)};
  EvidenceDirectoryId=[Atlaso.WorkstationFileIdentity]::Get({ps_literal(evidence)}); OutputDirectory={ps_literal(output)} }}
$record={ps_literal(json.dumps(record))} | ConvertFrom-Json -AsHashtable
$published=Publish-CertificatePeerRecord -Context $context -Record $record -Kind intent
$published | ConvertTo-Json -Compress
"""
    result = run_powershell(command)
    published = json.loads(result.stdout.strip().splitlines()[-1])
    receipt = Path(published["Path"])
    assert receipt.parent == evidence
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == published["Sha256"]
    written = json.loads(receipt.read_text(encoding="utf-8"))
    assert written["task_id"] == "synthetic-task"
    assert written["repository"] == "mdaneri/Atlaso"
    assert written["pr"] == 1118
    assert written["source_commit"] == "a" * 40
    assert written["root_path"] == str(output)
    assert not list(output.iterdir())


def test_inspect_and_cleanup_bind_hash_and_original_identity_before_remover():
    """The receipt gates precede Inspect success and the only supported removal call."""
    source = SCRIPT.read_text(encoding="utf-8")
    mode_start = source.index("if ($Mode -in @('Inspect', 'Cleanup'))")
    mode_end = source.index("if ($OriginalReceiptPath -or $OriginalReceiptSha256)", mode_start)
    branch = source[mode_start:mode_end]
    receipt_read = branch.index("Read-AtlasoTestVmSealedRecord")
    identity_guard = branch.index("[Atlaso.WorkstationFileIdentity]::Get($destination)")
    inspect_success = branch.index("OriginalOwnershipVerified = $true")
    remover = branch.index("remove-atlaso-vm.ps1")
    assert receipt_read < identity_guard < inspect_success < remover
    assert "-Sha256 $OriginalReceiptSha256" in branch
    assert "persistent_vm_identity_sha256" in branch
    assert "ExpectedRootIdentity $original.original_identities.directory" in branch
    assert "ExpectedPersistentVmIdentitySha256 $original.persistent_vm_identity_sha256" in branch
    assert "if ($Mode -eq 'Inspect')" in branch
    assert "elseif ($PSCmdlet.ShouldProcess" in branch


def lower_body_harness(
    tmp_path: Path,
    *,
    mode: str,
    mismatched_disk: bool = False,
    successful_create: bool = False,
    fail_seed: bool = False,
    tamper_receipt: bool = False,
) -> tuple[Path, Path]:
    """Write a synthetic script that executes the factory's real lower body with mocks.

    Args:
        tmp_path: Pytest-owned root for the harness, checkout, and synthetic receipts.
        mode: Factory operation to execute, such as Plan, Create, or Inspect.
        mismatched_disk: Whether source-disk bytes change before pinning.
        successful_create: Whether local copy and prepared-receipt steps succeed.
        fail_seed: Whether the mocked seed step raises after the disk copy.
        tamper_receipt: Whether the original receipt bytes change before inspection.
    """
    source = SCRIPT.read_text(encoding="utf-8")
    lower_body = source[source.index("$pins = [Collections.Generic.List[object]]::new()"):]
    checkout = tmp_path / "s"
    vmware = checkout / "scripts/windows/vmware"
    vmware.mkdir(parents=True)
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    durable = tmp_path / "durable"
    durable.mkdir()

    def fixture(name: str, contents: bytes = b"fixture") -> Path:
        """Create one ordinary file beneath the synthetic fixture directory.

        Args:
            name: Relative filename used by the harness case.
            contents: Bytes written as the fixture file contents.
        """
        path = fixture_root / name
        path.write_bytes(contents)
        return path

    appliance_intent = fixture("appliance-intent.json")
    appliance_ownership = fixture("appliance-ownership.json")
    appliance_boot = fixture("appliance-boot.json")
    source_preparation = fixture("peer-source-preparation.json")
    appliance_vmx = fixture("appliance.vmx")
    public_key = fixture("peer.pub", b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2U= fixture\n")
    disk = fixture("source.vmdk", b"synthetic admitted peer disk")
    qcow2 = fixture("source.qcow2", b"synthetic pinned qcow2")
    plan = fixture("plan.json", b"{}\n")
    python = fixture("python.exe", b"synthetic interpreter")
    qemu = fixture("qemu-img.exe", b"synthetic qemu executable")

    validation = {
        "task_id": "synthetic-task",
        "source_commit": "a" * 40,
        "pr": 1118,
        "collision_suffix": "synthetic",
        "appliance_intent": {"path": str(appliance_intent)},
        "appliance_ownership": {
            "path": str(appliance_ownership),
            "sha256": hashlib.sha256(appliance_ownership.read_bytes()).hexdigest(),
        },
        "appliance_installed_boot": {"path": str(appliance_boot)},
        "peer_source_preparation": {"path": str(source_preparation)},
        "appliance_vmx": str(appliance_vmx),
        "peer_public_key_path": str(public_key),
        "peer_public_key_sha256": hashlib.sha256(public_key.read_bytes()).hexdigest(),
        "peer_vmdk_sha256": hashlib.sha256(disk.read_bytes()).hexdigest(),
        "peer_hostname": "synthetic-peer",
        "peer_user": "fixture",
        "server_cidr": "198.18.42.1/24",
        "management_vmnet": "vmnet-test-management",
        "lease_address": "198.18.42.20",
        "appliance_mac": "00:50:56:aa:bb:cc",
        "management_addresses": ["192.0.2.20/24"],
    }
    admission = {
        "source_disk": str(disk),
        "source_qcow2": str(qcow2),
        "source_qcow2_sha512": hashlib.sha512(qcow2.read_bytes()).hexdigest(),
    }
    if mismatched_disk:
        validation["peer_vmdk_sha256"] = "0" * 64

    receipt_path = None
    receipt_sha256 = None
    if mode == "Inspect":
        output_directory = checkout / "image/vmware-workstation/test-vms/peer"
        output_directory.mkdir(parents=True)
        vmx_path = output_directory / "peer.vmx"
        cleanup_identity = "a" * 32
        vmx_path.write_text(
            f'guestinfo.atlaso.test_vm_cleanup_identity = "{cleanup_identity}"\n',
            encoding="utf-8",
        )
        cleanup_module = ROOT / "scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1"

        def native_identity(path: Path) -> str:
            """Read a fixture path's Windows identity through the cleanup module.

            Args:
                path: Existing path whose native file identity is needed.
            """
            command = (
                f"Import-Module {ps_literal(cleanup_module)} -Force; "
                f"[Atlaso.WorkstationFileIdentity]::Get({ps_literal(path)})"
            )
            return run_powershell(command).stdout.strip()

        root_identity = native_identity(output_directory)
        vmx_identity = native_identity(vmx_path)
        original_record = {
            "schema": 1,
            "kind": "vm",
            "phase": "original-certificate-peer-created",
            "task_id": "synthetic-task",
            "repository": "mdaneri/Atlaso",
            "pr": 1118,
            "source_commit": "a" * 40,
            "worktree": str(checkout),
            "source_branch": "codex/synthetic-task",
            "output_directory": str(output_directory),
            "vmx_path": str(vmx_path),
            "canonical_name": "peer",
            "pull_request_number": 1118,
            "local_builder": False,
            "path": str(vmx_path),
            "root_path": str(output_directory),
            "root_identity": root_identity,
            "original_identities": {"directory": root_identity, "vmx": vmx_identity},
            "persistent_vm_identity_sha256": hashlib.sha256(cleanup_identity.encode()).hexdigest().upper(),
            "intent_sha256": "b" * 64,
            "intent_path": str(durable / "intent.json"),
            "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
            "serial_path": str(output_directory / "peer-serial.log"),
            "lan_receipt_path": str(durable / "lan.json"),
            "lan_receipt_sha256": "c" * 64,
            "cleanup_tool": "scripts/windows/vmware/create-certificate-peer.ps1 -Mode Cleanup",
        }
        receipt_path = durable / "original-peer.json"
        original_bytes = (json.dumps(original_record, separators=(",", ":")) + "\n").encode()
        receipt_path.write_bytes(original_bytes)
        receipt_sha256 = hashlib.sha256(original_bytes).hexdigest()
        if tamper_receipt:
            receipt_path.write_bytes(original_bytes + b"tampered\n")

    def ps_json(value: object) -> str:
        """Serialize one fixture value as a PowerShell-safe JSON literal.

        Args:
            value: JSON-compatible value embedded in the synthetic script.
        """
        return ps_literal(json.dumps(value))

    successful_functions = ""
    if successful_create:
        successful_functions = f"""
Import-Module {ps_literal(ROOT / 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1')} -Force
{script_function('ConvertTo-CertificatePeerNativeIdentity')}
function Get-AtlasoTestVmOwnershipCleanupIdentityHash {{
  param($Value)
  $bytes=[Text.Encoding]::UTF8.GetBytes([string]$Value)
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}}
function Invoke-CertificatePeerPython {{
  param($Root,$Code,$Arguments)
  if ($Arguments -contains '--shape-only') {{ $global:FactoryCalls.Add('shape'); return $script:ValidationJson }}
  if ($Code -match 'certificate_peer_factory import main') {{ $global:FactoryCalls.Add('admission'); return $script:AdmissionJson }}
  if ($Code -match 'render_vmx') {{
    $global:FactoryCalls.Add('render')
    return ConvertTo-Json -InputObject 'config.version = "8"`n' -Compress
  }}
  if ($Code -match 'runpy') {{
    if (-not $script:OriginalReceiptPath -or -not (Test-Path -LiteralPath $script:OriginalReceiptPath)) {{ throw 'Seed began before the original peer receipt existed.' }}
    if (-not ($global:FactoryCalls -contains 'publisher-original')) {{ throw 'Seed began before original receipt publication.' }}
    $diskCopy=Join-Path $script:OutputDirectory 'peer.vmdk'
    if (-not (Test-Path -LiteralPath $diskCopy)) {{ throw 'Seed began before peer disk copy completed.' }}
    $global:FactoryCalls.Add('disk-copy-observed')
    $global:FactoryCalls.Add('seed')
    if ({'$true' if fail_seed else '$false'}) {{ throw 'Synthetic seed generation failure.' }}
    $outputIndex=[Array]::IndexOf([string[]]$Arguments,'--output')
    [IO.File]::WriteAllBytes([string]$Arguments[$outputIndex + 1],[byte[]](1,2,3,4))
    return
  }}
  throw 'Unexpected Python projection in successful Create harness.'
}}
function Assert-CertificatePeerPullRequest {{ param($Context); $global:FactoryCalls.Add('pr-mock') }}
function Invoke-AtlasoBoundedProcess {{
  param($FilePath,$ArgumentList,$TimeoutSeconds,$Action,[switch]$DiscardOutput)
  $global:LASTEXITCODE=0
  if ($ArgumentList[0] -eq '-L') {{ $global:FactoryCalls.Add('agent-mock'); return 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZha2U= fixture' }}
  $global:FactoryCalls.Add('qemu-mock')
  if ($ArgumentList[0] -eq 'info') {{ return '{{"format":"vmdk","virtual-size":2147483648}}' }}
  if ($ArgumentList[0] -eq 'compare') {{ return }}
  throw 'Unexpected qemu operation in successful Create harness.'
}}
function Get-CimInstance {{ $global:FactoryCalls.Add('capacity-mock'); return [pscustomobject]@{{ FreePhysicalMemory=4194304 }} }}
function Get-Process {{ param($Name,$ErrorAction); $global:FactoryCalls.Add('vmware-process-check'); return @() }}
function Publish-CertificatePeerRecord {{
  param($Context,$Record,$Kind)
  $phase=[string]$Record['phase']
  $recordKind=[string]$Record['kind']
  $label=if ($phase -eq 'original-certificate-peer-created') {{ 'publisher-original' }} elseif ($phase -eq 'original-certificate-peer-directory') {{ 'publisher-directory' }} elseif ($recordKind -eq 'certificate-dhcp-peer-fixture') {{ 'publisher-prepared' }} elseif ($Kind -eq 'intent') {{ 'publisher-intent' }} else {{ 'publisher-lan' }}
  $global:FactoryCalls.Add($label)
  $number=$script:PublishedPaths.Count + 1
  $path=Join-Path $Context.EvidenceDirectory ('mock-receipt-' + $number + '.json')
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 10 -Compress) + "`n")
  [IO.File]::WriteAllBytes($path,$bytes)
  $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
  $script:PublishedPaths.Add($path)
  if ($phase -eq 'original-certificate-peer-created') {{ $script:OriginalReceiptPath=$path; $script:OriginalReceiptSha256=$sha }}
  return [pscustomobject]@{{ Path=$path; Sha256=$sha }}
}}
function New-CertificatePeerPreparedOutput {{
  param($Context,$PlanSha256)
  $global:FactoryCalls.Add('output-created')
  $parent=Split-Path -Parent $Context.OutputDirectory
  [IO.Directory]::CreateDirectory($parent) | Out-Null
  [IO.Directory]::CreateDirectory($Context.OutputDirectory) | Out-Null
  $script:OutputDirectory=$Context.OutputDirectory
  $pin=[pscustomobject]@{{ Identity=[Atlaso.WorkstationFileIdentity]::Get($Context.OutputDirectory) }}
  $pin | Add-Member ScriptMethod GetRetainedCreatedIdentity {{ param($Path) return $this.Identity }}
  $pin | Add-Member ScriptMethod Dispose {{ }}
  $record=[ordered]@{{ schema=1; kind='certificate-peer-directory'; phase='original-certificate-peer-directory';
    task_id=$Context.TaskId; repository=$Context.Repository; source_commit=$Context.SourceCommit;
    worktree=$Context.Worktree; source_branch=$Context.Branch; output_directory=$Context.OutputDirectory;
    vmx_path=$Context.VmxPath; canonical_name=$Context.Name; pull_request_number=$Context.PullRequestNumber;
    local_builder=[bool]$Context.LocalBuilder; path=$Context.OutputDirectory; original_identity=$pin.Identity;
    intent_path=$Context.IntentPath; intent_sha256=$Context.IntentSha256; plan_sha256=$PlanSha256;
    cleanup_tool='scripts/windows/vmware/create-certificate-peer.ps1 -Mode CleanupPrepared' }}
  $null=Publish-CertificatePeerRecord -Context $Context -Record $record -Kind directory
  return $pin
}}
function Resolve-AtlasoOwnedLanSegment {{
  param($Name,$Owner,$PublishReceipt)
  $global:FactoryCalls.Add('lan-mock')
  $path=Join-Path {ps_literal(durable)} 'synthetic-lan-receipt.json'
  [IO.File]::WriteAllText($path,'{{"kind":"mock-private-lan","id":"synthetic-lan"}}')
  $sha=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  $receipt=[pscustomobject]@{{ ReceiptPath=$path; ReceiptSha256=$sha; Id='synthetic-lan' }}
  & $PublishReceipt $receipt
  return [pscustomobject]@{{ Id=$receipt.Id; ReceiptPath=$path; ReceiptSha256=$sha }}
}}
"""

    wrapper = f"""
$ErrorActionPreference='Stop'
Import-Module {ps_literal(ROOT / 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1')} -Force
$global:FactoryCalls=[Collections.Generic.List[string]]::new()
$script:PublishedPaths=[Collections.Generic.List[string]]::new()
$script:OriginalReceiptPath=''
$script:OriginalReceiptSha256=''
$script:OutputDirectory=''
$script:ValidationJson={ps_json(validation)}
$script:AdmissionJson={ps_json(admission)}
$script:SourceCommit={ps_literal('a' * 40)}
$script:SourceBranch='codex/synthetic-task'
$env:CODEX_THREAD_ID='synthetic-task'
function Add-CertificatePeerPublicPin {{ param($Path,$Pins); $global:FactoryCalls.Add('pin') }}
function Invoke-CertificatePeerPython {{
  param($Root,$Code,$Arguments)
  $global:FactoryCalls.Add('python')
  if ($Arguments -contains '--shape-only') {{ return $script:ValidationJson }}
  if ($Code -match 'certificate_peer_factory import main') {{ return $script:AdmissionJson }}
  throw 'Unexpected Python operation in synthetic harness.'
}}
function git {{
  if ($args -contains 'rev-parse') {{ $global:FactoryCalls.Add('git-head'); $global:LASTEXITCODE=0; return $script:SourceCommit }}
  if ($args -contains '--show-current') {{ $global:FactoryCalls.Add('git-branch'); $global:LASTEXITCODE=0; return $script:SourceBranch }}
  if ($args -contains 'merge-base') {{ $global:FactoryCalls.Add('git-ancestry'); $global:LASTEXITCODE=0; return }}
  throw 'Unexpected git operation in synthetic harness.'
}}
function New-AtlasoVmwareTestIdentity {{ param($PullRequestNumber,$Purpose,$CollisionSuffix); return [pscustomobject]@{{ Name='peer' }} }}
function New-AtlasoTestVmOwnershipContext {{
  param($Worktree,$OutputDirectory,$VmxPath,$Name,$SourceCommit,$SourceBranch,$PullRequestNumber)
  $global:FactoryCalls.Add('context')
  return [pscustomobject]@{{ Enabled=$true; TaskId='synthetic-task'; Repository='mdaneri/Atlaso';
    PullRequestNumber=1118; SourceCommit=$SourceCommit; Branch=$SourceBranch; Worktree=$Worktree;
    OutputDirectory=$OutputDirectory; VmxPath=$VmxPath; Name=$Name; EvidenceDirectory={ps_literal(tmp_path / 'durable')};
    EvidenceDirectoryId=[Atlaso.WorkstationFileIdentity]::Get({ps_literal(durable)}); LocalBuilder=$false }}
}}
function Assert-AtlasoTestVmCheckoutSource {{ param($Context); $global:FactoryCalls.Add('checkout-source') }}
function Assert-CertificatePeerPullRequest {{ param($Context); $global:FactoryCalls.Add('pr'); throw 'PR mock must not run in this case.' }}
function Invoke-AtlasoBoundedProcess {{ param($FilePath,$ArgumentList,$TimeoutSeconds,$Action); $global:FactoryCalls.Add('qemu-or-process'); throw 'Process mock must not run in this case.' }}
function ssh-add.exe {{ $global:FactoryCalls.Add('agent'); throw 'Agent mock must not run in this case.' }}
function Get-CimInstance {{ $global:FactoryCalls.Add('capacity'); throw 'Capacity mock must not run in this case.' }}
function Publish-CertificatePeerRecord {{ param($Context,$Record,$Kind); $global:FactoryCalls.Add('publisher'); throw 'Publisher mock must not run in this case.' }}
function New-CertificatePeerPreparedOutput {{ param($Context,$OnCreated); $global:FactoryCalls.Add('output'); throw 'Output mock must not run in this case.' }}
function Resolve-AtlasoOwnedLanSegment {{ param($Name,$Owner,$PublishReceipt); $global:FactoryCalls.Add('lan'); throw 'LAN mock must not run in this case.' }}
{successful_functions}
function Invoke-FactoryHarness {{
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([string]$Plan,[string]$PythonPath,[string]$Mode,[string]$OriginalReceiptPath='',
    [string]$OriginalReceiptSha256='',[string]$QemuImgPath,[string]$VmrunPath='')
  Set-StrictMode -Version Latest
  $ErrorActionPreference='Stop'
{lower_body}
}}
try {{ $factoryResult=Invoke-FactoryHarness -Plan {ps_literal(plan)} -PythonPath {ps_literal(python)} -Mode {ps_literal(mode)} -QemuImgPath {ps_literal(qemu)} -Confirm:$false }}
catch {{ $factoryError=$_.Exception.Message; $factoryPosition=$_.InvocationInfo.PositionMessage; $factoryStack=$_.ScriptStackTrace }}
$destination=Join-Path {ps_literal(checkout)} 'image/vmware-workstation/test-vms/peer'
[pscustomobject]@{{ result=$factoryResult; error=$factoryError; position=$factoryPosition; stack=$factoryStack; calls=@($global:FactoryCalls); receipts=@($script:PublishedPaths); originalReceipt=$script:OriginalReceiptPath; outputExists=(Test-Path -LiteralPath $destination); diskExists=(Test-Path -LiteralPath (Join-Path $destination 'peer.vmdk')); seedExists=(Test-Path -LiteralPath (Join-Path $destination 'peer-seed.iso')) }} | ConvertTo-Json -Depth 10 -Compress
"""
    if mode == "Inspect":
        ownership_module = ROOT / "scripts/windows/vmware/Atlaso.TestVmOwnership.ps1"
        wrapper = wrapper.replace(
            "$global:FactoryCalls=[Collections.Generic.List[string]]::new()",
            "$global:FactoryCalls=[Collections.Generic.List[string]]::new()\n"
            f". {ps_literal(ownership_module)}",
        )
    selector_args = ""
    if receipt_path and receipt_sha256:
        selector_args = f" -OriginalReceiptPath {ps_literal(receipt_path)} -OriginalReceiptSha256 {ps_literal(receipt_sha256)}"
    wrapper = wrapper.replace(
        f"-QemuImgPath {ps_literal(qemu)} -Confirm:$false",
        f"-QemuImgPath {ps_literal(qemu)}{selector_args} -Confirm:$false",
    )
    harness = vmware / "factory-lower-body-harness.ps1"
    harness.write_text(wrapper, encoding="utf-8")
    return harness, checkout


def run_lower_body_harness(harness: Path) -> dict[str, object]:
    """Execute the generated synthetic PowerShell harness and decode its summary.

    Args:
        harness: Path to the generated isolated PowerShell script.
    """
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_full_lower_body_plan_executes_with_mocked_source_and_admission(tmp_path: Path):
    """Run actual Plan orchestration and prove it reaches no output or provider boundary.

    Args:
        tmp_path: Pytest-owned root for the generated harness and checkout.
    """
    harness, checkout = lower_body_harness(tmp_path, mode="Plan")
    observed = run_lower_body_harness(harness)
    assert observed["error"] is None
    assert observed["result"]["Mode"] == "Plan"
    assert observed["result"]["OriginalIsoAdmitted"] is True
    assert observed["result"]["SourceDiskAdmitted"] is True
    assert observed["result"]["StartsVm"] is False
    assert observed["outputExists"] is False
    calls = observed["calls"]
    assert calls.count("python") == 2
    assert "context" in calls and "checkout-source" in calls
    assert not {"pr", "qemu-or-process", "agent", "capacity", "publisher", "output", "lan"}.intersection(calls)
    assert not (checkout / "image").exists()


def test_full_lower_body_create_refuses_changed_source_before_external_boundaries(tmp_path: Path):
    """Run actual Create orchestration through source hashing, then preserve a failed boundary.

    Args:
        tmp_path: Pytest-owned root for the generated harness and checkout.
    """
    harness, checkout = lower_body_harness(tmp_path, mode="Create", mismatched_disk=True)
    observed = run_lower_body_harness(harness)
    assert "independently admitted certificate peer source changed before pinning" in observed["error"]
    assert observed["outputExists"] is False
    assert not (checkout / "image").exists()
    calls = observed["calls"]
    assert calls.count("python") == 2
    assert "context" in calls and "checkout-source" in calls
    assert not {"pr", "qemu-or-process", "agent", "capacity", "publisher", "output", "lan"}.intersection(calls)


def test_full_lower_body_create_publishes_receipts_before_copy_and_seed(tmp_path: Path):
    """Execute positive Create through local disk copy, seed mock, and prepared receipt.

    Args:
        tmp_path: Pytest-owned root for the generated harness and checkout.
    """
    harness, checkout = lower_body_harness(tmp_path, mode="Create", successful_create=True)
    observed = run_lower_body_harness(harness)
    assert observed["error"] is None, observed
    assert observed["result"]["Mode"] == "Create"
    assert observed["result"]["State"] == "offline-prepared-not-native-acceptance"
    assert observed["outputExists"] is True
    assert observed["diskExists"] is True
    assert observed["seedExists"] is True

    calls = observed["calls"]
    ordered_events = [
        "publisher-intent",
        "output-created",
        "publisher-directory",
        "lan-mock",
        "publisher-lan",
        "publisher-original",
        "disk-copy-observed",
        "seed",
        "publisher-prepared",
    ]
    positions = [calls.index(event) for event in ordered_events]
    assert positions == sorted(positions)
    assert "pr-mock" in calls and "agent-mock" in calls
    assert "qemu-mock" in calls and "capacity-mock" in calls
    assert not any("provider" in call or "vmrun" in call for call in calls)

    receipt_path = Path(observed["originalReceipt"])
    original = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert original["phase"] == "original-certificate-peer-created"
    assert original["task_id"] == "synthetic-task"
    assert original["repository"] == "mdaneri/Atlaso"
    assert original["pr"] == 1118
    assert original["source_commit"] == "a" * 40
    output_root = checkout / "image/vmware-workstation/test-vms/peer"
    actual_identity = WindowsFiles().snapshot(output_root)["."]["identity"]
    assert original["root_identity"] == actual_identity
    assert original["original_identities"]["directory"]
    assert original["persistent_vm_identity_sha256"]
    assert hashlib.sha256(receipt_path.read_bytes()).hexdigest() == observed["result"]["OriginalReceiptSha256"]
    prepared_path = Path(observed["result"]["PreparedReceiptPath"])
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    assert prepared["kind"] == "certificate-dhcp-peer-fixture"
    assert prepared["original_receipt_path"] == str(receipt_path)


def test_full_lower_body_seed_failure_preserves_original_receipt_and_disk(tmp_path: Path):
    """A seed boundary failure retains the original peer receipt and copied disk.

    Args:
        tmp_path: Pytest-owned root for the generated harness and checkout.
    """
    harness, checkout = lower_body_harness(tmp_path, mode="Create", successful_create=True, fail_seed=True)
    observed = run_lower_body_harness(harness)
    assert "Synthetic seed generation failure" in observed["error"]
    assert observed["outputExists"] is True
    assert observed["diskExists"] is True
    assert observed["seedExists"] is False
    assert "publisher-original" in observed["calls"]
    assert "seed" in observed["calls"]
    assert observed["calls"].count("seed") == 1
    assert "publisher-prepared" not in observed["calls"]
    assert not any("cleanup" in call or "remove" in call or "retry" in call for call in observed["calls"])
    receipt_path = Path(observed["originalReceipt"])
    assert receipt_path.is_file()
    output_root = checkout / "image/vmware-workstation/test-vms/peer"
    assert (output_root / "peer.vmx").is_file()
    assert (output_root / "peer.vmdk").is_file()


def test_full_lower_body_inspect_uses_real_sealed_reader_with_bound_original_receipt(tmp_path: Path):
    """Inspect validates the exact standard ownership receipt before reporting success.

    Args:
        tmp_path: Pytest-owned root for the generated harness and checkout.
    """
    harness, checkout = lower_body_harness(tmp_path, mode="Inspect")
    observed = run_lower_body_harness(harness)
    assert observed["error"] is None, observed
    assert observed["result"]["Mode"] == "Inspect"
    assert observed["result"]["OriginalOwnershipVerified"] is True
    assert observed["calls"].count("git-ancestry") == 2
    assert not any("remove" in call.lower() or "cleanup" in call.lower() for call in observed["calls"])
    assert observed["outputExists"] is True
    assert observed["receipts"] == []
    assert (checkout / "image/vmware-workstation/test-vms/peer/peer.vmx").is_file()


def test_full_lower_body_inspect_refuses_tampered_original_digest_before_ancestry(tmp_path: Path):
    """The real sealed reader rejects changed receipt bytes before trusting ancestry.

    Args:
        tmp_path: Pytest-owned root for the generated harness and checkout.
    """
    harness, _ = lower_body_harness(tmp_path, mode="Inspect", tamper_receipt=True)
    observed = run_lower_body_harness(harness)
    assert "Original recovery receipt changed" in observed["error"]
    assert observed["calls"].count("git-ancestry") == 1
    assert observed["receipts"] == []
    assert not any("remove" in call.lower() or "cleanup" in call.lower() for call in observed["calls"])


def test_prepared_output_helper_publishes_receipt_readable_by_real_sealed_reader(tmp_path: Path):
    """The actual empty-directory helper publishes its original identity before returning.

    Args:
        tmp_path: Pytest-owned root for durable receipt, worktree, and output fixtures.
    """
    durable = tmp_path / "durable"
    worktree = tmp_path / "worktree"
    output = tmp_path / "peer"
    durable.mkdir()
    worktree.mkdir()
    vmware = ROOT / "scripts/windows/vmware"
    command = f"""
$ErrorActionPreference='Stop'
Import-Module {ps_literal(vmware / 'Atlaso.WorkstationCleanup.psm1')} -Force
. {ps_literal(vmware / 'Atlaso.TestVmOwnership.ps1')}
{script_function('Publish-CertificatePeerRecord')}
{script_function('New-CertificatePeerPreparedOutput')}
function git {{ $global:LASTEXITCODE=0; return }}
$context=[pscustomobject]@{{ Enabled=$true; TaskId='synthetic-task'; Repository='mdaneri/Atlaso';
  SourceCommit={ps_literal('a' * 40)}; Branch='codex/synthetic-task'; Worktree={ps_literal(worktree)};
  OutputDirectory={ps_literal(output)}; VmxPath=(Join-Path {ps_literal(output)} 'peer.vmx'); Name='peer';
  PullRequestNumber=1118; LocalBuilder=$false; EvidenceDirectory={ps_literal(durable)};
  EvidenceDirectoryId=[Atlaso.WorkstationFileIdentity]::Get({ps_literal(durable)});
  IntentPath=(Join-Path {ps_literal(durable)} 'intent.json'); IntentSha256={ps_literal('b' * 64)} }}
$pin=New-CertificatePeerPreparedOutput -Context $context -PlanSha256 {ps_literal('c' * 64)}
try {{
  $retained=$pin.GetRetainedCreatedIdentity({ps_literal(output)})
  $receipt=Get-ChildItem -LiteralPath {ps_literal(durable)} -Filter 'atlaso-test-vm-directory-*.json' | Select-Object -First 1
  $digest=(Get-FileHash -LiteralPath $receipt.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
  $record=Read-AtlasoTestVmSealedRecord -Context $context -Path $receipt.FullName -Sha256 $digest -Phase 'original-certificate-peer-directory'
  [pscustomobject]@{{ receipt=$receipt.FullName; sha256=$digest; record=$record;
    retained=$retained; observed=[Atlaso.WorkstationFileIdentity]::Get({ps_literal(output)}); outputExists=(Test-Path -LiteralPath {ps_literal(output)}) }} | ConvertTo-Json -Depth 10 -Compress
}} finally {{ $pin.Dispose() }}
"""
    result = run_powershell(command)
    observed = json.loads(result.stdout.strip().splitlines()[-1])
    record = observed["record"]
    assert observed["outputExists"] is True
    assert observed["retained"] == observed["observed"] == record["original_identity"]
    assert record["phase"] == "original-certificate-peer-directory"
    assert record["kind"] == "certificate-peer-directory"
    assert record["task_id"] == "synthetic-task"
    assert record["repository"] == "mdaneri/Atlaso"
    assert record["worktree"] == str(worktree)
    assert record["source_branch"] == "codex/synthetic-task"
    assert record["source_commit"] == "a" * 40
    assert record["output_directory"] == str(output)
    assert record["vmx_path"] == str(output / "peer.vmx")
    assert record["canonical_name"] == "peer"
    assert record["pull_request_number"] == 1118
    assert record["local_builder"] is False
    assert record["plan_sha256"] == "c" * 64
    assert hashlib.sha256(Path(observed["receipt"]).read_bytes()).hexdigest() == observed["sha256"]
