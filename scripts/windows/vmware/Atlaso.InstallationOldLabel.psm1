<#
.SYNOPSIS
Prepare a genuine old system-content filesystem only in a newly owned regular image before its baseline.
#>
Set-StrictMode -Version Latest

<#
.SYNOPSIS
Return the finite public seed identity shared by creation and baseline admission.
#>
function Get-AtlasoInstallationOldLabelSpec {
    return [pscustomobject]@{
        Label = 'ATLASO_SYSTEM'; Uuid = '54205420-0000-4000-8000-000000000004'
        Sentinel = "Atlaso issue542 unselected old system-content disk`n"
    }
}

<#
.SYNOPSIS
Create the old-label disk from a new regular raw image without mounting or opening a host block device.
.PARAMETER OutputDirectory
Original receipt-owned VM directory, pinned by the creation caller.
.PARAMETER QemuImg
Resolved native qemu-img executable used for image creation and conversion.
#>
function New-AtlasoInstallationOldLabelDisk {
    param([string]$OutputDirectory, [string]$QemuImg)
    $spec = Get-AtlasoInstallationOldLabelSpec
    $raw = Join-Path $OutputDirectory 'old-system-label.raw'
    $seed = Join-Path $OutputDirectory 'old-system-label-content'
    $disk = Join-Path $OutputDirectory 'unselected-4g.vmdk'
    foreach ($path in @($raw, $seed, $disk)) {
        if (Test-Path -LiteralPath $path) { throw 'Old-label seed requires new absent image and content paths.' }
    }
    # These artifacts remain inside the original VM root for its identity-bound owning cleanup.
    $null = New-Item -ItemType Directory -Path $seed -ErrorAction Stop
    $sentinel = Join-Path $seed 'sentinel.txt'
    $stream = [IO.File]::Open($sentinel, [IO.FileMode]::CreateNew)
    try { $stream.Write([Text.Encoding]::UTF8.GetBytes($spec.Sentinel)); $stream.Flush($true) }
    finally { $stream.Dispose() }
    $null = Invoke-AtlasoBoundedProcess -FilePath $QemuImg -ArgumentList @('create', '-q', '-f', 'raw', $raw, '4294967296') `
        -TimeoutSeconds 120 -Action 'Create new owned old-label regular image'
    $program = @'
import hashlib,json,os,pathlib,re,shutil,stat,subprocess,sys
def path(value):
 if not re.fullmatch(r'[A-Za-z]:\\[^\r\n]+',value): raise ValueError('A local drive path is required')
 p=pathlib.Path('/mnt/'+value[0].lower()+'/'+value[3:].replace('\\','/'))
 for parent in [p,*p.parents]:
  if parent.is_symlink(): raise ValueError('Image paths cannot contain symlinks')
 return p
raw,seed=map(path,sys.argv[1:3]);label,uuid=sys.argv[3:5]
info=raw.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size!=4294967296: raise ValueError('New regular four-GiB image required')
if raw.parent!=seed.parent or not seed.is_dir() or sorted(p.name for p in seed.iterdir())!=['sentinel.txt']: raise ValueError('Unexpected seed content')
tools={}
for name in ['mke2fs','debugfs','e2fsck','blkid']:
 tool=shutil.which(name)
 if not tool: raise ValueError('Required filesystem image tool unavailable')
 tools[name]={'path':tool,'sha256':hashlib.sha256(pathlib.Path(tool).read_bytes()).hexdigest()}
def run(name,args):
 r=subprocess.run([tools[name]['path'],*args],capture_output=True,timeout=60)
 if r.returncode!=0: raise ValueError('Filesystem image tool refused '+name)
 return r.stdout
run('mke2fs',['-q','-F','-t','ext4','-b','4096','-m','0','-L',label,'-U',uuid,'-E','lazy_itable_init=0,lazy_journal_init=0','-d',str(seed),str(raw)])
run('e2fsck',['-f','-n',str(raw)])
identity=dict(line.split('=',1) for line in run('blkid',['-p','-o','export',str(raw)]).decode().splitlines() if '=' in line)
actual=run('debugfs',['-R','cat /sentinel.txt',str(raw)])
if identity.get('LABEL')!=label or identity.get('UUID')!=uuid or identity.get('TYPE')!='ext4' or actual!=(seed/'sentinel.txt').read_bytes(): raise ValueError('Old-label filesystem verification failed')
with raw.open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
print(json.dumps({'schema':1,'label':label,'uuid':uuid,'filesystem':'ext4','virtual_size_bytes':info.st_size,'raw_sha256':digest,'sentinel_sha256':hashlib.sha256(actual).hexdigest(),'tools':tools,'wsl_distribution':os.environ.get('WSL_DISTRO_NAME')}))
'@
    $json = Invoke-AtlasoBoundedProcess -FilePath 'wsl.exe' -ArgumentList @('--exec', '/usr/bin/python3', '-c', $program, $raw, $seed, $spec.Label, $spec.Uuid) `
        -TimeoutSeconds 240 -Action 'Seed and independently inspect new old-label filesystem image'
    if ($json.Length -gt 8192) { throw 'Old-label filesystem record exceeds its public bound.' }
    $record = $json | ConvertFrom-Json
    $expectedSentinel = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($spec.Sentinel))).ToLowerInvariant()
    if ($record.schema -ne 1 -or $record.label -cne $spec.Label -or $record.uuid -cne $spec.Uuid -or
        $record.filesystem -cne 'ext4' -or $record.virtual_size_bytes -ne 4GB -or
        $record.raw_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $record.sentinel_sha256 -cne $expectedSentinel -or
        (Get-FileHash -LiteralPath $raw -Algorithm SHA256).Hash -ine $record.raw_sha256) {
        throw 'Old-label seed does not match the fixed original creation recipe.'
    }
    $null = Invoke-AtlasoBoundedProcess -FilePath $QemuImg -ArgumentList @('convert', '-q', '-f', 'raw', '-O', 'vmdk', '-o', 'subformat=monolithicSparse,adapter_type=lsilogic', $raw, $disk) `
        -TimeoutSeconds 120 -Action 'Convert original old-label image to new unselected VMDK'
    $null = Invoke-AtlasoBoundedProcess -FilePath $QemuImg -ArgumentList @('compare', '-f', 'raw', '-F', 'vmdk', $raw, $disk) `
        -TimeoutSeconds 120 -Action 'Verify old-label VMDK logical equality before baseline'
    return $record
}

<#
.SYNOPSIS
Require the fixed old-label seed plan and its creation-time verified filesystem evidence.
.PARAMETER Original
Admitted original VM receipt with the immutable seed plan.
.PARAMETER Baseline
Admitted baseline published only after the genuine old-label image was verified.
#>
function Assert-AtlasoInstallationOldLabelRecords {
    param([psobject]$Original, [psobject]$Baseline)
    $spec = Get-AtlasoInstallationOldLabelSpec
    $sentinelSha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($spec.Sentinel))).ToLowerInvariant()
    if (-not $Original.PSObject.Properties['old_label_seed_plan'] -or -not $Baseline.PSObject.Properties['old_label_seed']) {
        throw 'Original old-label seed plan and before-use evidence are required.'
    }
    $plan = $Original.old_label_seed_plan; $seed = $Baseline.old_label_seed
    if ($plan.Label -cne $spec.Label -or $plan.Uuid -cne $spec.Uuid -or $plan.Sentinel -cne $spec.Sentinel -or
        $seed.schema -ne 1 -or $seed.label -cne $spec.Label -or $seed.uuid -cne $spec.Uuid -or
        $seed.filesystem -cne 'ext4' -or $seed.virtual_size_bytes -ne 4GB -or
        $seed.raw_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $seed.sentinel_sha256 -cne $sentinelSha) {
        throw 'Original old-label filesystem evidence differs from its sealed recipe.'
    }
}

<#
.SYNOPSIS
Require an original controlled-interruption record bound to exactly the same VM and baseline.
.PARAMETER Original
Original VM identity admitted by the owning reader.
.PARAMETER Interruption
Hash-admitted interruption record; the owning reader also verifies task, source and repository context.
.PARAMETER Selectors
Independently retained original VM and baseline paths and digests.
#>
function Assert-AtlasoInstallationInterruptionRecord {
    param([psobject]$Original, [psobject]$Interruption, [hashtable]$Selectors)
    if ($Interruption.phase -cne 'installation-controlled-interruption' -or
        $Interruption.original_receipt_path -cne $Selectors.OriginalReceiptPath -or
        $Interruption.original_receipt_sha256 -cne $Selectors.OriginalReceiptSha256 -or
        $Interruption.baseline_receipt_path -cne $Selectors.BaselineReceiptPath -or
        $Interruption.baseline_receipt_sha256 -cne $Selectors.BaselineReceiptSha256 -or
        $Interruption.original_directory_identity -cne $Original.original_identities.directory -or
        $Interruption.persistent_vm_identity_sha256 -cne $Original.persistent_vm_identity_sha256 -or
        $Interruption.stage -cne 'installing Photon appliance packages' -or
        $Interruption.unselected_logical_contents_unchanged -isnot [bool] -or -not $Interruption.unselected_logical_contents_unchanged -or
        $Interruption.selected_disks_may_have_been_written -isnot [bool] -or -not $Interruption.selected_disks_may_have_been_written) {
        throw 'Installer interruption receipt differs from the original stopped fixture.'
    }
}

Export-ModuleMember -Function Get-AtlasoInstallationOldLabelSpec, New-AtlasoInstallationOldLabelDisk, Assert-AtlasoInstallationOldLabelRecords, Assert-AtlasoInstallationInterruptionRecord
