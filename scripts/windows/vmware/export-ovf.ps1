<#
.SYNOPSIS
Export a VMware VMX into a validated Atlaso OVF/OVA package.

.PARAMETER SourceVmxPath
Path to the source VMX used for ovftool export.
.PARAMETER OutputDirectory
Directory to hold generated OVF artifacts.
.PARAMETER Name
Base name for exported assets.
.PARAMETER OvfToolPath
Optional path to ovftool or an ovftool installation directory.
.PARAMETER TarPath
Optional path to tar used when creating OVA archives.
.PARAMETER NoOva
Skip OVA creation and emit OVF only.
.PARAMETER Force
Allow replacement of the exact approved output directory.
#>
<#
.SYNOPSIS
Export a verified Atlaso VMware image as a customized OVF or OVA package.
.PARAMETER SourceVmxPath
Source Vmx Path value.
.PARAMETER OutputDirectory
Output Directory value.
.PARAMETER Name
Name value.
.PARAMETER OvfToolPath
Ovf Tool Path value.
.PARAMETER TarPath
Tar Path value.
.PARAMETER NoOva
No Ova value.
.PARAMETER Force
Force value.
#>
[CmdletBinding()]
param(
    [string]$SourceVmxPath = 'image/vmware-workstation/output/atlaso-photon-vmware-workstation/Atlaso-Photon-Builder-VMware.vmx',
    [string]$OutputDirectory = '',
    [string]$Name = 'Atlaso-Photon',
    [string]$OvfToolPath = '',
    [string]$TarPath = '',
    [switch]$NoOva,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$outputSafetyModule = Join-Path $PSScriptRoot 'Atlaso.OvfExport.psm1'
Import-Module $outputSafetyModule -Force
$payloadModule = Join-Path $PSScriptRoot 'Atlaso.VmwarePayload.psm1'
Import-Module $payloadModule -Force

$ovfNamespace = 'http://schemas.dmtf.org/ovf/envelope/1'
$rasdNamespace = 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData'
$vmwNamespace = 'http://www.vmware.com/schema/ovf'

<#
.SYNOPSIS
Resolve the location of ovftool from a provided path or common install locations.

.PARAMETER Path
Path to an ovftool executable or directory containing ovftool.exe.
#>
<#
.SYNOPSIS
Resolve Ovf Tool Path.
.PARAMETER Path
Path value.
#>
function Resolve-OvfToolPath {
    param([string]$Path)

    if ($Path) {
        $candidate = if (Test-Path -LiteralPath $Path -PathType Container) {
            Join-Path $Path 'ovftool.exe'
        }
        else {
            $Path
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "ovftool was not found: $Path"
        }
        return (Resolve-Path -LiteralPath $candidate).Path
    }

    foreach ($candidate in @(
            'C:\Program Files\VMware\VMware Workstation\OVFTool\ovftool.exe',
            'C:\Program Files (x86)\VMware\VMware Workstation\OVFTool\ovftool.exe',
            'C:\Program Files\VMware\VMware OVF Tool\ovftool.exe',
            'C:\Program Files (x86)\VMware\VMware OVF Tool\ovftool.exe'
        )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    $command = Get-Command ovftool -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'ovftool was not found. Install VMware Workstation or pass -OvfToolPath.'
}

<#
.SYNOPSIS
Resolve the tar executable used for OVA archive creation.

.PARAMETER Path
Optional custom tar path.
#>
<#
.SYNOPSIS
Resolve Tar Path.
.PARAMETER Path
Path value.
#>
function Resolve-TarPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "tar was not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    $command = Get-Command tar.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $fallback = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (Test-Path -LiteralPath $fallback -PathType Leaf) {
        return $fallback
    }
    throw 'tar.exe was not found. Pass -NoOva to keep only the OVF folder.'
}

<#
.SYNOPSIS
Create a new OVF namespace attribute on an XML element.

.PARAMETER Document
XML document owning the created attribute.
.PARAMETER Name
Attribute local name.
.PARAMETER Value
Text serialized into the created OVF attribute.
#>
<#
.SYNOPSIS
Create Ovf Attribute.
.PARAMETER Document
Document value.
.PARAMETER Name
Name value.
.PARAMETER Value
Text assigned to the new OVF attribute.
#>
function New-OvfAttribute {
    param(
        [xml]$Document,
        [string]$Name,
        [string]$Value
    )

    $attribute = $Document.CreateAttribute('ovf', $Name, $ovfNamespace)
    $attribute.Value = $Value
    return $attribute
}

<#
.SYNOPSIS
Set an OVF namespaced attribute value on an element.

.PARAMETER Document
XML document used for creating new attributes when missing.
.PARAMETER Element
XML element receiving the attribute.
.PARAMETER Name
Attribute local name.
.PARAMETER Value
Text serialized into the OVF attribute.
#>
<#
.SYNOPSIS
Set Ovf Attribute.
.PARAMETER Document
Document value.
.PARAMETER Element
Element value.
.PARAMETER Name
Name value.
.PARAMETER Value
Text assigned to the OVF attribute.
#>
function Set-OvfAttribute {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$Element,
        [string]$Name,
        [string]$Value
    )

    $existing = $Element.Attributes.GetNamedItem($Name, $ovfNamespace)
    if ($existing) {
        $existing.Value = $Value
        return
    }
    [void]$Element.Attributes.Append((New-OvfAttribute -Document $Document -Name $Name -Value $Value))
}

<#
.SYNOPSIS
Set a VMware namespaced attribute value on an element.

.PARAMETER Document
XML document used for creating new attributes when missing.
.PARAMETER Element
XML element receiving the attribute.
.PARAMETER Name
Attribute local name.
.PARAMETER Value
Text serialized into the VMware namespaced attribute.
#>
<#
.SYNOPSIS
Set Vmw Attribute.
.PARAMETER Document
Document value.
.PARAMETER Element
Element value.
.PARAMETER Name
Name value.
.PARAMETER Value
Text assigned to the VMware namespaced attribute.
#>
function Set-VmwAttribute {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$Element,
        [string]$Name,
        [string]$Value
    )

    $existing = $Element.Attributes.GetNamedItem($Name, $vmwNamespace)
    if ($existing) {
        $existing.Value = $Value
        return
    }
    $attribute = $Document.CreateAttribute('vmw', $Name, $vmwNamespace)
    $attribute.Value = $Value
    [void]$Element.Attributes.Append($attribute)
}

<#
.SYNOPSIS
Add a text child element to a parent using the OVF namespace.

.PARAMETER Document
XML document used to create new elements.
.PARAMETER Parent
Parent element for the new node.
.PARAMETER LocalName
Local element name.
.PARAMETER Value
Text serialized inside the new child element.
#>
<#
.SYNOPSIS
Add Text Element.
.PARAMETER Document
Document value.
.PARAMETER Parent
Parent value.
.PARAMETER LocalName
Local Name value.
.PARAMETER Value
Inner text assigned to the new child element.
#>
function Add-TextElement {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$Parent,
        [string]$LocalName,
        [string]$Value
    )

    $element = $Document.CreateElement('ovf', $LocalName, $ovfNamespace)
    $element.InnerText = $Value
    [void]$Parent.AppendChild($element)
    return $element
}

<#
.SYNOPSIS
Find a child element by local name and namespace.

.PARAMETER Parent
Parent XML element to scan.
.PARAMETER LocalName
Child element local name to match.
.PARAMETER Namespace
Child element namespace URI to match.
#>
<#
.SYNOPSIS
Return Namespaced Child Element.
.PARAMETER Parent
Parent value.
.PARAMETER LocalName
Local Name value.
.PARAMETER Namespace
Namespace value.
#>
function Get-NamespacedChildElement {
    param(
        [System.Xml.XmlElement]$Parent,
        [string]$LocalName,
        [string]$Namespace
    )

    foreach ($child in $Parent.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.LocalName -eq $LocalName -and $child.NamespaceURI -eq $Namespace) {
            return $child
        }
    }
    return $null
}

<#
.SYNOPSIS
Set an element's inner text in a namespaced context.

.PARAMETER Document
XML document used to create missing nodes.
.PARAMETER Parent
Parent element for the node.
.PARAMETER Prefix
Namespace prefix used when creating a missing node.
.PARAMETER LocalName
Child local name.
.PARAMETER Namespace
Namespace URI for lookup and creation.
.PARAMETER Value
Value to set.
#>
<#
.SYNOPSIS
Set Namespaced Text Element.
.PARAMETER Document
Document value.
.PARAMETER Parent
Parent value.
.PARAMETER Prefix
Prefix value.
.PARAMETER LocalName
Local Name value.
.PARAMETER Namespace
Namespace value.
.PARAMETER Value
Value value.
#>
function Set-NamespacedTextElement {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$Parent,
        [string]$Prefix,
        [string]$LocalName,
        [string]$Namespace,
        [string]$Value
    )

    $element = Get-NamespacedChildElement -Parent $Parent -LocalName $LocalName -Namespace $Namespace
    if (-not $element) {
        $element = $Document.CreateElement($Prefix, $LocalName, $Namespace)
        [void]$Parent.AppendChild($element)
    }
    $element.InnerText = $Value
    return $element
}

<#
.SYNOPSIS
Remove all matching child elements by local name and namespace.

.PARAMETER Parent
Parent element whose children are pruned.
.PARAMETER LocalName
Child local name to remove.
.PARAMETER Namespace
Child namespace URI to match.
#>
<#
.SYNOPSIS
Remove Namespaced Child Element.
.PARAMETER Parent
Parent value.
.PARAMETER LocalName
Local Name value.
.PARAMETER Namespace
Namespace value.
#>
function Remove-NamespacedChildElement {
    param(
        [System.Xml.XmlElement]$Parent,
        [string]$LocalName,
        [string]$Namespace
    )

    foreach ($child in @($Parent.ChildNodes)) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.LocalName -eq $LocalName -and $child.NamespaceURI -eq $Namespace) {
            [void]$Parent.RemoveChild($child)
        }
    }
}

<#
.SYNOPSIS
Read a RASD value from an item by local name.

.PARAMETER Item
RASD item node.
.PARAMETER LocalName
Target child local name.
#>
<#
.SYNOPSIS
Return Rasd Value.
.PARAMETER Item
Item value.
.PARAMETER LocalName
Local Name value.
#>
function Get-RasdValue {
    param(
        [System.Xml.XmlElement]$Item,
        [string]$LocalName
    )

    $element = Get-NamespacedChildElement -Parent $Item -LocalName $LocalName -Namespace $rasdNamespace
    if ($element) {
        return $element.InnerText
    }
    return ''
}

<#
.SYNOPSIS
Set a RASD child text value.

.PARAMETER Document
XML document used for creating missing nodes.
.PARAMETER Item
RASD item node.
.PARAMETER LocalName
Child local name.
.PARAMETER Value
Value to assign.
#>
<#
.SYNOPSIS
Set Rasd Value.
.PARAMETER Document
Document value.
.PARAMETER Item
Item value.
.PARAMETER LocalName
Local Name value.
.PARAMETER Value
Value value.
#>
function Set-RasdValue {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$Item,
        [string]$LocalName,
        [string]$Value
    )

    [void](Set-NamespacedTextElement -Document $Document -Parent $Item -Prefix 'rasd' -LocalName $LocalName -Namespace $rasdNamespace -Value $Value)
}

<#
.SYNOPSIS
Set or reorder the RASD description value.

.PARAMETER Document
XML document used for namespaced operations.
.PARAMETER Item
RASD item node.
.PARAMETER Value
Description text.
#>
<#
.SYNOPSIS
Set Rasd Description.
.PARAMETER Document
Document value.
.PARAMETER Item
Item value.
.PARAMETER Value
Value value.
#>
function Set-RasdDescription {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$Item,
        [string]$Value
    )

    $description = Set-NamespacedTextElement -Document $Document -Parent $Item -Prefix 'rasd' -LocalName 'Description' -Namespace $rasdNamespace -Value $Value
    $elementName = Get-NamespacedChildElement -Parent $Item -LocalName 'ElementName' -Namespace $rasdNamespace
    if ($elementName -and $description.NextSibling -ne $elementName) {
        [void]$Item.RemoveChild($description)
        [void]$Item.InsertBefore($description, $elementName)
    }
}

<#
.SYNOPSIS
Compute the next available RASD InstanceID for a hardware section.

.PARAMETER HardwareSection
Hardware section containing existing Item nodes.
.PARAMETER NamespaceManager
Namespace manager used for OVF queries.
#>
<#
.SYNOPSIS
Return Next Rasd Instance Id.
.PARAMETER HardwareSection
Hardware Section value.
.PARAMETER NamespaceManager
Namespace Manager value.
#>
function Get-NextRasdInstanceId {
    param(
        [System.Xml.XmlElement]$HardwareSection,
        [System.Xml.XmlNamespaceManager]$NamespaceManager
    )

    $maxId = 0
    foreach ($item in $HardwareSection.SelectNodes('ovf:Item', $NamespaceManager)) {
        $instanceId = 0
        if ([int]::TryParse((Get-RasdValue -Item $item -LocalName 'InstanceID'), [ref]$instanceId) -and $instanceId -gt $maxId) {
            $maxId = $instanceId
        }
    }
    return $maxId + 1
}

<#
.SYNOPSIS
Update the network element metadata in an OVF VirtualHardware section.

.PARAMETER Document
XML document for attribute and child updates.
.PARAMETER Network
OVF network element to update.
.PARAMETER Name
New network name.
.PARAMETER Description
New network description text.
#>
<#
.SYNOPSIS
Set Ovf Network.
.PARAMETER Document
Document value.
.PARAMETER Network
Network value.
.PARAMETER Name
Name value.
.PARAMETER Description
Description value.
#>
function Set-OvfNetwork {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$Network,
        [string]$Name,
        [string]$Description
    )

    Set-OvfAttribute -Document $Document -Element $Network -Name 'name' -Value $Name
    [void](Set-NamespacedTextElement -Document $Document -Parent $Network -Prefix 'ovf' -LocalName 'Description' -Namespace $ovfNamespace -Value $Description)
}

<#
.SYNOPSIS
Normalize network topology in the OVF payload.

.PARAMETER Document
OVF XML document to normalize.
.PARAMETER VirtualSystem
Target VirtualSystem node.
.PARAMETER HardwareSection
VirtualHardwareSection under the virtual system.
.PARAMETER NamespaceManager
Namespace manager for OVF selectors.
#>
<#
.SYNOPSIS
Ensure Atlaso Ovf Networks.
.PARAMETER Document
Document value.
.PARAMETER VirtualSystem
Virtual System value.
.PARAMETER HardwareSection
Hardware Section value.
.PARAMETER NamespaceManager
Namespace Manager value.
#>
function Ensure-AtlasoOvfNetworks {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$VirtualSystem,
        [System.Xml.XmlElement]$HardwareSection,
        [System.Xml.XmlNamespaceManager]$NamespaceManager
    )

    $managementNetworkName = 'Atlaso Management Network'
    $serviceNetworkName = 'Atlaso Services Network'

    $envelope = $Document.SelectSingleNode('/ovf:Envelope', $NamespaceManager)
    if (-not $envelope) {
        throw 'OVF descriptor does not contain an ovf:Envelope.'
    }

    $networkSection = $Document.SelectSingleNode('/ovf:Envelope/ovf:NetworkSection', $NamespaceManager)
    $nestedNetworkSection = $Document.SelectSingleNode('//ovf:VirtualSystem/ovf:NetworkSection', $NamespaceManager)
    if (-not $networkSection -and $nestedNetworkSection) {
        [void]$nestedNetworkSection.ParentNode.RemoveChild($nestedNetworkSection)
        [void]$envelope.InsertBefore($nestedNetworkSection, $VirtualSystem)
        $networkSection = $nestedNetworkSection
    }
    if (-not $networkSection) {
        $networkSection = $Document.CreateElement('ovf', 'NetworkSection', $ovfNamespace)
        [void](Add-TextElement -Document $Document -Parent $networkSection -LocalName 'Info' -Value 'Atlaso deployment networks')
        [void]$envelope.InsertBefore($networkSection, $VirtualSystem)
    }

    $networks = @($networkSection.GetElementsByTagName('Network', $ovfNamespace))
    $managementNetwork = $networks | Select-Object -First 1
    if (-not $managementNetwork) {
        $managementNetwork = $Document.CreateElement('ovf', 'Network', $ovfNamespace)
        [void]$networkSection.AppendChild($managementNetwork)
    }
    Set-OvfNetwork -Document $Document -Network $managementNetwork -Name $managementNetworkName -Description 'Management-only network for the Atlaso admin UI and appliance administration.'

    $serviceNetwork = $networks | Where-Object {
        $name = $_.Attributes.GetNamedItem('name', $ovfNamespace)
        $name -and $name.Value -eq $serviceNetworkName
    } | Select-Object -First 1
    if (-not $serviceNetwork) {
        $serviceNetwork = $Document.CreateElement('ovf', 'Network', $ovfNamespace)
        [void]$networkSection.AppendChild($serviceNetwork)
    }
    Set-OvfNetwork -Document $Document -Network $serviceNetwork -Name $serviceNetworkName -Description 'Service network for Atlaso-managed DNS, DHCP, CA, depot, PXE, KMS, and other lab services.'

    $networkAdapters = @($HardwareSection.SelectNodes('ovf:Item', $NamespaceManager) | Where-Object { (Get-RasdValue -Item $_ -LocalName 'ResourceType') -eq '10' })
    if ($networkAdapters.Count -eq 0) {
        throw 'OVF descriptor does not contain a network adapter to use as the management NIC.'
    }

    $managementAdapter = $networkAdapters[0]
    Set-RasdValue -Document $Document -Item $managementAdapter -LocalName 'ElementName' -Value 'Network adapter 1'
    Set-RasdValue -Document $Document -Item $managementAdapter -LocalName 'Description' -Value 'VMXNET3 Ethernet adapter for Atlaso management traffic.'
    Set-RasdValue -Document $Document -Item $managementAdapter -LocalName 'Connection' -Value $managementNetworkName

    $serviceAdapter = $networkAdapters | Where-Object { (Get-RasdValue -Item $_ -LocalName 'Connection') -eq $serviceNetworkName } | Select-Object -First 1
    if (-not $serviceAdapter -and $networkAdapters.Count -ge 2) {
        $serviceAdapter = $networkAdapters[1]
    }
    if (-not $serviceAdapter) {
        $serviceAdapter = $managementAdapter.CloneNode($true)
        Remove-NamespacedChildElement -Parent $serviceAdapter -LocalName 'Address' -Namespace $rasdNamespace
        [void]$HardwareSection.InsertAfter($serviceAdapter, $managementAdapter)
    }

    Set-RasdValue -Document $Document -Item $serviceAdapter -LocalName 'ElementName' -Value 'Network adapter 2'
    Set-RasdValue -Document $Document -Item $serviceAdapter -LocalName 'Description' -Value 'VMXNET3 Ethernet adapter for Atlaso service traffic.'
    Set-RasdValue -Document $Document -Item $serviceAdapter -LocalName 'InstanceID' -Value "$(Get-NextRasdInstanceId -HardwareSection $HardwareSection -NamespaceManager $NamespaceManager)"
    Set-RasdValue -Document $Document -Item $serviceAdapter -LocalName 'ResourceType' -Value '10'
    Set-RasdValue -Document $Document -Item $serviceAdapter -LocalName 'ResourceSubType' -Value 'VmxNet3'
    Set-RasdValue -Document $Document -Item $serviceAdapter -LocalName 'AutomaticAllocation' -Value 'true'
    Set-RasdValue -Document $Document -Item $serviceAdapter -LocalName 'Connection' -Value $serviceNetworkName
}

<#
.SYNOPSIS
Ensure Atlaso-required empty data disks exist and remove stale payload entries.

.PARAMETER Document
OVF XML document to validate.
.PARAMETER HardwareSection
VirtualHardwareSection containing disk hardware items.
.PARAMETER NamespaceManager
Namespace manager for OVF selectors.
#>
<#
.SYNOPSIS
Ensure Atlaso Ovf Empty Data Disks.
.PARAMETER Document
Document value.
.PARAMETER HardwareSection
Hardware Section value.
.PARAMETER NamespaceManager
Namespace Manager value.
#>
function Ensure-AtlasoOvfEmptyDataDisks {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$HardwareSection,
        [System.Xml.XmlNamespaceManager]$NamespaceManager
    )

    $diskSection = $Document.SelectSingleNode('/ovf:Envelope/ovf:DiskSection', $NamespaceManager)
    if (-not $diskSection) {
        throw 'OVF descriptor does not contain a root-level ovf:DiskSection for the Photon OS disk.'
    }

    $hardwareDisks = @($HardwareSection.SelectNodes('ovf:Item', $NamespaceManager) | Where-Object { (Get-RasdValue -Item $_ -LocalName 'ResourceType') -eq '17' })
    $osDisk = $hardwareDisks | Where-Object { (Get-RasdValue -Item $_ -LocalName 'AddressOnParent') -eq '0' } | Select-Object -First 1
    if (-not $osDisk) {
        $osDisk = $hardwareDisks | Select-Object -First 1
    }
    if (-not $osDisk) {
        throw 'OVF descriptor does not contain a Photon OS disk hardware item to clone for the empty data disks.'
    }

    $controllerId = Get-RasdValue -Item $osDisk -LocalName 'Parent'
    if (-not $controllerId) {
        throw 'OVF Photon OS disk hardware item is not attached to a SCSI controller.'
    }

    $osDiskHostResource = Get-RasdValue -Item $osDisk -LocalName 'HostResource'
    if ($osDiskHostResource -notmatch '^ovf:/disk/(.+)$') {
        throw 'OVF Photon OS disk hardware item does not reference an OVF disk definition.'
    }
    $osDiskId = $Matches[1]
    $osDiskDefinition = $Document.SelectSingleNode("/ovf:Envelope/ovf:DiskSection/ovf:Disk[@ovf:diskId='$osDiskId']", $NamespaceManager)
    if (-not $osDiskDefinition) {
        throw "OVF descriptor does not contain the Photon OS disk definition $osDiskId."
    }
    $diskFormat = $osDiskDefinition.GetAttribute('format', $ovfNamespace)
    if ([string]::IsNullOrWhiteSpace($diskFormat)) {
        throw 'OVF Photon OS disk definition does not declare the required ovf:format attribute.'
    }

    $systemContentDisk = $hardwareDisks | Where-Object { (Get-RasdValue -Item $_ -LocalName 'AddressOnParent') -eq '1' } | Select-Object -First 1
    if (-not $systemContentDisk) {
        throw 'OVF descriptor does not contain the required Atlaso system-content disk at SCSI unit 1.'
    }
    $systemContentHostResource = Get-RasdValue -Item $systemContentDisk -LocalName 'HostResource'
    if ($systemContentHostResource -notmatch '^ovf:/disk/(.+)$') {
        throw 'OVF Atlaso system-content disk does not reference an OVF disk definition.'
    }
    $systemContentDefinition = $Document.SelectSingleNode("/ovf:Envelope/ovf:DiskSection/ovf:Disk[@ovf:diskId='$($Matches[1])']", $NamespaceManager)
    if (-not $systemContentDefinition -or [string]::IsNullOrWhiteSpace($systemContentDefinition.GetAttribute('fileRef', $ovfNamespace))) {
        throw 'OVF Atlaso system-content disk must retain its file-backed payload.'
    }

    $dataDisks = @(
        @{ Id = 'atlaso-depot'; Unit = '2'; Name = 'Hard disk 3 - VCF Offline Depot'; Description = 'Empty 500 GiB Atlaso VCF Offline Depot data disk.' },
        @{ Id = 'atlaso-backups'; Unit = '3'; Name = 'Hard disk 4 - VCF Backups'; Description = 'Empty 500 GiB Atlaso VCF Backups data disk.' }
    )

    foreach ($definition in $dataDisks) {
        $disk = $Document.SelectSingleNode("/ovf:Envelope/ovf:DiskSection/ovf:Disk[@ovf:diskId='$($definition.Id)']", $NamespaceManager)
        if (-not $disk) {
            $disk = $Document.CreateElement('ovf', 'Disk', $ovfNamespace)
            [void]$diskSection.AppendChild($disk)
        }
        Set-OvfAttribute -Document $Document -Element $disk -Name 'diskId' -Value $definition.Id
        Set-OvfAttribute -Document $Document -Element $disk -Name 'capacity' -Value '500'
        Set-OvfAttribute -Document $Document -Element $disk -Name 'capacityAllocationUnits' -Value 'byte * 2^30'
        Set-OvfAttribute -Document $Document -Element $disk -Name 'format' -Value $diskFormat
        $disk.RemoveAttribute('fileRef', $ovfNamespace)
        $disk.RemoveAttribute('parentRef', $ovfNamespace)
        $disk.RemoveAttribute('populatedSize', $ovfNamespace)

        $hostResource = "ovf:/disk/$($definition.Id)"
        $diskItem = @($HardwareSection.SelectNodes('ovf:Item', $NamespaceManager) | Where-Object {
                (Get-RasdValue -Item $_ -LocalName 'ResourceType') -eq '17' -and
                (Get-RasdValue -Item $_ -LocalName 'HostResource') -eq $hostResource
            }) | Select-Object -First 1
        if (-not $diskItem) {
            $diskItem = $osDisk.CloneNode($true)
            Remove-NamespacedChildElement -Parent $diskItem -LocalName 'Address' -Namespace $rasdNamespace
            $firstVmwareConfig = @($HardwareSection.ChildNodes | Where-Object {
                    $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.NamespaceURI -eq $vmwNamespace
                }) | Select-Object -First 1
            if ($firstVmwareConfig) {
                [void]$HardwareSection.InsertBefore($diskItem, $firstVmwareConfig)
            }
            else {
                [void]$HardwareSection.AppendChild($diskItem)
            }
        }
        Set-RasdValue -Document $Document -Item $diskItem -LocalName 'InstanceID' -Value "$(Get-NextRasdInstanceId -HardwareSection $HardwareSection -NamespaceManager $NamespaceManager)"
        Set-RasdValue -Document $Document -Item $diskItem -LocalName 'ResourceType' -Value '17'
        Set-RasdValue -Document $Document -Item $diskItem -LocalName 'Parent' -Value $controllerId
        Set-RasdValue -Document $Document -Item $diskItem -LocalName 'AddressOnParent' -Value $definition.Unit
        Set-RasdValue -Document $Document -Item $diskItem -LocalName 'HostResource' -Value $hostResource
        Set-RasdValue -Document $Document -Item $diskItem -LocalName 'ElementName' -Value $definition.Name
        Set-RasdDescription -Document $Document -Item $diskItem -Value $definition.Description
    }
}

<#
.SYNOPSIS
Normalize Atlaso hardware section for VM topology and required disk layout.

.PARAMETER Document
OVF XML document to update.
.PARAMETER HardwareSection
VirtualHardwareSection to normalize.
.PARAMETER NamespaceManager
Namespace manager for OVF selectors.
#>
<#
.SYNOPSIS
Set Atlaso Ovf Hardware.
.PARAMETER Document
Document value.
.PARAMETER HardwareSection
Hardware Section value.
.PARAMETER NamespaceManager
Namespace Manager value.
#>
function Set-AtlasoOvfHardware {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$HardwareSection,
        [System.Xml.XmlNamespaceManager]$NamespaceManager
    )

    $operatingSystem = $Document.SelectSingleNode('//ovf:VirtualSystem/ovf:OperatingSystemSection', $NamespaceManager)
    if (-not $operatingSystem) {
        throw 'OVF descriptor does not contain an ovf:OperatingSystemSection.'
    }
    Set-OvfAttribute -Document $Document -Element $operatingSystem -Name 'id' -Value '36'
    Set-VmwAttribute -Document $Document -Element $operatingSystem -Name 'osType' -Value 'vmwarePhoton64Guest'

    $items = @($HardwareSection.SelectNodes('ovf:Item', $NamespaceManager))
    $scsiControllers = @($items | Where-Object { (Get-RasdValue -Item $_ -LocalName 'ResourceType') -eq '6' })
    if ($scsiControllers.Count -eq 0) {
        throw 'OVF descriptor does not contain a SCSI controller for the appliance disk.'
    }
    foreach ($controller in $scsiControllers) {
        Set-RasdValue -Document $Document -Item $controller -LocalName 'ResourceSubType' -Value 'VirtualSCSI'
        Set-RasdValue -Document $Document -Item $controller -LocalName 'ElementName' -Value 'SCSI Controller 0 - VMware Paravirtual'
        Set-RasdDescription -Document $Document -Item $controller -Value 'VMware Paravirtual SCSI controller.'
    }

    $disks = @($items | Where-Object { (Get-RasdValue -Item $_ -LocalName 'ResourceType') -eq '17' })
    foreach ($disk in $disks) {
        $unit = Get-RasdValue -Item $disk -LocalName 'AddressOnParent'
        if ($unit -eq '0') {
            Set-RasdValue -Document $Document -Item $disk -LocalName 'ElementName' -Value 'Hard disk 1 - Photon OS'
            Set-RasdDescription -Document $Document -Item $disk -Value 'Atlaso Photon OS disk.'
        }
        elseif ($unit -eq '1') {
            Set-RasdValue -Document $Document -Item $disk -LocalName 'ElementName' -Value 'Hard disk 2 - Atlaso System Content'
            Set-RasdDescription -Document $Document -Item $disk -Value 'Required Atlaso application and tools disk.'
        }
        elseif ($unit -eq '2') {
            Set-RasdValue -Document $Document -Item $disk -LocalName 'ElementName' -Value 'Hard disk 3 - VCF Offline Depot'
            Set-RasdDescription -Document $Document -Item $disk -Value 'Expandable Atlaso VCF Offline Depot data disk.'
        }
        elseif ($unit -eq '3') {
            Set-RasdValue -Document $Document -Item $disk -LocalName 'ElementName' -Value 'Hard disk 4 - VCF Backups'
            Set-RasdDescription -Document $Document -Item $disk -Value 'Expandable Atlaso VCF Backups data disk.'
        }
    }

    foreach ($cdrom in @($items | Where-Object { (Get-RasdValue -Item $_ -LocalName 'ResourceType') -eq '15' })) {
        [void]$HardwareSection.RemoveChild($cdrom)
    }

    $remainingItems = @($HardwareSection.SelectNodes('ovf:Item', $NamespaceManager))
    foreach ($controller in @($remainingItems | Where-Object { (Get-RasdValue -Item $_ -LocalName 'ResourceType') -in @('5', '20') })) {
        $instanceId = Get-RasdValue -Item $controller -LocalName 'InstanceID'
        $hasChildren = $remainingItems | Where-Object { (Get-RasdValue -Item $_ -LocalName 'Parent') -eq $instanceId } | Select-Object -First 1
        if (-not $hasChildren) {
            [void]$HardwareSection.RemoveChild($controller)
        }
    }
}

<#
.SYNOPSIS
Validate the OVF disk ordering and required topology for Atlaso payloads.

.PARAMETER OvfPath
OVF descriptor path to validate.
#>
<#
.SYNOPSIS
Validate Atlaso Ovf Disk Topology.
.PARAMETER OvfPath
Ovf Path value.
#>
function Assert-AtlasoOvfDiskTopology {
    param([string]$OvfPath)

    [xml]$document = Get-Content -LiteralPath $OvfPath -Raw
    $manager = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $manager.AddNamespace('ovf', $ovfNamespace)
    $manager.AddNamespace('rasd', $rasdNamespace)

    $diskFiles = @($document.SelectNodes('/ovf:Envelope/ovf:DiskSection/ovf:Disk', $manager))
    $hardwareDisks = @($document.SelectNodes('//ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType="17"]', $manager))
    if ($diskFiles.Count -ne 4 -or $hardwareDisks.Count -ne 4) {
        throw "Atlaso OVF must contain exactly four disks (Photon OS, Atlaso System Content, VCF Offline Depot, and VCF Backups); descriptor has $($diskFiles.Count) disk definitions and $($hardwareDisks.Count) virtual disks."
    }

    $diskFormat = ''
    foreach ($payloadDisk in @(
            @{ Unit = '0'; Name = 'Photon OS' },
            @{ Unit = '1'; Name = 'Atlaso System Content' }
        )) {
        $diskHardware = $hardwareDisks | Where-Object { (Get-RasdValue -Item $_ -LocalName 'AddressOnParent') -eq $payloadDisk.Unit } | Select-Object -First 1
        if (-not $diskHardware) {
            throw "Atlaso OVF is missing the $($payloadDisk.Name) disk at SCSI unit $($payloadDisk.Unit)."
        }
        $hostResource = Get-RasdValue -Item $diskHardware -LocalName 'HostResource'
        $hostResourceMatch = [regex]::Match($hostResource, '^ovf:/disk/(.+)$')
        if (-not $hostResourceMatch.Success) {
            throw "Atlaso OVF $($payloadDisk.Name) disk does not reference an OVF disk definition."
        }
        $diskDefinition = $document.SelectSingleNode("/ovf:Envelope/ovf:DiskSection/ovf:Disk[@ovf:diskId='$($hostResourceMatch.Groups[1].Value)']", $manager)
        if (-not $diskDefinition -or [string]::IsNullOrWhiteSpace($diskDefinition.GetAttribute('fileRef', $ovfNamespace))) {
            throw "Atlaso OVF $($payloadDisk.Name) disk must retain a file-backed payload."
        }
        $payloadFormat = $diskDefinition.GetAttribute('format', $ovfNamespace)
        if ([string]::IsNullOrWhiteSpace($payloadFormat)) {
            throw "Atlaso OVF $($payloadDisk.Name) disk does not declare the required ovf:format attribute."
        }
        if ([string]::IsNullOrWhiteSpace($diskFormat)) {
            $diskFormat = $payloadFormat
        }
        elseif ($payloadFormat -ne $diskFormat) {
            throw 'Atlaso OVF payload disks must use the same disk format.'
        }
    }

    foreach ($diskId in @('atlaso-depot', 'atlaso-backups')) {
        $disk = $document.SelectSingleNode("/ovf:Envelope/ovf:DiskSection/ovf:Disk[@ovf:diskId='$diskId']", $manager)
        if (-not $disk) {
            throw "Atlaso OVF is missing the empty data disk definition $diskId."
        }
        foreach ($forbiddenAttribute in @('fileRef', 'parentRef', 'populatedSize')) {
            if ($disk.HasAttribute($forbiddenAttribute, $ovfNamespace)) {
                throw "Atlaso OVF data disk $diskId must be empty and cannot define ovf:$forbiddenAttribute."
            }
        }
        if ($disk.GetAttribute('format', $ovfNamespace) -ne $diskFormat) {
            throw "Atlaso OVF data disk $diskId must declare the Photon OS disk format."
        }
        if ($disk.GetAttribute('capacity', $ovfNamespace) -ne '500' -or $disk.GetAttribute('capacityAllocationUnits', $ovfNamespace) -ne 'byte * 2^30') {
            throw "Atlaso OVF data disk $diskId must declare an empty 500 GiB capacity."
        }
    }
}

<#
.SYNOPSIS
Write byte-bound OVA provenance for the two verified payload disks.
.PARAMETER RepoRoot
Atlaso repository containing the recorded source commit.
.PARAMETER OvfPath
Normalized OVF descriptor whose payload references are recorded.
.PARAMETER SourceCommit
Exact clean source commit from VMware build provenance.
#>
function Write-AtlasoOvaProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$OvfPath,
        [Parameter(Mandatory = $true)][string]$SourceCommit
    )

    if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw 'VMware build provenance contains an invalid source commit.'
    }
    $metadata = @(& git -C $RepoRoot show "${SourceCommit}:pyproject.toml" 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw "The VMware build source commit is unavailable: $SourceCommit"
    }
    $versionMatch = [regex]::Match($metadata, '(?m)^version\s*=\s*"(?<version>\d+\.\d+\.\d+)"\s*$')
    if (-not $versionMatch.Success) {
        throw 'Could not resolve the synchronized product version from the VMware build source commit.'
    }
    [xml]$document = Get-Content -Raw -LiteralPath $OvfPath
    $manager = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $manager.AddNamespace('ovf', $ovfNamespace)
    $manager.AddNamespace('rasd', $rasdNamespace)
    $hardwareDisks = @($document.SelectNodes(
            '//ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item[rasd:ResourceType="17"]',
            $manager
        ))
    $references = @($document.SelectNodes('/ovf:Envelope/ovf:References/ovf:File', $manager))
    $payloadContracts = @(
        @{ Slot = 0; Role = 'photon_os'; Capacity = 42949672960 },
        @{ Slot = 1; Role = 'atlaso_system'; Capacity = 21474836480 }
    )
    $payloads = foreach ($contract in $payloadContracts) {
        $hardware = @($hardwareDisks | Where-Object {
                (Get-RasdValue -Item $_ -LocalName 'AddressOnParent') -eq [string]$contract.Slot
            })
        if ($hardware.Count -ne 1) {
            throw "OVF provenance requires exactly one payload disk at SCSI slot $($contract.Slot)."
        }
        $hostResource = Get-RasdValue -Item $hardware[0] -LocalName 'HostResource'
        $diskMatch = [regex]::Match($hostResource, '^ovf:/disk/(?<id>[^/]+)$')
        if (-not $diskMatch.Success) {
            throw "OVF payload at SCSI slot $($contract.Slot) has an invalid disk reference."
        }
        $disk = $document.SelectSingleNode(
            "/ovf:Envelope/ovf:DiskSection/ovf:Disk[@ovf:diskId='$($diskMatch.Groups['id'].Value)']",
            $manager
        )
        $fileId = if ($disk) { $disk.GetAttribute('fileRef', $ovfNamespace) } else { '' }
        $file = @($references | Where-Object { $_.GetAttribute('id', $ovfNamespace) -eq $fileId })
        if ($file.Count -ne 1) {
            throw "OVF payload at SCSI slot $($contract.Slot) does not resolve to exactly one file."
        }
        $fileName = $file[0].GetAttribute('href', $ovfNamespace)
        if ([System.IO.Path]::GetFileName($fileName) -ne $fileName) {
            throw 'OVF payload provenance requires flat, safe VMDK file names.'
        }
        $filePath = Join-Path (Split-Path -Parent $OvfPath) $fileName
        $fileItem = Get-Item -LiteralPath $filePath -ErrorAction Stop
        if ($fileItem.Length -le 0 -or
            ($fileItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "OVF payload is missing, empty, or a reparse point: $fileName"
        }
        [ordered]@{
            role               = $contract.Role
            scsi_slot          = $contract.Slot
            file               = $fileName
            virtual_size_bytes = $contract.Capacity
            sha256             = (Get-FileHash -LiteralPath $fileItem.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $provenance = [ordered]@{
        schema_version  = 1
        kind            = 'atlaso-vmware-ova-provenance'
        product_version = $versionMatch.Groups['version'].Value
        source_commit   = $SourceCommit
        machine         = [ordered]@{
            firmware    = 'uefi'
            secure_boot = $false
            cpu_count   = 4
            memory_mib  = 4096
            nic_count   = 2
            disk_bus    = 'scsi'
        }
        payloads        = @($payloads)
    }
    $path = Join-Path (Split-Path -Parent $OvfPath) 'atlaso-provenance.json'
    [System.IO.File]::WriteAllText(
        $path,
        (($provenance | ConvertTo-Json -Depth 8) + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    return $path
}

<#
.SYNOPSIS
Validate the final OVA through the provider-neutral Python contract.
.PARAMETER RepoRoot
Atlaso repository containing the validator.
.PARAMETER OvaPath
Final OVA archive to validate.
#>
function Assert-AtlasoCanonicalOva {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$OvaPath
    )

    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        throw 'python was not found. Canonical OVA validation is mandatory.'
    }
    $validationRoot = Join-Path (Split-Path -Parent $OvaPath) ('.ova-validation-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $validationRoot | Out-Null
    try {
        $output = @(& $python.Source (Join-Path $RepoRoot 'scripts\virtualization\validate_ova.py') `
                $OvaPath '--extract-directory' $validationRoot 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $tail = @($output | Select-Object -Last 20) -join [Environment]::NewLine
            throw "Final OVA validation failed.$([Environment]::NewLine)$tail"
        }
    }
    finally {
        if (Test-Path -LiteralPath $validationRoot) {
            Remove-Item -LiteralPath $validationRoot -Recurse -Force
        }
    }
}

<#
.SYNOPSIS
Find an existing product property by key.

.PARAMETER ProductSection
OVF product section to search.
.PARAMETER Key
Property key value to match.
#>
<#
.SYNOPSIS
Return Ovf Property.
.PARAMETER ProductSection
Product Section value.
.PARAMETER Key
Key value.
#>
function Get-OvfProperty {
    param(
        [System.Xml.XmlElement]$ProductSection,
        [string]$Key
    )

    foreach ($node in $ProductSection.GetElementsByTagName('Property', $ovfNamespace)) {
        $existingKey = $node.Attributes.GetNamedItem('key', $ovfNamespace)
        if ($existingKey -and $existingKey.Value -eq $Key) {
            return $node
        }
    }
    return $null
}

<#
.SYNOPSIS
Add a property category element to the OVF product section.

.PARAMETER Document
OVF document used to create the category node.
.PARAMETER ProductSection
ProductSection node receiving the new category.
.PARAMETER Name
Category display name.
#>
<#
.SYNOPSIS
Add Atlaso Ovf Category.
.PARAMETER Document
Document value.
.PARAMETER ProductSection
Product Section value.
.PARAMETER Name
Name value.
#>
function Add-AtlasoOvfCategory {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$ProductSection,
        [string]$Name
    )

    [void](Add-TextElement -Document $Document -Parent $ProductSection -LocalName 'Category' -Value $Name)
}

<#
.SYNOPSIS
Add or update a typed OVF product property definition.

.PARAMETER Document
OVF document containing the property.
.PARAMETER ProductSection
ProductSection receiving the property.
.PARAMETER Key
Property key.
.PARAMETER Label
Property label.
.PARAMETER Description
Property description text.
.PARAMETER Required
Whether the property is required.
.PARAMETER Password
Whether the property uses password input semantics.
.PARAMETER Boolean
Whether the property uses boolean input semantics.
.PARAMETER DefaultValue
Optional text serialized as the OVF property default.
.PARAMETER MinLength
Minimum permitted string length for password-like strings.
#>
<#
.SYNOPSIS
Set Atlaso Ovf Property.
.PARAMETER Document
Document value.
.PARAMETER ProductSection
Product Section value.
.PARAMETER Key
Key value.
.PARAMETER Label
Label value.
.PARAMETER Description
Description value.
.PARAMETER Required
Required value.
.PARAMETER Password
Password value.
.PARAMETER Boolean
Boolean value.
.PARAMETER DefaultValue
Optional OVF property default serialized when the property declares one.
.PARAMETER MinLength
Min Length value.
#>
function Set-AtlasoOvfProperty {
    param(
        [xml]$Document,
        [System.Xml.XmlElement]$ProductSection,
        [string]$Key,
        [string]$Label,
        [string]$Description,
        [bool]$Required,
        [bool]$Password = $false,
        [bool]$Boolean = $false,
        [string]$DefaultValue = '',
        [int]$MinLength = 0
    )

    $property = Get-OvfProperty -ProductSection $ProductSection -Key $Key
    if (-not $property) {
        $property = $Document.CreateElement('ovf', 'Property', $ovfNamespace)
    }
    [void]$ProductSection.AppendChild($property)
    Set-OvfAttribute -Document $Document -Element $property -Name 'key' -Value $Key
    $propertyType = if ($Password) { 'password' } elseif ($Boolean) { 'boolean' } else { 'string' }
    Set-OvfAttribute -Document $Document -Element $property -Name 'type' -Value $propertyType
    Set-OvfAttribute -Document $Document -Element $property -Name 'userConfigurable' -Value 'true'
    Set-OvfAttribute -Document $Document -Element $property -Name 'required' -Value ($Required.ToString().ToLowerInvariant())
    if ($MinLength -gt 0) {
        Set-OvfAttribute -Document $Document -Element $property -Name 'qualifiers' -Value "MinLen($MinLength)"
    }
    else {
        $property.RemoveAttribute('qualifiers', $ovfNamespace)
    }
    if ($DefaultValue) {
        Set-OvfAttribute -Document $Document -Element $property -Name 'value' -Value $DefaultValue
    }
    else {
        $property.RemoveAttribute('value', $ovfNamespace)
    }
    $property.RemoveAttribute('password', $vmwNamespace)

    foreach ($childName in @('Label', 'Description')) {
        foreach ($child in @($property.GetElementsByTagName($childName, $ovfNamespace))) {
            [void]$property.RemoveChild($child)
        }
    }
    [void](Add-TextElement -Document $Document -Parent $property -LocalName 'Label' -Value $Label)
    [void](Add-TextElement -Document $Document -Parent $property -LocalName 'Description' -Value $Description)
}

<#
.SYNOPSIS
Inject Atlaso product properties and normalize OVF metadata.

.PARAMETER OvfPath
OVF descriptor path to modify.
#>
<#
.SYNOPSIS
Add Atlaso Ovf Properties.
.PARAMETER OvfPath
Ovf Path value.
#>
function Add-AtlasoOvfProperties {
    param([string]$OvfPath)

    [xml]$document = Get-Content -LiteralPath $OvfPath -Raw
    $document.PreserveWhitespace = $false
    if (-not $document.DocumentElement.HasAttribute('xmlns:vmw')) {
        $document.DocumentElement.SetAttribute('xmlns:vmw', $vmwNamespace)
    }
    if (-not $document.DocumentElement.HasAttribute('xmlns:rasd')) {
        $document.DocumentElement.SetAttribute('xmlns:rasd', $rasdNamespace)
    }

    $manager = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $manager.AddNamespace('ovf', $ovfNamespace)
    $virtualSystem = $document.SelectSingleNode('//ovf:VirtualSystem', $manager)
    if (-not $virtualSystem) {
        throw "OVF descriptor does not contain an ovf:VirtualSystem: $OvfPath"
    }

    $productSection = $document.SelectSingleNode('//ovf:VirtualSystem/ovf:ProductSection[@ovf:class="atlaso"]', $manager)
    if (-not $productSection) {
        $productSection = $document.CreateElement('ovf', 'ProductSection', $ovfNamespace)
        Set-OvfAttribute -Document $document -Element $productSection -Name 'class' -Value 'atlaso'
        [void](Add-TextElement -Document $document -Parent $productSection -LocalName 'Info' -Value 'Atlaso deployment properties')
        [void](Add-TextElement -Document $document -Parent $productSection -LocalName 'Product' -Value 'Atlaso Photon Appliance')
        $hardwareSection = $document.SelectSingleNode('//ovf:VirtualSystem/ovf:VirtualHardwareSection', $manager)
        if ($hardwareSection) {
            [void]$virtualSystem.InsertBefore($productSection, $hardwareSection)
        }
        else {
            [void]$virtualSystem.AppendChild($productSection)
        }
    }

    $hardware = $document.SelectSingleNode('//ovf:VirtualSystem/ovf:VirtualHardwareSection', $manager)
    if ($hardware) {
        Set-OvfAttribute -Document $document -Element $hardware -Name 'transport' -Value 'com.vmware.guestInfo'
        Ensure-AtlasoOvfEmptyDataDisks -Document $document -HardwareSection $hardware -NamespaceManager $manager
        Set-AtlasoOvfHardware -Document $document -HardwareSection $hardware -NamespaceManager $manager
        Ensure-AtlasoOvfNetworks -Document $document -VirtualSystem $virtualSystem -HardwareSection $hardware -NamespaceManager $manager
    }

    foreach ($category in @($productSection.GetElementsByTagName('Category', $ovfNamespace))) {
        [void]$productSection.RemoveChild($category)
    }

    Add-AtlasoOvfCategory -Document $document -ProductSection $productSection -Name 'Management network'
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'cidr' -Label 'Management IPv4 CIDR' -Description 'Static IPv4 address and prefix for eth0, for example 192.168.10.10/24. Leave blank to use DHCPv4.' -Required $false
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'gateway' -Label 'Management IPv4 gateway' -Description 'Required when a static IPv4 CIDR is supplied. Leave blank with DHCPv4.' -Required $false
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'ipv6_enabled' -Label 'Enable management IPv6' -Description 'Enables IPv6 on eth0. Blank IPv6 addressing then uses router advertisements and SLAAC.' -Required $false -Boolean $true -DefaultValue 'false'
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'ipv6_cidr' -Label 'Management IPv6 CIDR' -Description 'Optional static IPv6 address and prefix. Leave blank while IPv6 is enabled to use RA/SLAAC.' -Required $false
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'ipv6_gateway' -Label 'Management IPv6 gateway' -Description 'Optional with a static IPv6 CIDR. Use an on-link global address or a link-local address; leave blank when no IPv6 default route is required.' -Required $false
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'dns_servers' -Label 'DNS servers' -Description 'Optional resolver IPs separated by commas, spaces, or new lines. Blank DHCP deployments keep lease-provided DNS.' -Required $false

    Add-AtlasoOvfCategory -Document $document -ProductSection $productSection -Name 'Appliance identity'
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'fqdn' -Label 'Appliance FQDN' -Description 'Fully qualified appliance name applied to Photon OS and Atlaso desired state.' -Required $true

    Add-AtlasoOvfCategory -Document $document -ProductSection $productSection -Name 'Initial credentials'
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'admin_password' -Label 'Atlaso admin password' -Description 'Required initial Atlaso web admin password; minimum 12 characters. The value is consumed on first boot and not logged.' -Required $true -Password $true -MinLength 12
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'root_password' -Label 'Photon root password' -Description 'Required Photon root console password; minimum 12 characters. Root SSH remains disabled by default.' -Required $true -Password $true -MinLength 12
    Set-AtlasoOvfProperty -Document $document -ProductSection $productSection -Key 'root_ssh_enabled' -Label 'Enable Photon root SSH' -Description 'Allows root password SSH on first boot using the supplied Photon root password. Leave disabled for console-only root recovery.' -Required $false -Boolean $true -DefaultValue 'false'

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $writer = [System.Xml.XmlWriter]::Create($OvfPath, $settings)
    try {
        $document.Save($writer)
    }
    finally {
        $writer.Close()
    }
}

<#
.SYNOPSIS
Rewrite the manifest for all OVF package files.

.PARAMETER OvfDirectory
Directory containing the OVF package files.
#>
<#
.SYNOPSIS
Update Ovf Manifest.
.PARAMETER OvfDirectory
Ovf Directory value.
#>
function Update-OvfManifest {
    param([string]$OvfDirectory)

    $ovf = Get-ChildItem -LiteralPath $OvfDirectory -Filter '*.ovf' -File | Select-Object -First 1
    if (-not $ovf) {
        throw "No .ovf descriptor found in $OvfDirectory"
    }
    $manifest = Join-Path $OvfDirectory "$([System.IO.Path]::GetFileNameWithoutExtension($ovf.Name)).mf"
    $files = Get-ChildItem -LiteralPath $OvfDirectory -File |
    Where-Object { $_.Extension -notin @('.mf', '.ova') } |
    Sort-Object Name
    $lines = foreach ($file in $files) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "SHA256($($file.Name))= $hash"
    }
    [System.IO.File]::WriteAllLines($manifest, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    return $manifest
}

<#
.SYNOPSIS
Create an OVA archive from an exported OVF directory.

.PARAMETER OvfDirectory
Directory containing OVF package files.
.PARAMETER OvaPath
Destination OVA output path.
.PARAMETER ResolvedTarPath
Path to the tar executable.
#>
<#
.SYNOPSIS
Create Ova Archive.
.PARAMETER OvfDirectory
Ovf Directory value.
.PARAMETER OvaPath
Ova Path value.
.PARAMETER ResolvedTarPath
Resolved Tar Path value.
#>
function New-OvaArchive {
    param(
        [string]$OvfDirectory,
        [string]$OvaPath,
        [string]$ResolvedTarPath
    )

    if (Test-Path -LiteralPath $OvaPath -PathType Leaf) {
        Remove-Item -LiteralPath $OvaPath -Force
    }
    $ovf = Get-ChildItem -LiteralPath $OvfDirectory -Filter '*.ovf' -File | Select-Object -First 1
    $manifest = Get-ChildItem -LiteralPath $OvfDirectory -Filter '*.mf' -File | Select-Object -First 1
    if (-not $ovf -or -not $manifest) {
        throw "Cannot package OVA because OVF or manifest is missing in $OvfDirectory"
    }
    $otherFiles = Get-ChildItem -LiteralPath $OvfDirectory -File |
    Where-Object { $_.Name -notin @($ovf.Name, $manifest.Name) -and $_.Extension -ne '.ova' } |
    Sort-Object Name |
    ForEach-Object { $_.Name }
    $arguments = @('-cf', $OvaPath, '-C', $OvfDirectory, $ovf.Name, $manifest.Name) + $otherFiles
    & $ResolvedTarPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "tar failed while creating OVA with exit code $LASTEXITCODE."
    }
}

<#
.SYNOPSIS
Resolve the OVF descriptor path from an export directory.

.PARAMETER OutputDirectory
Directory where ovftool wrote output files.
#>
<#
.SYNOPSIS
Return Ovf Descriptor Path.
.PARAMETER OutputDirectory
Output Directory value.
#>
function Get-OvfDescriptorPath {
    param([string]$OutputDirectory)

    $ovfFiles = @(Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.ovf' -File)
    if ($ovfFiles.Count -eq 0) {
        $ovfFiles = @(Get-ChildItem -LiteralPath $OutputDirectory -Filter '*.ovf' -File -Recurse)
    }
    if ($ovfFiles.Count -eq 0) {
        throw "ovftool did not produce an OVF descriptor under $OutputDirectory"
    }
    if ($ovfFiles.Count -gt 1) {
        $paths = ($ovfFiles | ForEach-Object { $_.FullName }) -join ', '
        throw "ovftool produced multiple OVF descriptors under $OutputDirectory`: $paths"
    }
    return $ovfFiles[0].FullName
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$resolvedSourceVmx = (Resolve-Path -LiteralPath $SourceVmxPath).Path
$buildProvenance = Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx
$callerSpecifiedOutputDirectory = $PSBoundParameters.ContainsKey('OutputDirectory')
$outputPlan = Resolve-AtlasoOvfOutputPlan `
    -RepoRoot $repoRoot `
    -OutputDirectory $OutputDirectory `
    -Name $Name `
    -CallerSpecifiedOutputDirectory:$callerSpecifiedOutputDirectory
$resolvedOutputDirectory = $outputPlan.OutputDirectory
$resolvedOvfTool = Resolve-OvfToolPath -Path $OvfToolPath
$resolvedTar = if ($NoOva) { '' } else { Resolve-TarPath -Path $TarPath }

Clear-AtlasoOvfOutputDirectory -OutputPlan $outputPlan -Force:$Force
New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null

& $resolvedOvfTool --acceptAllEulas $resolvedSourceVmx $resolvedOutputDirectory
if ($LASTEXITCODE -ne 0) {
    throw "ovftool failed with exit code $LASTEXITCODE."
}

$ovfPath = Get-OvfDescriptorPath -OutputDirectory $resolvedOutputDirectory
$ovfPackageDirectory = Split-Path -Parent $ovfPath
Add-AtlasoOvfProperties -OvfPath $ovfPath
Assert-AtlasoOvfDiskTopology -OvfPath $ovfPath
$provenancePath = Write-AtlasoOvaProvenance `
    -RepoRoot $repoRoot `
    -OvfPath $ovfPath `
    -SourceCommit ([string]$buildProvenance.source_commit)
$manifestPath = Update-OvfManifest -OvfDirectory $ovfPackageDirectory

$ovaPath = ''
if (-not $NoOva) {
    $ovaPath = Join-Path (Split-Path -Parent $resolvedOutputDirectory) "$Name.ova"
    New-OvaArchive -OvfDirectory $ovfPackageDirectory -OvaPath $ovaPath -ResolvedTarPath $resolvedTar
    Assert-AtlasoCanonicalOva -RepoRoot $repoRoot -OvaPath $ovaPath
}

foreach ($asset in @(Get-ChildItem -LiteralPath $ovfPackageDirectory -File | Sort-Object Name)) {
    Write-Host "Atlaso OVF asset: $($asset.Name) ($($asset.Length) bytes)"
}
if ($ovaPath) {
    $ovaAsset = Get-Item -LiteralPath $ovaPath
    Write-Host "Atlaso OVA archive size: $($ovaAsset.Length) bytes"
}

Write-Host "Atlaso OVF export root: $resolvedOutputDirectory"
Write-Host "Atlaso OVF folder: $ovfPackageDirectory"
Write-Host "Atlaso OVF descriptor: $ovfPath"
Write-Host "Atlaso OVA provenance: $provenancePath"
Write-Host "Atlaso OVF manifest: $manifestPath"
if ($ovaPath) {
    Write-Host "Atlaso OVA archive: $ovaPath"
}
