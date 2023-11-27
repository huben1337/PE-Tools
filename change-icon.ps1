param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile,
    [Parameter(Mandatory=$true)]
    [string]$OutputFile,
    [Parameter(Mandatory=$true)]
    [string]$IconFile
) 

Import-Module .\Get-IconFromPng.psm1
Import-Module .\Get-PEInfo.psm1

$peBytes = [System.IO.File]::ReadAllBytes((Get-Item $InputFile))
$peInfo = Get-PEInfo -peBytes $peBytes

$rsrcSectionTableEntry = $peInfo.sectionTable[".rsrc"]
$rsrcRVAoffset = $rsrcSectionTableEntry.pointerToRawData - $rsrcSectionTableEntry.virtualAddress
$groupIconDirOffset = $peInfo.resourceDirectory.idEntries.directoryEntries["14"].idEntries.directoryEntries["1"].idEntries.dataEntries["1033"].dataRVA + $rsrcRVAoffset
$groupIconDir = @{
    idReserved = [System.BitConverter]::ToUInt16($peBytes[($groupIconDirOffset)..($groupIconDirOffset + 1)], 0)
    idType = [System.BitConverter]::ToUInt16($peBytes[($groupIconDirOffset + 2)..($groupIconDirOffset + 3)], 0)
    idCount = [System.BitConverter]::ToUInt16($peBytes[($groupIconDirOffset + 4)..($groupIconDirOffset + 5)], 0)
    idEntries = [System.Collections.SortedList]::new()
}
for ($i = 0; $i -lt $groupIconDir.idCount; $i++) {
    $entryOffset = $groupIconDirOffset + 6 + $i * 14
    $id = [System.BitConverter]::ToUInt16($peBytes[($entryOffset + 12)..($entryOffset + 13)], 0)
    $groupIconDir.idEntries["$id"] = @{
        offset = [int]$entryOffset
        width = $peBytes[$entryOffset]
        height = $peBytes[$entryOffset + 1]
        colorCount = $peBytes[$entryOffset + 2]
        reserved = $peBytes[$entryOffset + 3]
        planes = [System.BitConverter]::ToUInt16($peBytes[($entryOffset + 4)..($entryOffset + 5)], 0)
        bitCount = [System.BitConverter]::ToUInt16($peBytes[($entryOffset + 6)..($entryOffset + 7)], 0)
        bytesInRes = [System.BitConverter]::ToUInt32($peBytes[($entryOffset + 8)..($entryOffset + 11)], 0)
    }
}
$iconEntries = $peInfo.resourceDirectory.idEntries.directoryEntries["3"].idEntries.directoryEntries
$icons = [System.Collections.SortedList]::new()
# loop through each icon and add to icons
$needsSorting = $false
$lastOffset = 0
$oldIconsDataSize = 0
$newIconsDataSize = 0
foreach ($iconEntryId in $groupIconDir.idEntries.Keys) {
    $dataOffset = [int]($iconEntries[$iconEntryId].idEntries.dataEntries["1033"].dataRVA + $rsrcRVAoffset)
    if ($dataOffset -lt $lastOffset) {
        $needsSorting = $true
    }
    $lastOffset = $dataOffset
    #$iconHeight = $groupIconDir.idEntries[$iconEntryId].height
    $iconWidth = $groupIconDir.idEntries[$iconEntryId].width 
    if ($iconWidth -eq 0) {
        $iconWidth = 256
    }
    $newIcon = [byte[]](Get-IconFromPng -InputFile $IconFile -size $iconWidth)
    $oldIconsDataSize += $groupIconDir.idEntries[$iconEntryId].bytesInRes
    $newIconsDataSize += $newIcon.Length
    $icons[$iconEntryId] = @{
        dataOffset = [int]($iconEntries[$iconEntryId].idEntries.dataEntries["1033"].dataRVA + $rsrcRVAoffset)
        dataSize = [int]$iconEntries[$iconEntryId].idEntries.dataEntries["1033"].size
        dataEntryOffset = [int]($iconEntries[$iconEntryId].idEntries.dataEntries["1033"].dataEntryOffset)
        groupIconDirOffset = $groupIconDir.idEntries[$iconEntryId].offset
        newIcon = $newIcon
        width = $iconWidth
    }
}
# cretae new pe bytes
$iconDataSizeDelta = $newIconsDataSize - $oldIconsDataSize
$newSize = [math]::Ceiling(($peBytes.Length + $iconDataSizeDelta) / 16) * 16
$totalSizeDelta = $newSize - $peBytes.Length
$newPeBytes = [byte[]]::new($newSize)
$iconDataOffsetStart = $icons.GetByIndex(0).dataOffset
$currentResDataOffset = $iconDataOffsetStart
# copy over old bytes up to icon data
[System.Buffer]::BlockCopy($peBytes, 0, $newPeBytes, 0, $currentResDataOffset)
if ($needsSorting) {
    Write-Host "Sorting icons"
    $icons = ($icons.GetEnumerator() | Sort-Object -Property Value.dataOffset)
}

# patch in icons
foreach ($icon in $icons.Values) {
    # write new icon bytes
    [System.Buffer]::BlockCopy($icon.newIcon, 0, $newPeBytes, $currentResDataOffset, $icon.newIcon.Length)

    # write new res data offset in res dir
    $newDataOffsetB = [System.BitConverter]::GetBytes([uint32]($currentResDataOffset - $rsrcRVAoffset))
    [System.Buffer]::BlockCopy($newDataOffsetB, 0, $newPeBytes, $icon.dataEntryOffset, 4)

    # write new group icon dir entry bytesInRes
    $newDataSizeB = [System.BitConverter]::GetBytes([uint32]$icon.newIcon.Length)
    [System.Buffer]::BlockCopy($newDataSizeB, 0, $newPeBytes, $icon.dataEntryOffset + 4, 4)
    [System.Buffer]::BlockCopy($newDataSizeB, 0, $peBytes, $icon.groupIconDirOffset + 8, 4)

    $currentResDataOffset += $icon.newIcon.Length
}

$iconDataOffsetEndOld = $iconDataOffsetStart + $oldIconsDataSize
# copy over old bytes after icon data
[System.Buffer]::BlockCopy($peBytes, $iconDataOffsetEndOld, $newPeBytes, $currentResDataOffset, $peBytes.Length - $iconDataOffsetEndOld)

# fix the resource offsets for all resource which have adress above $iconDataOffsetEndOld
function Set-OffsetAdress {
    param(
        [Parameter(Mandatory=$true)]
        $resourceDirectory
    )

    foreach ($directoryEntry in $resourceDirectory.nameEntries.directoryEntries.Values) {
        Set-OffsetAdress -resourceDirectory $directoryEntry
    }
    foreach ($directoryEntry in $resourceDirectory.idEntries.directoryEntries.Values) {
        Set-OffsetAdress -resourceDirectory $directoryEntry
    }
    # add all data entries
    foreach ($dataEntry in $resourceDirectory.idEntries.dataEntries.Values) {
        $dataOffset = ($dataEntry.dataRVA + $rsrcRVAoffset)
        if ($dataOffset -lt $iconDataOffsetEndOld) { continue }
        $newDataOffsetB = [System.BitConverter]::GetBytes([uint32]($dataOffset + $iconDataSizeDelta - $rsrcRVAoffset))
        [System.Buffer]::BlockCopy($newDataOffsetB, 0, $newPeBytes, $dataEntry.dataEntryOffset, 4)
    }
    foreach ($dataEntry in $resourceDirectory.nameEntries.dataEntries.Values) {
        $dataOffset = ($dataEntry.dataRVA + $rsrcRVAoffset)
        $newDataOffsetB = [System.BitConverter]::GetBytes([uint32]($dataOffset + $iconDataSizeDelta - $rsrcRVAoffset))
        [System.Buffer]::BlockCopy($newDataOffsetB, 0, $newPeBytes, $dataEntry.dataEntryOffset, 4)
    }
}

Set-OffsetAdress -resourceDirectory $peInfo.resourceDirectory

#fix section table
$newRsrcRawSize = ($peInfo.sectionTable[".rsrc"].sizeOfRawData + $totalSizeDelta)
$newRsrcRawSizeB = [System.BitConverter]::GetBytes([uint32]$newRsrcRawSize)
[System.Buffer]::BlockCopy($newRsrcRawSizeB, 0, $newPeBytes, $peInfo.sectionTable[".rsrc"].offset + 16, 4)
$newRscVirtualSize = ($peInfo.sectionTable[".rsrc"].virtualSize + $totalSizeDelta)
$newRscVirtualSizeB = [System.BitConverter]::GetBytes([uint32]$newRscVirtualSize)
[System.Buffer]::BlockCopy($newRscVirtualSizeB , 0, $newPeBytes, $peInfo.sectionTable[".rsrc"].offset + 8, 4)


#write to file
[System.IO.File]::WriteAllBytes($OutputFile, $newPeBytes)