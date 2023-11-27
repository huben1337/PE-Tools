$ErrorActionPreference = "Stop"

    # function to extract resource directory table
function Get-ResourceDirectory {
    param (
        [int]$offset,
        [int]$rsrcSectionOffset
    )
    $numberOfNameEntries = [System.BitConverter]::ToUInt16($peBytes[($offset + 12)..($offset + 13)], 0)
    $numberOfIdEntries = [System.BitConverter]::ToUInt16($peBytes[($offset + 14)..($offset + 15)], 0)

    $resourceTable = @{
        offset = $offset
        characteristics = [System.BitConverter]::ToUInt32($peBytes[($offset)..($offset + 3)], 0)
        timeDateStamp = [System.BitConverter]::ToUInt32($peBytes[($offset + 4)..($offset + 7)], 0)
        majorVersion = [System.BitConverter]::ToUInt16($peBytes[($offset + 8)..($offset + 9)], 0)
        minorVersion = [System.BitConverter]::ToUInt16($peBytes[($offset + 10)..($offset + 11)], 0)
        numberOfNameEntries = $numberOfNameEntries
        numberOfIdEntries = $numberOfIdEntries
    }
    
    if ($numberOfNameEntries -ne 0) {
        $resourceDirectoryNameEntries = @{}
        $nameEntriesOffset = $offset + 16
        for ($i = 0; $i -lt $numberOfNameEntries; $i++) {
            $entryOffset = $nameEntriesOffset + $i * 8
            $highByte = $peBytes[$entryOffset + 7]
            $highBit = $($highByte -ge 128)
            $peBytes[$entryOffset + 7] = 0
            $entryValueOffset = $rsrcSectionOffset + [System.BitConverter]::ToUInt32($peBytes[($entryOffset + 4)..($entryOffset + 7)], 0) # offset to data or subdirectory
            if ($highBit) {
                if (!$resourceDirectoryNameEntries["directoryEntries"]) {
                    $resourceDirectoryNameEntries["directoryEntries"] = [System.Collections.SortedList]::new()
                }
                $resourceDirectoryNameEntries["directoryEntries"]["$i"] = Get-ResourceDirectory -offset $entryValueOffset -rsrcSectionOffset $rsrcSectionOffset
                
            } else {
                if (!$resourceDirectoryNameEntries["dataEntries"]) {
                    $resourceDirectoryNameEntries["dataEntries"] =[System.Collections.SortedList]::new()
                }
                $resourceDataEntry = @{
                    directoryEntryOffset = $entryOffset
                    dataEntryOffset = $entryValueOffset
                    dataRVA = [System.BitConverter]::ToUInt32($peBytes[($entryValueOffset)..($entryValueOffset + 3)], 0)
                    size = [System.BitConverter]::ToUInt32($peBytes[($entryValueOffset + 4)..($entryValueOffset + 7)], 0)
                    codePage = [System.BitConverter]::ToUInt32($peBytes[($entryValueOffset + 8)..($entryValueOffset + 11)], 0)
                }
                $resourceDirectoryNameEntries["dataEntries"]["$i"] = $resourceDataEntry
            }
            $peBytes[$entryOffset + 7] = $highByte
        }
        $resourceTable["nameEntries"] = $resourceDirectoryNameEntries
    }

    if ($numberOfIdEntries -ne 0) {
        $resourceDirectoryIdEntries = @{}
        $idEntriesOffset = $offset + 16 + $numberOfNameEntries * 8
        for ($i = 0; $i -lt $numberOfIdEntries; $i++) {
            $entryOffset = $idEntriesOffset + $i * 8
            $id = [System.BitConverter]::ToUInt32($peBytes[($entryOffset)..($entryOffset + 3)], 0)
            $highByte = $peBytes[$entryOffset + 7]
            $highBit = $($highByte -ge 128)
            $peBytes[$entryOffset + 7] = 0
            $entryValueOffset = $rsrcSectionOffset + [System.BitConverter]::ToUInt32($peBytes[($entryOffset + 4)..($entryOffset + 7)], 0) # offset to data or subdirectory
            if ($highBit) {
                if (!$resourceDirectoryIdEntries["directoryEntries"]) {
                    $resourceDirectoryIdEntries["directoryEntries"] = [System.Collections.SortedList]::new()
                }
                $resourceDirectoryIdEntries["directoryEntries"]["$id"] = Get-ResourceDirectory -offset $entryValueOffset -rsrcSectionOffset $rsrcSectionOffset
                
            } else {
                if (!$resourceDirectoryIdEntries["dataEntries"]) {
                    $resourceDirectoryIdEntries["dataEntries"] = [System.Collections.SortedList]::new()
                }
                $resourceDataEntry = @{
                    directoryEntryOffset = $entryOffset
                    dataEntryOffset = $entryValueOffset
                    dataRVA = [System.BitConverter]::ToUInt32($peBytes[($entryValueOffset)..($entryValueOffset + 3)], 0)
                    size = [System.BitConverter]::ToUInt32($peBytes[($entryValueOffset + 4)..($entryValueOffset + 7)], 0)
                    codePage = [System.BitConverter]::ToUInt32($peBytes[($entryValueOffset + 8)..($entryValueOffset + 11)], 0)
                }
                $resourceDirectoryIdEntries["dataEntries"]["$id"] = $resourceDataEntry
            }
            $peBytes[$entryOffset + 7] = $highByte
        }
        $resourceTable["idEntries"] = $resourceDirectoryIdEntries
    }
    
    return $resourceTable
}

function Get-PEInfo {
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$peBytes
    ) 

    # PE Header
    # find signature 50 45 00 00
    $peSignatureOffset = 0
    for ($i = 0; $i -lt $peBytes.Length; $i++) {
        if ($peBytes[$i] -eq 0x50 -and $peBytes[$i + 1] -eq 0x45 -and $peBytes[$i + 2] -eq 0x00 -and $peBytes[$i + 3] -eq 0x00) {
            $peSignatureOffset = $i
            break
        }
    }

    # COFF File Header
    $coffFileHeaderOffset = $peSignatureOffset + 4
    $sizeOfcoffFileHeader = 20
    $numberOfSections = [System.BitConverter]::ToUInt16($peBytes[($coffFileHeaderOffset + 2)..($coffFileHeaderOffset + 3)], 0)
    $sizeOfOptionalHeader = [System.BitConverter]::ToUInt16($peBytes[($coffFileHeaderOffset + 16)..($coffFileHeaderOffset + 17)], 0)

    # Section Table
    $sectionTableOffset = $coffFileHeaderOffset + $sizeOfcoffFileHeader + $sizeOfOptionalHeader
    # create array of section table entries
    $lastOffset = 0
    $needsSorting = $false
    $sectionTable = [System.Collections.SortedList]::new()
    for ($i = 0; $i -lt $numberOfSections; $i++) {
        $sectionTableEntryOffset = $sectionTableOffset + $i * 40
        $pointerToRawData = [System.BitConverter]::ToUInt32($peBytes[($sectionTableEntryOffset + 20)..($sectionTableEntryOffset + 23)], 0)
        if ($pointerToRawData -lt $lastOffset) {
            $needsSorting = $true
        }
        $lastOffset = $pointerToRawData
        $name = [System.Text.Encoding]::ASCII.GetString($peBytes[($sectionTableEntryOffset)..($sectionTableEntryOffset + 7)]).TrimEnd([char]0)
        $sectionTable[$name] = @{
            offset = $sectionTableEntryOffset
            virtualSize = [System.BitConverter]::ToUInt32($peBytes[($sectionTableEntryOffset + 8)..($sectionTableEntryOffset + 11)], 0)
            virtualAddress = [System.BitConverter]::ToUInt32($peBytes[($sectionTableEntryOffset + 12)..($sectionTableEntryOffset + 15)], 0)
            sizeOfRawData = [System.BitConverter]::ToUInt32($peBytes[($sectionTableEntryOffset + 16)..($sectionTableEntryOffset + 19)], 0)
            pointerToRawData = $pointerToRawData
            pointerToRelocations = [System.BitConverter]::ToUInt32($peBytes[($sectionTableEntryOffset + 24)..($sectionTableEntryOffset + 27)], 0)
            pointerToLinenumbers = [System.BitConverter]::ToUInt32($peBytes[($sectionTableEntryOffset + 28)..($sectionTableEntryOffset + 31)], 0)
            numberOfRelocations = [System.BitConverter]::ToUInt16($peBytes[($sectionTableEntryOffset + 32)..($sectionTableEntryOffset + 33)], 0)
            numberOfLinenumbers = [System.BitConverter]::ToUInt16($peBytes[($sectionTableEntryOffset + 34)..($sectionTableEntryOffset + 35)], 0)
            characteristics = [System.BitConverter]::ToUInt32($peBytes[($sectionTableEntryOffset + 36)..($sectionTableEntryOffset + 40)], 0)
        }
    }

    if ($needsSorting) {
        Write-Host "Sorting section table"
        $sectionTable = $sectionTable.Values | Sort-Object -Property Value.pointerToRawData
    }

    # The .rsrc Section
    $rsrcSectionOffset = $sectionTable[".rsrc"]["pointerToRawData"]

    $resourceDirectory = Get-ResourceDirectory -offset $rsrcSectionOffset -rsrcSectionOffset $rsrcSectionOffset
    return @{
        resourceDirectory = $resourceDirectory
        sectionTable = $sectionTable
    }
}

# function to trsnform resourceTable definition to bytes for PE
# !!! under construction !!! #
function Set-ResourceDirectory {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $resourceDirectory
    )
    [byte[]]$resourceDirectoryB = @()

    [byte[]]$numberOfNameEntriesB = [System.BitConverter]::GetBytes($resourceDirectory.numberOfNameEntries)
    [byte[]]$numberOfIdEntriesB = [System.BitConverter]::GetBytes($resourceDirectory.numberOfIdEntries)
    [byte[]]$characteristicsB = [System.BitConverter]::GetBytes($resourceDirectory.characteristics)
    [byte[]]$timeDateStampB = [System.BitConverter]::GetBytes($resourceDirectory.timeDateStamp)
    [byte[]]$majorVersionB = [System.BitConverter]::GetBytes($resourceDirectory.majorVersion)
    [byte[]]$minorVersionB = [System.BitConverter]::GetBytes($resourceDirectory.minorVersion)

    # write bytes to resourceDirectoryB
    $resourceDirectoryB += $numberOfNameEntriesB
    $resourceDirectoryB += $numberOfIdEntriesB
    $resourceDirectoryB += $characteristicsB
    $resourceDirectoryB += $timeDateStampB
    $resourceDirectoryB += $majorVersionB
    $resourceDirectoryB += $minorVersionB

    # add all subirectories
    foreach ($directoryEntry in $resourceDirectory.nameEntries.directoryEntries) {
        $directoryEntryyB = Set-ResourceDirectory -resourceDirectory $directoryEntry
        # set high bit of $directoryEntryB to 1
        $directoryEntryyB[7] = $directoryEntryB[7] -bor 0x80
        $resourceDirectoryB += $directoryEntryyB
    }
    foreach ($directoryEntry in $resourceDirectory.idEntries.directoryEntries) {
        $directoryEntryyB = Set-ResourceDirectory -resourceDirectory $directoryEntry
        # set high bit of $directoryEntryB to 1
        $directoryEntryyB[7] = $directoryEntryB[7] -bor 0x80
        $resourceDirectoryB += $directoryEntryyB
    }

    # add all data entries
    foreach ($dataEntry in $resourceDirectory.idEntries.dataEntries) {
        
    }
    

    return $resourceDirectoryB

}
Export-ModuleMember "Get-PEInfo"

