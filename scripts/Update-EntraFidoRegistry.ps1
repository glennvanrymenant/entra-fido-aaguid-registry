[CmdletBinding()]
param (
    [Parameter()]
    [string] $SourceUri = 'https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/identity/authentication/concept-fido2-hardware-vendor.md',

    [Parameter()]
    [string] $OutputPath = (Join-Path $PSScriptRoot '..' 'data' 'entra-fido-aaguids.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LearnUrl = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor'
$Today = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
$Now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

Write-Host "Downloading Microsoft Entra documentation source..."
$Response = Invoke-WebRequest -Uri $SourceUri -Method Get
$Content = $Response.Content

$SectionHeading = '## FIDO2 security keys eligible for attestation with Microsoft Entra ID'
$SectionStart = $Content.IndexOf($SectionHeading, [StringComparison]::Ordinal)

if ($SectionStart -lt 0) {
    throw "Could not find the expected FIDO2 attestation section in the Microsoft document."
}

$Section = $Content.Substring($SectionStart)

$NextHeadingMatch = [regex]::Match(
    $Section.Substring($SectionHeading.Length),
    '(?m)^##\s+'
)

if ($NextHeadingMatch.Success) {
    $Section = $Section.Substring(
        0,
        $SectionHeading.Length + $NextHeadingMatch.Index
    )
}

$MdsVersionMatch = [regex]::Match(
    $Section,
    'MDS version (?<Version>\d+)',
    [Text.RegularExpressions.RegexOptions]::IgnoreCase
)

if (-not $MdsVersionMatch.Success) {
    throw "Could not determine the MDS version from the Microsoft document."
}

$MdsVersion = [int] $MdsVersionMatch.Groups['Version'].Value

$DocumentDateMatch = [regex]::Match(
    $Content,
    '(?m)^ms\.date:\s*(?<Date>[^\r\n]+)$'
)

$DocumentDate = if ($DocumentDateMatch.Success) {
    $DocumentDateMatch.Groups['Date'].Value.Trim()
}
else {
    $null
}

function ConvertTo-CapabilityBoolean {
    param (
        [Parameter(Mandatory)]
        [string] $Value
    )

    $Value = $Value.Trim()

    if ($Value.Contains([char] 0x2705)) {
        return $true
    }

    if ($Value.Contains([char] 0x274C)) {
        return $false
    }

    switch ($Value.ToLowerInvariant()) {
        'true'  { return $true }
        'yes'   { return $true }
        '1'     { return $true }
        'false' { return $false }
        'no'    { return $false }
        '0'     { return $false }
        default { throw "Unexpected capability value '$Value' in Microsoft table." }
    }
}

$AaguidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

$ScrapedEntries = foreach ($Line in ($Section -split '\r?\n')) {
    if ($Line -notmatch '\|') {
        continue
    }

    $Columns = @(
        $Line -split '\|' |
            ForEach-Object { $_.Trim() }
    )

    if ($Columns.Count -lt 6) {
        continue
    }

    if ($Columns[1] -notmatch $AaguidPattern) {
        continue
    }

    [PSCustomObject][ordered]@{
        Description = $Columns[0]
        Aaguid      = $Columns[1].ToLowerInvariant()
        Bio         = ConvertTo-CapabilityBoolean -Value $Columns[2]
        Usb         = ConvertTo-CapabilityBoolean -Value $Columns[3]
        Nfc         = ConvertTo-CapabilityBoolean -Value $Columns[4]
        Ble         = ConvertTo-CapabilityBoolean -Value $Columns[5]
    }
}

$ScrapedEntries = @($ScrapedEntries)

if ($ScrapedEntries.Count -lt 10) {
    throw "Only $($ScrapedEntries.Count) AAGUID rows were parsed. The Microsoft page format may have changed, so the dataset was not updated."
}

$DuplicateAaguids = $ScrapedEntries |
    Group-Object Aaguid |
    Where-Object Count -gt 1

if ($DuplicateAaguids) {
    $Values = ($DuplicateAaguids.Name -join ', ')
    throw "Duplicate AAGUIDs found in the parsed Microsoft table: $Values"
}

$OutputDirectory = Split-Path -Path $OutputPath -Parent
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$Existing = $null
$ExistingByAaguid = @{}

if (Test-Path $OutputPath) {
    try {
        $Existing = Get-Content -Path $OutputPath -Raw | ConvertFrom-Json

        foreach ($Entry in $Existing.Entries) {
            $ExistingByAaguid[$Entry.Aaguid.ToLowerInvariant()] = $Entry
        }
    }
    catch {
        throw "Existing dataset could not be parsed: $($_.Exception.Message)"
    }
}

$CurrentAaguids = @{}
$MergedEntries = @()

foreach ($Entry in $ScrapedEntries) {
    $Aaguid = $Entry.Aaguid
    $CurrentAaguids[$Aaguid] = $true

    $FirstSeen = if ($ExistingByAaguid.ContainsKey($Aaguid)) {
        $ExistingByAaguid[$Aaguid].FirstSeen
    }
    else {
        $Today
    }

    $MergedEntries += [PSCustomObject][ordered]@{
        Description = $Entry.Description
        Aaguid      = $Aaguid
        Bio         = $Entry.Bio
        Usb         = $Entry.Usb
        Nfc         = $Entry.Nfc
        Ble         = $Entry.Ble
        Active      = $true
        FirstSeen   = $FirstSeen
        RemovedOn   = $null
    }
}

if ($Existing) {
    foreach ($OldEntry in $Existing.Entries) {
        $Aaguid = $OldEntry.Aaguid.ToLowerInvariant()

        if ($CurrentAaguids.ContainsKey($Aaguid)) {
            continue
        }

        $RemovedOn = if ($OldEntry.Active -eq $false -and $OldEntry.RemovedOn) {
            $OldEntry.RemovedOn
        }
        else {
            $Today
        }

        $MergedEntries += [PSCustomObject][ordered]@{
            Description = $OldEntry.Description
            Aaguid      = $Aaguid
            Bio         = [bool] $OldEntry.Bio
            Usb         = [bool] $OldEntry.Usb
            Nfc         = [bool] $OldEntry.Nfc
            Ble         = [bool] $OldEntry.Ble
            Active      = $false
            FirstSeen   = $OldEntry.FirstSeen
            RemovedOn   = $RemovedOn
        }
    }
}

$MergedEntries = @(
    $MergedEntries |
        Sort-Object @{ Expression = 'Active'; Descending = $true }, Description, Aaguid
)

$Comparable = [ordered]@{
    MdsVersion        = $MdsVersion
    MicrosoftDocDate  = $DocumentDate
    Entries           = $MergedEntries
}

$ComparableJson = $Comparable | ConvertTo-Json -Depth 5 -Compress

$ExistingComparableJson = $null
if ($Existing) {
    $ExistingComparable = [ordered]@{
        MdsVersion        = $Existing.MdsVersion
        MicrosoftDocDate  = $Existing.MicrosoftDocDate
        Entries           = $Existing.Entries
    }

    $ExistingComparableJson = $ExistingComparable |
        ConvertTo-Json -Depth 5 -Compress
}

$GeneratedAtUtc = if ($Existing -and $ComparableJson -eq $ExistingComparableJson) {
    $Existing.GeneratedAtUtc
}
else {
    $Now
}

$Dataset = [PSCustomObject][ordered]@{
    SchemaVersion     = 1
    GeneratedAtUtc    = $GeneratedAtUtc
    Source            = $LearnUrl
    SourceMarkdown    = $SourceUri
    MicrosoftDocDate  = $DocumentDate
    MdsVersion        = $MdsVersion
    ActiveEntryCount  = @($MergedEntries | Where-Object Active).Count
    TotalTrackedCount = $MergedEntries.Count
    Entries           = $MergedEntries
}

$Json = $Dataset | ConvertTo-Json -Depth 5

Set-Content -Path $OutputPath -Value $Json -Encoding utf8

Write-Host "Dataset written to $OutputPath"
Write-Host "MDS version: $MdsVersion"
Write-Host "Active AAGUIDs: $($Dataset.ActiveEntryCount)"
Write-Host "Total tracked AAGUIDs: $($Dataset.TotalTrackedCount)"
