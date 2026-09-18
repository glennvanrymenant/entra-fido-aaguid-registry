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

$RowPattern = '(?m)^(?<Description>[^|\r\n]+?)\s*\|\s*(?<Aaguid>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*\|\s*(?<Bio>✅|❌)\s*\|\s*(?<Usb>✅|❌)\s*\|\s*(?<Nfc>✅|❌)\s*\|\s*(?<Ble>✅|❌)\s*$'
$Matches = [regex]::Matches($Section, $RowPattern)

if ($Matches.Count -lt 10) {
    throw "Only $($Matches.Count) AAGUID rows were parsed. The Microsoft page format may have changed, so the dataset was not updated."
}

$ScrapedEntries = foreach ($Match in $Matches) {
    [PSCustomObject][ordered]@{
        Description = $Match.Groups['Description'].Value.Trim()
        Aaguid      = $Match.Groups['Aaguid'].Value.ToLowerInvariant()
        Bio         = $Match.Groups['Bio'].Value -eq '✅'
        Usb         = $Match.Groups['Usb'].Value -eq '✅'
        Nfc         = $Match.Groups['Nfc'].Value -eq '✅'
        Ble         = $Match.Groups['Ble'].Value -eq '✅'
    }
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
