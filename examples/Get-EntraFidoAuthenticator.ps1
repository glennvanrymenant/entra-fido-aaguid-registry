function Get-EntraFidoAuthenticator {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $Aaguid,

        [Parameter()]
        [string] $DatasetUri = 'https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/entra-fido-aaguid-registry/main/data/entra-fido-aaguids.json',

        [Parameter()]
        [switch] $IncludeInactive
    )

    try {
        $Dataset = Invoke-RestMethod -Uri $DatasetUri -Method Get -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve Entra FIDO AAGUID dataset: $($_.Exception.Message)"
    }

    $Entries = $Dataset.Entries

    if (-not $IncludeInactive) {
        $Entries = $Entries | Where-Object Active
    }

    if ($Aaguid) {
        $NormalizedAaguid = $Aaguid.Trim().ToLowerInvariant()

        $Entries = $Entries | Where-Object {
            $_.Aaguid -eq $NormalizedAaguid
        }
    }

    return $Entries
}
