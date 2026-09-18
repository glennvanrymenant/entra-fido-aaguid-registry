# Entra FIDO AAGUID Registry

A machine-readable registry generated from Microsoft's public Microsoft Entra documentation page:

https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor

The updater reads the Markdown source used by Microsoft Learn:

https://github.com/MicrosoftDocs/entra-docs/blob/main/docs/identity/authentication/concept-fido2-hardware-vendor.md

## Dataset

`data/entra-fido-aaguids.json`

The dataset contains:

- Microsoft Entra attestation-eligible FIDO2 authenticator models
- AAGUID
- Bio / USB / NFC / BLE capabilities
- Current active/inactive state
- FirstSeen date
- RemovedOn date when a previously listed AAGUID disappears
- Microsoft MDS version referenced by the source document
- Microsoft document date

## Updating

The GitHub Action runs every Monday and can also be started manually from the Actions tab.

The workflow only commits when the generated dataset actually changes.

## Querying from PowerShell

Replace `YOUR-GITHUB-USERNAME` in `examples/Get-EntraFidoAuthenticator.ps1`, dot-source the function, then run:

```powershell
. ./examples/Get-EntraFidoAuthenticator.ps1

Get-EntraFidoAuthenticator

Get-EntraFidoAuthenticator -Aaguid '50a45b0c-80e7-f944-bf29-f552bfa2e048'
```

## Attribution

Source content is derived from Microsoft Entra documentation in the
`MicrosoftDocs/entra-docs` repository.

Microsoft documentation content in that repository is licensed under the
Creative Commons Attribution 4.0 International license.
