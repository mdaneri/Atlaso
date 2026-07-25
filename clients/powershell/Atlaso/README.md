# Atlaso PowerShell Module Roadmap

This folder is the scaffold for the future `Atlaso` PowerShell module.

Goals:

- Connect to a Atlaso appliance with bearer-token authentication.
- Generate friendly cmdlets from the OpenAPI contract where practical.
- Add hand-written wrappers for common workflows.
- Keep TLS validation enabled by default.
- Add `-SkipCertificateCheck` only for explicit lab testing.

Planned authentication commands:

```powershell
Connect-Atlaso
Disconnect-Atlaso
Get-AtlasoSession
New-AtlasoApiToken
Get-AtlasoApiToken
Revoke-AtlasoApiToken
```

Planned route and WAN commands:

```powershell
Get-AtlasoRoute
New-AtlasoRoute
Set-AtlasoRoute
Remove-AtlasoRoute
Get-AtlasoWanPolicy
New-AtlasoWanPolicy
Apply-AtlasoWanPolicy
Clear-AtlasoWanPolicy
Get-AtlasoWanStatus
```
