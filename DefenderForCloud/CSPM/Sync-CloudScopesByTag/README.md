# Tag-driven Defender XDR Cloud Scopes Sync Script

[Sync-CloudScopesByTag.ps1](./Sync-CloudScopesByTag.ps1) keeps Microsoft Defender for Cloud **cloud scopes**
(Microsoft Graph **beta** `security.zone` / `security.environment` resources) continuously
in sync with Azure subscription tags.

For every tag you configure, the script:
1. Finds every Azure subscription that carries the exact `TagKey=TagValue` pair.
2. Finds the matching cloud scope by display name, or creates it if it doesn't exist yet.
3. Reconciles the cloud scope's subscriptions: **attaches** subscriptions that now match the
   tag, and **detaches** subscriptions that no longer match (tag removed or value changed).

Because step 3 runs every time, the script is idempotent and safe to run repeatedly/unattended
(for example on a schedule) to keep cloud scopes continuously up to date. Only environments of
kind `azureSubscription` are managed — any AWS/GCP/DevOps/registry environments manually attached
to the same cloud scope are left untouched.

> [!NOTE]
> This uses the Microsoft Graph **beta** endpoint (`/beta/security/zones`), which is subject to
> change. See [zone](https://learn.microsoft.com/en-us/graph/api/resources/security-zone?view=graph-rest-beta)
> and [environment](https://learn.microsoft.com/en-us/graph/api/resources/security-environment?view=graph-rest-beta)
> in the Microsoft Graph documentation.

## Prerequisites

### PowerShell modules

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Permissions

| Area | Requirement |
| --- | --- |
| Microsoft Graph | `Zone.ReadWrite.All` application permission (admin consent required) **or** a signed-in delegated user assigned the **Security Administrator** Microsoft Entra role |
| Azure RBAC | **Reader** (or higher) on every subscription/management group whose tags should be evaluated, so `Get-TaggedSubscription` can see them |

If you'll run the script with a managed identity (see [Authentication modes](#authentication-modes)),
grant that identity the Graph application permission above (with admin consent) and the Azure Reader
role instead of a user.

## Configuration file

The tag → cloud scope mappings live in a JSON file — [CloudScopesConfig.json](./CloudScopesConfig.json)
is provided as a starting example. Each entry supports:

| Property | Required | Description |
| --- | --- | --- |
| `TagKey` | Yes | Name of the Azure subscription tag to match. |
| `TagValue` | Yes | Exact value the tag must have (case-insensitive). |
| `CloudScopeDisplayName` | Yes | Display name of the Defender for Cloud cloud scope to create/update. |
| `CloudScopeDescription` | No | Description to set (and keep updated) on the cloud scope. |

```json
[
  {
    "TagKey": "Environment",
    "TagValue": "Production",
    "CloudScopeDisplayName": "CloudScope-Production",
    "CloudScopeDescription": "Azure subscriptions tagged Environment=Production"
  },
  {
    "TagKey": "Department",
    "TagValue": "Finance",
    "CloudScopeDisplayName": "CloudScope-Finance",
    "CloudScopeDescription": "Azure subscriptions tagged Department=Finance"
  }
]
```

Each mapping is independent: a given tag/value pair maps to exactly one cloud scope. Add as many
entries as you need — one per cloud scope you want kept in sync.

### Matching rules

- A subscription matches when it has a tag whose key equals `TagKey` and whose value equals `TagValue`.
  Both comparisons are **case-insensitive**.
- Subscriptions with **no tags** (or without the configured tag) never match, so they are never attached.
  If one is already in a cloud scope it is detached on the next run.
- If a mapping matches **zero** subscriptions, the cloud scope is still created/kept and any
  `azureSubscription` environments already in it are detached.
- Required properties (`TagKey`, `TagValue`, `CloudScopeDisplayName`) are validated before anything runs;
  a missing one aborts the script.

## Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-ConfigPath` | `CloudScopesConfig.json` next to the script | Path to the JSON mapping file. |
| `-AuthMode` | `Interactive` | `Interactive` or `ManagedIdentity` (see below). |
| `-TenantId` | *(none)* | Optional Microsoft Entra tenant ID to target. |
| `-LogPath` | `Logs\CloudScopes_<timestamp>.log` next to the script | Log file path (console output is mirrored here). |
| `-WhatIf` / `-Confirm` | *(standard PowerShell)* | Preview changes without creating/attaching/detaching anything. |

## Authentication modes

- **`Interactive`** (default) — uses `Connect-AzAccount` and `Connect-MgGraph` interactive/device-code
  sign-in. Use this for manual, ad-hoc runs from your own workstation.
- **`ManagedIdentity`** — uses `Connect-AzAccount -Identity` and `Connect-MgGraph -Identity`. Use this
  when the script runs unattended from an Azure context that has a managed identity assigned (Azure
  Automation Account, Azure VM, Function App, etc.).

## Running the script

### First run — dry run (recommended)

Preview what would be created/attached/detached without making any changes:

```powershell
.\Sync-CloudScopesByTag.ps1 -WhatIf
```

### Interactive run

```powershell
.\Sync-CloudScopesByTag.ps1
```

Uses the default `CloudScopesConfig.json` next to the script and prompts you to sign in to both
Azure and Microsoft Graph.

### Run with a custom config file and tenant

```powershell
.\Sync-CloudScopesByTag.ps1 -ConfigPath C:\Scripts\CloudScopesConfig.json -TenantId 00000000-0000-0000-0000-000000000000
```

### Unattended run with a managed identity

```powershell
.\Sync-CloudScopesByTag.ps1 -ConfigPath C:\Scripts\CloudScopesConfig.json -AuthMode ManagedIdentity
```

### Output

- Console output (also written to the log file) shows each step: connecting, subscriptions found,
  cloud scopes created/found, subscriptions attached/detached.
- A summary table is printed at the end:

  ```text
  CloudScopeDisplayName  Matched Added Removed Unchanged Errors
  ---------------------  ------- ----- ------- --------- ------
  CloudScope-Production        3     1       0         2      0
  CloudScope-Finance           2     0       1         1      0
  ```
- The script exits with code `1` if any mapping failed (so a scheduler can flag the run as failed),
  or `0` on full success.

### Limits

- A cloud scope can hold up to **1,000 environments** (Graph limit)
- Only subscriptions visible to the signed-in identity (Azure Reader or higher) are evaluated.


## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `Configuration file not found` | `-ConfigPath` doesn't point to a valid JSON file. |
| `Configuration entry is missing required property` | A mapping in the config file is missing `TagKey`, `TagValue`, or `CloudScopeDisplayName`. |
| `403 Forbidden` from Graph calls | The signed-in user/identity doesn't have `Zone.ReadWrite.All` (or Security Administrator role). |
| A subscription you expect isn't matched | The subscription's tag key/value doesn't match the config (both are compared case-insensitively), the subscription has no tags, or the signed-in identity lacks Azure Reader access to it. |
| `Failed to detach subscription ...` | None of the Graph detach ID forms succeeded or the subscription was still present afterwards; the log includes the last Graph response. Remove it manually in the Defender for Cloud portal and report the response if it persists (beta API). |
| Graph requests retrying/slow | The script automatically retries on HTTP `429`/`503`/`504`, waiting for the `Retry-After` value Graph returns (or exponential backoff if absent, capped at 120 seconds); check the log for repeated throttling if this happens often. |

Check the log file (default: `Logs\CloudScopes_<timestamp>.log` next to the script, or the path you
passed via `-LogPath`) for full details of every run.
