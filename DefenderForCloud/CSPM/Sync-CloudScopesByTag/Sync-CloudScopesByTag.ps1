#Requires -Modules Az.Accounts, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Keeps Microsoft Defender for Cloud "cloud scopes" (Microsoft Graph beta security zones) in sync with Azure subscription tags.
.DESCRIPTION
    Reads a JSON configuration file of TagKey/TagValue -> cloud scope mappings, finds every Azure
    subscription carrying the exact TagKey=TagValue pair, and reconciles the matching Defender for Cloud
    cloud scope so that it contains exactly those subscriptions:
      - Creates the cloud scope (security.zone) if it doesn't exist yet.
      - Attaches (security.environment, kind = azureSubscription) subscriptions that now match the tag.
      - Detaches subscriptions that previously matched but no longer carry the tag (or whose value changed).
    The script is idempotent and safe to run repeatedly/unattended (for example from Windows Task Scheduler
    or an Azure Automation runbook) to keep cloud scopes continuously up to date.
    Only environments of kind 'azureSubscription' are managed by this script. Any other environment kinds
    (AWS, GCP, DevOps, container registries, ...) manually attached to the same cloud scope are left untouched.
.PARAMETER ConfigPath
    Path to the JSON configuration file describing the tag -> cloud scope mappings. Defaults to
    'CloudScopesConfig.json' next to this script. Each entry supports:
        TagKey                 (required)  Name of the Azure subscription tag to match.
        TagValue               (required)  Exact value the tag must have (case-insensitive).
        CloudScopeDisplayName  (required)  Display name of the Defender for Cloud cloud scope (security.zone).
        CloudScopeDescription  (optional)  Description to set/update on the cloud scope.
.PARAMETER AuthMode
    How to authenticate to Azure Resource Manager and Microsoft Graph.
        Interactive     - Connect-AzAccount / Connect-MgGraph interactive (or device code) sign-in. Use for manual runs.
        ManagedIdentity - Connect-AzAccount -Identity / Connect-MgGraph -Identity. Use when running unattended from
                          an Azure context (Automation Account, Azure VM, Function App, etc.) that has a managed
                          identity granted the required permissions.
.PARAMETER TenantId
    Optional Microsoft Entra tenant ID to target. Passed through to Connect-AzAccount and Connect-MgGraph.
.PARAMETER LogPath
    Path to a log file that console output is also written to. Defaults to a timestamped file under a 'Logs'
    folder next to this script.
.INPUTS
    None.
.OUTPUTS
    Console/log output and a summary table of created/updated cloud scopes with added/removed subscriptions.
    Sets a non-zero exit code if any mapping entry fails, so scheduled task runners can detect failures.
.NOTES
    Prerequisite modules: Az.Accounts, Microsoft.Graph.Authentication
        Install-Module Az.Accounts -Scope CurrentUser
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

    Prerequisite permissions:
      - Microsoft Graph application permission 'Zone.ReadWrite.All' (admin consent required), or a signed-in
        delegated user assigned the Security Administrator Entra role.
      - Azure RBAC 'Reader' (or higher) on every subscription/management group whose tags should be evaluated,
        so that the subscriptions list call returns them.

    This API targets the Microsoft Graph /beta endpoint (security.zone / security.environment resources), which
    is subject to change: https://learn.microsoft.com/en-us/graph/api/resources/security-zone?view=graph-rest-beta
.ROLE
    Zone.ReadWrite.All (Microsoft Graph Scope) and Reader (Azure RBAC)
.EXAMPLE
    .\Sync-CloudScopesByTag.ps1
    Runs interactively using the default CloudScopesConfig.json next to the script.
.EXAMPLE
    .\Sync-CloudScopesByTag.ps1 -ConfigPath C:\Scripts\CloudScopesConfig.json -AuthMode ManagedIdentity
    Runs unattended (for example from an Azure Automation runbook or an Azure VM) using the VM/Automation
    Account's managed identity, reading mappings from a custom config file path.
.EXAMPLE
    .\Sync-CloudScopesByTag.ps1 -WhatIf
    Shows what cloud scopes would be created and which subscriptions would be added/removed, without making
    any changes.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'CloudScopesConfig.json'),

    [Parameter()]
    [ValidateSet('Interactive', 'ManagedIdentity')]
    [string]$AuthMode = 'Interactive',

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$LogPath = (Join-Path $PSScriptRoot "Logs\CloudScopes_$(Get-Date -Format 'yyyyMMdd_HHmmss').log")
)
# Make the log path available to helper functions without passing it through every call.
$script:LogPath = $LogPath
function Write-CloudScopeLog {
    <#
    .DESCRIPTION
        Writes a timestamped message to the console and appends it to the log file.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message

    switch ($Level) {
        'WARN' { Write-Warning $Message }
        'ERROR' { Write-Error $Message -ErrorAction Continue }
        default { Write-Information -MessageData $line -InformationAction Continue }
    }

    $logFolder = Split-Path -Path $script:LogPath -Parent
    if ($logFolder -and -not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }
    Add-Content -Path $script:LogPath -Value $line
}

function Connect-CloudScopeService {
    <#
    .DESCRIPTION
        Signs in to Azure and Microsoft Graph using the requested authentication mode.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$AuthMode,

        [Parameter()]
        [string]$TenantId
    )

    $azParams = @{}
    $graphParams = @{ NoWelcome = $true }
    if ($TenantId) {
        $azParams['Tenant'] = $TenantId
        $graphParams['TenantId'] = $TenantId
    }

    if ($AuthMode -eq 'ManagedIdentity') {
        Write-CloudScopeLog 'Connecting to Azure using the system-assigned managed identity...'
        Connect-AzAccount -Identity @azParams | Out-Null

        Write-CloudScopeLog 'Connecting to Microsoft Graph using the system-assigned managed identity...'
        Connect-MgGraph -Identity @graphParams | Out-Null
    }
    else {
        Write-CloudScopeLog 'Connecting to Azure interactively...'
        Connect-AzAccount @azParams | Out-Null

        Write-CloudScopeLog 'Connecting to Microsoft Graph interactively (scope: Zone.ReadWrite.All)...'
        Connect-MgGraph -Scopes 'Zone.ReadWrite.All' @graphParams | Out-Null
    }
}

function Invoke-GraphRequestWithRetry {
    <#
    .DESCRIPTION
        Wraps Invoke-MgGraphRequest with retry for throttling (429) and transient (503/504) responses, honouring
        the Retry-After header when present and falling back to exponential backoff otherwise.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Body,

        [Parameter()]
        [int]$MaxAttempts = 5
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{
                Method      = $Method
                Uri         = $Uri
                ErrorAction = 'Stop'
            }
            if ($Body) {
                $params['Body'] = ($Body | ConvertTo-Json -Depth 10)
                $params['ContentType'] = 'application/json'
            }
            return Invoke-MgGraphRequest @params
        }
        catch {
            $statusCode = $null
            if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $isThrottled = $statusCode -in 429, 503, 504
            if ($isThrottled -and $attempt -lt $MaxAttempts) {
                # Prefer the server-provided Retry-After value; fall back to exponential backoff.
                $retryAfter = [Math]::Pow(2, $attempt)
                try {
                    $retryHeader = $_.Exception.Response.Headers.RetryAfter
                    if ($retryHeader -and $retryHeader.Delta) {
                        $retryAfter = [Math]::Ceiling($retryHeader.Delta.TotalSeconds)
                    }
                    elseif ($retryHeader -and $retryHeader.Date) {
                        $retryAfter = [Math]::Ceiling(($retryHeader.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
                    }
                }
                catch {
                    Write-Verbose 'Retry-After header unavailable; using exponential backoff.'
                }
                $retryAfter = [Math]::Min([Math]::Max($retryAfter, 1), 120)

                Write-CloudScopeLog "Graph request throttled (HTTP $statusCode). Retrying in $retryAfter second(s) (attempt $attempt/$MaxAttempts)..." -Level WARN
                Start-Sleep -Seconds $retryAfter
                continue
            }

            throw
        }
    }
}

function Get-GraphCollection {
    <#
    .DESCRIPTION
        Returns every item of a Microsoft Graph collection, following @odata.nextLink across pages.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    while ($nextUri) {
        $page = Invoke-GraphRequestWithRetry -Method GET -Uri $nextUri
        foreach ($item in @($page.value)) {
            $items.Add($item)
        }
        $nextUri = $page.'@odata.nextLink'
    }

    return $items.ToArray()
}

function Get-TaggedSubscription {
    <#
    .DESCRIPTION
        Returns every Azure subscription visible to the signed-in principal, including its tags, using a single
        ARM call instead of per-subscription Get-AzTag lookups.
    #>

    Write-CloudScopeLog 'Retrieving all Azure subscriptions and their tags...'
    $allSubscriptions = [System.Collections.Generic.List[object]]::new()
    $uri = 'https://management.azure.com/subscriptions?api-version=2022-12-01'

    while ($uri) {
        $response = Invoke-AzRestMethod -Method GET -Uri $uri
        if ($response.StatusCode -ge 300) {
            throw "Failed to list Azure subscriptions. HTTP $($response.StatusCode): $($response.Content)"
        }

        $content = $response.Content | ConvertFrom-Json
        foreach ($sub in $content.value) {
            $allSubscriptions.Add($sub)
        }

        $uri = $content.nextLink
    }

    Write-CloudScopeLog "Retrieved $($allSubscriptions.Count) subscription(s)."
    return $allSubscriptions
}

function Get-OrCreateCloudScope {
    <#
    .DESCRIPTION
        Finds a Defender for Cloud cloud scope (security.zone) by display name, creating it if it doesn't exist.
        Returns the cloud scope id.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName,

        [Parameter()]
        [string]$Description
    )

    $escapedName = $DisplayName.Replace("'", "''")
    $listUri = "https://graph.microsoft.com/beta/security/zones?`$filter=displayName eq '$escapedName'"
    $existing = Invoke-GraphRequestWithRetry -Method GET -Uri $listUri

    if ($existing.value.Count -gt 0) {
        $cloudScope = $existing.value[0]
        Write-CloudScopeLog "Cloud scope '$DisplayName' already exists (id: $($cloudScope.id))."

        if ($Description -and $cloudScope.description -ne $Description) {
            if ($PSCmdlet.ShouldProcess($DisplayName, 'Update cloud scope description')) {
                Invoke-GraphRequestWithRetry -Method PATCH -Uri "https://graph.microsoft.com/beta/security/zones/$($cloudScope.id)" -Body @{ description = $Description } | Out-Null
                Write-CloudScopeLog "Updated description for cloud scope '$DisplayName'."
            }
        }

        return $cloudScope.id
    }

    if ($PSCmdlet.ShouldProcess($DisplayName, 'Create cloud scope')) {
        Write-CloudScopeLog "Cloud scope '$DisplayName' not found. Creating it..."
        $body = @{ displayName = $DisplayName }
        if ($Description) {
            $body['description'] = $Description
        }

        $created = Invoke-GraphRequestWithRetry -Method POST -Uri 'https://graph.microsoft.com/beta/security/zones' -Body $body
        Write-CloudScopeLog "Created cloud scope '$DisplayName' (id: $($created.id))."
        return $created.id
    }

    # -WhatIf: no id to return since nothing was created.
    return $null
}

function Sync-CloudScopeEnvironment {
    <#
    .DESCRIPTION
        Reconciles the azureSubscription environments attached to a cloud scope against the desired set of
        subscription IDs: attaches missing ones, detaches ones that no longer belong.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$CloudScopeId,

        [Parameter(Mandatory)]
        [string]$CloudScopeDisplayName,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$DesiredSubscriptionIds
    )

    $result = [pscustomobject]@{
        CloudScopeDisplayName = $CloudScopeDisplayName
        Added                 = [System.Collections.Generic.List[string]]::new()
        Removed               = [System.Collections.Generic.List[string]]::new()
        Unchanged             = 0
        Errors                = [System.Collections.Generic.List[string]]::new()
    }

    try {
        $listUri = "https://graph.microsoft.com/beta/security/zones/$CloudScopeId/environments?`$filter=kind eq 'azureSubscription'"
        $currentIds = @(Get-GraphCollection -Uri $listUri | ForEach-Object { $_.id })
    }
    catch {
        $result.Errors.Add("Failed to list environments for cloud scope '$CloudScopeDisplayName': $($_.Exception.Message)")
        return $result
    }

    $desiredIds = @($DesiredSubscriptionIds | ForEach-Object { "/subscriptions/$_" })

    $toAdd = $desiredIds | Where-Object { $_ -notin $currentIds }
    $toRemove = $currentIds | Where-Object { $_ -notin $desiredIds }
    $result.Unchanged = ($desiredIds | Where-Object { $_ -in $currentIds }).Count

    foreach ($envId in $toAdd) {
        $subId = $envId -replace '^/subscriptions/', ''
        if ($PSCmdlet.ShouldProcess("$CloudScopeDisplayName <- $subId", 'Attach subscription to cloud scope')) {
            try {
                $body = @{ id = $envId; kind = 'azureSubscription' }
                Invoke-GraphRequestWithRetry -Method POST -Uri "https://graph.microsoft.com/beta/security/zones/$CloudScopeId/environments" -Body $body | Out-Null
                Write-CloudScopeLog "Attached subscription '$subId' to cloud scope '$CloudScopeDisplayName'."
                $result.Added.Add($subId)
            }
            catch {
                $result.Errors.Add("Failed to attach subscription '$subId' to '$CloudScopeDisplayName': $($_.Exception.Message)")
                Write-CloudScopeLog "Failed to attach subscription '$subId' to '$CloudScopeDisplayName': $($_.Exception.Message)" -Level ERROR
            }
        }
    }

    foreach ($envId in $toRemove) {
        $subId = $envId -replace '^/subscriptions/', ''
        if ($PSCmdlet.ShouldProcess("$CloudScopeDisplayName -> $subId", 'Detach subscription from cloud scope (tag no longer matches)')) {
            $encoded = [System.Uri]::EscapeDataString($envId)
            $baseUri = "https://graph.microsoft.com/beta/security/zones/$CloudScopeId/environments"

            # The Graph beta route for slash-containing environment IDs is inconsistent, so try each
            # documented/plausible ID form and confirm the removal by re-listing the cloud scope.
            $candidateUris = @(
                "$baseUri/$encoded"
                "$baseUri/$([System.Uri]::EscapeDataString($encoded))"
                "$baseUri('$encoded')"
                "$baseUri/$subId"
            )

            $detached = $false
            $lastError = $null
            foreach ($candidateUri in $candidateUris) {
                try {
                    Invoke-GraphRequestWithRetry -Method DELETE -Uri $candidateUri | Out-Null
                }
                catch {
                    $lastError = $_.Exception.Message
                    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                        $lastError += " Graph response: $($_.ErrorDetails.Message)"
                    }
                }

                try {
                    if ($envId -notin @(Get-GraphCollection -Uri $listUri | ForEach-Object { $_.id })) {
                        $detached = $true
                        break
                    }
                }
                catch {
                    $lastError = "Could not verify detach: $($_.Exception.Message)"
                    break
                }
            }

            if ($detached) {
                Write-CloudScopeLog "Detached subscription '$subId' from cloud scope '$CloudScopeDisplayName' (tag no longer matches)."
                $result.Removed.Add($subId)
            }
            else {
                $result.Errors.Add("Failed to detach subscription '$subId' from '$CloudScopeDisplayName': $lastError")
                Write-CloudScopeLog "Failed to detach subscription '$subId' from '$CloudScopeDisplayName': $lastError" -Level ERROR
            }
        }
    }

    return $result
}

try {
    if (-not (Test-Path $ConfigPath)) {
        throw "Configuration file not found: $ConfigPath"
    }

    $mappings = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    if (-not $mappings -or $mappings.Count -eq 0) {
        throw "No tag -> cloud scope mappings found in '$ConfigPath'."
    }

    foreach ($mapping in $mappings) {
        foreach ($required in 'TagKey', 'TagValue', 'CloudScopeDisplayName') {
            if (-not $mapping.$required) {
                throw "Configuration entry is missing required property '$required': $($mapping | ConvertTo-Json -Compress)"
            }
        }
    }

    Connect-CloudScopeService -AuthMode $AuthMode -TenantId $TenantId

    $subscriptions = Get-TaggedSubscription

    $summary = [System.Collections.Generic.List[object]]::new()
    $hadErrors = $false

    foreach ($mapping in $mappings) {
        Write-CloudScopeLog "Processing mapping: TagKey='$($mapping.TagKey)', TagValue='$($mapping.TagValue)' -> CloudScopeDisplayName='$($mapping.CloudScopeDisplayName)'"

        $matchingSubscriptionIds = @(
            $subscriptions | Where-Object {
                $_.tags -and
                ($_.tags.PSObject.Properties | Where-Object {
                        $_.Name -eq $mapping.TagKey -and $_.Value -eq $mapping.TagValue
                    }).Count -gt 0
            } | ForEach-Object { $_.subscriptionId }
        )

        Write-CloudScopeLog "Found $($matchingSubscriptionIds.Count) subscription(s) matching '$($mapping.TagKey)=$($mapping.TagValue)'."

        $cloudScopeId = Get-OrCreateCloudScope -DisplayName $mapping.CloudScopeDisplayName -Description $mapping.CloudScopeDescription

        if (-not $cloudScopeId) {
            # -WhatIf run against a non-existent cloud scope: nothing more to reconcile.
            $summary.Add([pscustomobject]@{
                    CloudScopeDisplayName = $mapping.CloudScopeDisplayName
                    Matched               = $matchingSubscriptionIds.Count
                    Added                 = 0
                    Removed               = 0
                    Unchanged             = 0
                    Errors                = 0
                })
            continue
        }

        $syncResult = Sync-CloudScopeEnvironment -CloudScopeId $cloudScopeId -CloudScopeDisplayName $mapping.CloudScopeDisplayName -DesiredSubscriptionIds $matchingSubscriptionIds

        if ($syncResult.Errors.Count -gt 0) {
            $hadErrors = $true
        }

        $summary.Add([pscustomobject]@{
                CloudScopeDisplayName = $mapping.CloudScopeDisplayName
                Matched               = $matchingSubscriptionIds.Count
                Added                 = $syncResult.Added.Count
                Removed               = $syncResult.Removed.Count
                Unchanged             = $syncResult.Unchanged
                Errors                = $syncResult.Errors.Count
            })
    }

    Write-CloudScopeLog '----- Summary -----'
    $summary | Format-Table -AutoSize | Out-String | Write-Information -InformationAction Continue

    if ($hadErrors) {
        Write-CloudScopeLog 'Completed with one or more errors. See log for details.' -Level ERROR
        exit 1
    }

    Write-CloudScopeLog 'Completed successfully.'
    exit 0
}
catch {
    Write-CloudScopeLog "Script failed: $($_.Exception.Message)" -Level ERROR
    exit 1
}