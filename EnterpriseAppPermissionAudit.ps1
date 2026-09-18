#requires -Version 7.2

<#
.SYNOPSIS
    Audits Microsoft Entra enterprise applications for privileged consent,
    unrestricted user access, application permissions, assignments, ownership,
    and recent sign-in activity.

.DESCRIPTION
    Produces an HTML risk report and supporting CSV files. The audit separates:
      * Delegated consent granted to all users (AllPrincipals)
      * Delegated consent granted to individual users (Principal)
      * Application permissions used without a signed-in user
      * User/group assignments that are relevant when assignment is required

    The script is read-only. It does not change consent, assignments, or apps.

.PARAMETER OutputPath
    Directory where the report and CSV files will be written.

.PARAMETER SignInLookbackDays
    Number of days requested from Entra sign-in logs. Results remain limited by
    the tenant's configured log-retention period.

.PARAMETER SkipSignInLogs
    Skips interactive, non-interactive, and service-principal sign-in queries.

.PARAMETER IncludeLowRisk
    Includes applications whose detected permissions score as Low risk.

.EXAMPLE
    .\EnterpriseAppPermissionAudit.ps1

.EXAMPLE
    .\EnterpriseAppPermissionAudit.ps1 -SignInLookbackDays 30 -IncludeLowRisk

.EXAMPLE
    .\EnterpriseAppPermissionAudit.ps1 -ResumeFromCheckpoint "C:\Reports\EnterpriseAppAudit-Recovery.clixml"

.NOTES
    Required Microsoft Graph delegated scopes:
      Application.Read.All
      Directory.Read.All
      DelegatedPermissionGrant.Read.All
      AuditLog.Read.All          (unless -SkipSignInLogs is used)

    Only Microsoft.Graph.Authentication is required.

    A collection checkpoint is automatically saved before report generation.
    Use -ResumeFromCheckpoint to regenerate reports without querying Graph again.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PWD "EnterpriseAppPermissionAudit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"),

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$SignInLookbackDays = 30,

    [Parameter()]
    [switch]$SkipSignInLogs,

    [Parameter()]
    [switch]$IncludeLowRisk,

    [Parameter()]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ResumeFromCheckpoint,

    [Parameter()]
    [string]$CheckpointPath
)

$ErrorActionPreference = 'Stop'

function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning')][string]$Level = 'Info'
    )

    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        default   { 'Cyan' }
    }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $color
}

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Invoke-GraphPagedRequest {
    param([Parameter(Mandatory)][string]$Uri)

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri

    while ($next) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($null -ne $response.value) {
            foreach ($item in $response.value) { $items.Add($item) }
        }
        else {
            $items.Add($response)
        }
        $next = $response.'@odata.nextLink'
    }

    return @($items)
}

function Get-PermissionRisk {
    param([Parameter(Mandatory)][string]$Permission)

    $criticalPatterns = @(
        '^Directory\.AccessAsUser\.All$',
        '^Directory\.ReadWrite\.All$',
        '^RoleManagement\.ReadWrite\.',
        '^RoleAssignmentSchedule\.ReadWrite\.',
        '^RoleEligibilitySchedule\.ReadWrite\.',
        '^AppRoleAssignment\.ReadWrite\.All$',
        '^DelegatedPermissionGrant\.ReadWrite\.All$',
        '^Application\.ReadWrite\.All$',
        '^Policy\.ReadWrite\.ConditionalAccess$',
        '^UserAuthenticationMethod\.ReadWrite\.All$',
        '^DeviceManagementManagedDevices\.PrivilegedOperations\.All$',
        '^User\.ManageIdentities\.All$'
    )

    $highPatterns = @(
        'ReadWrite',
        'FullControl',
        '\.Manage(\.|$)',
        '^Mail\.Send',
        '^Files\.Read\.All$',
        '^Sites\.Read\.All$',
        '^AuditLog\.Read\.All$',
        '^SecurityEvents\.Read\.All$',
        '^SecurityIncident\.Read\.All$',
        '^Reports\.Read\.All$',
        '^DeviceManagement.*\.Read\.All$'
    )

    foreach ($pattern in $criticalPatterns) {
        if ($Permission -match $pattern) {
            return [pscustomobject]@{ Level = 'Critical'; Score = 50 }
        }
    }
    foreach ($pattern in $highPatterns) {
        if ($Permission -match $pattern) {
            return [pscustomobject]@{ Level = 'High'; Score = 25 }
        }
    }
    if ($Permission -match '\.All$') {
        return [pscustomobject]@{ Level = 'Medium'; Score = 10 }
    }
    return [pscustomobject]@{ Level = 'Low'; Score = 0 }
}

function Get-OverallRisk {
    param(
        [Parameter(Mandatory)][object[]]$Permissions,
        [Parameter(Mandatory)][bool]$AssignmentRequired,
        [Parameter(Mandatory)][int]$OwnerCount,
        [Parameter(Mandatory)][bool]$VerifiedPublisher
    )

    $score = 0
    $reasons = [System.Collections.Generic.List[string]]::new()

    $critical = @($Permissions | Where-Object Risk -eq 'Critical')
    $high = @($Permissions | Where-Object Risk -eq 'High')
    $appOnly = @($Permissions | Where-Object PermissionType -eq 'Application')
    $tenantWide = @($Permissions | Where-Object ConsentType -eq 'AllPrincipals')
    $tenantWidePrivileged = @($tenantWide | Where-Object Risk -in @('Critical', 'High'))

    if ($critical.Count -gt 0) {
        $score += 45
        $reasons.Add("$($critical.Count) critical permission(s)")
    }
    elseif ($high.Count -gt 0) {
        $score += 25
        $reasons.Add("$($high.Count) high-risk permission(s)")
    }

    if ($appOnly.Count -gt 0) {
        $score += 20
        $reasons.Add("$($appOnly.Count) app-only permission(s)")
    }

    if ($tenantWidePrivileged.Count -gt 0) {
        $score += 20
        $reasons.Add('privileged tenant-wide delegated consent')
    }

    if (-not $AssignmentRequired -and $tenantWide.Count -gt 0) {
        $score += 15
        $reasons.Add('assignment not required')
    }

    if ($OwnerCount -eq 0) {
        $score += 5
        $reasons.Add('no owner recorded')
    }

    if (-not $VerifiedPublisher) {
        $score += 5
        $reasons.Add('publisher not verified')
    }

    $level = if ($score -ge 70) {
        'Critical'
    }
    elseif ($score -ge 45) {
        'High'
    }
    elseif ($score -ge 20) {
        'Medium'
    }
    else {
        'Low'
    }

    [pscustomobject]@{
        Score   = $score
        Level   = $level
        Reasons = $reasons -join '; '
    }
}

function Get-SuggestedAction {
    param(
        [Parameter(Mandatory)][object[]]$Permissions,
        [Parameter(Mandatory)][bool]$AssignmentRequired,
        [Parameter(Mandatory)][int]$OwnerCount,
        [AllowNull()][Nullable[datetime]]$LastSignIn
    )

    $actions = [System.Collections.Generic.List[string]]::new()
    $tenantWidePrivileged = @($Permissions | Where-Object {
        $_.ConsentType -eq 'AllPrincipals' -and $_.Risk -in @('Critical', 'High')
    })
    $appOnlyPrivileged = @($Permissions | Where-Object {
        $_.PermissionType -eq 'Application' -and $_.Risk -in @('Critical', 'High')
    })

    if ($tenantWidePrivileged.Count -gt 0 -and -not $AssignmentRequired) {
        $actions.Add('Require assignment and assign only approved users/groups')
    }
    if ($tenantWidePrivileged.Count -gt 0) {
        $actions.Add('Reduce or remove tenant-wide delegated consent')
    }
    if ($appOnlyPrivileged.Count -gt 0) {
        $actions.Add('Validate app-only permissions, credentials, and workload owner')
    }
    if ($OwnerCount -eq 0) {
        $actions.Add('Assign accountable owner')
    }
    if ($null -eq $LastSignIn) {
        $actions.Add('No successful use found; validate and consider removal')
    }
    if ($actions.Count -eq 0) {
        $actions.Add('Document business justification and retain')
    }

    return $actions -join '; '
}

function Get-SignInEvents {
    param(
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][datetime]$StartDate
    )

    $start = $StartDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $select = 'createdDateTime,userId,userDisplayName,userPrincipalName,appId,appDisplayName,ipAddress,isInteractive,signInEventTypes,status,servicePrincipalId'
    $events = [System.Collections.Generic.List[object]]::new()

    foreach ($eventType in @('interactiveUser', 'nonInteractiveUser', 'servicePrincipal')) {
        $filter = "createdDateTime ge $start and appId eq '$AppId' and signInEventTypes/any(t:t eq '$eventType')"
        $encodedFilter = [uri]::EscapeDataString($filter)
        $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$encodedFilter&`$select=$select"

        foreach ($event in @(Invoke-GraphPagedRequest -Uri $uri)) {
            $events.Add($event)
        }
    }

    return @($events)
}

if ($ResumeFromCheckpoint) {
    Write-Status "Loading checkpoint: $ResumeFromCheckpoint"
    $recovery = Import-Clixml -LiteralPath $ResumeFromCheckpoint

    $requiredProperties = @(
        'Context', 'ServicePrincipals', 'PermissionRows', 'OwnersBySp',
        'AssignmentsBySp', 'SignInsBySp', 'AssignmentRows', 'SignInRows',
        'CandidateIds'
    )
    $missingProperties = @($requiredProperties | Where-Object {
        $_ -notin @($recovery.PSObject.Properties.Name)
    })
    if ($missingProperties.Count -gt 0) {
        throw "Checkpoint is missing required data: $($missingProperties -join ', ')"
    }

    $context = $recovery.Context
    $servicePrincipals = @($recovery.ServicePrincipals)
    $permissionRows = @($recovery.PermissionRows)
    $ownersBySp = $recovery.OwnersBySp
    $assignmentsBySp = $recovery.AssignmentsBySp
    $signInsBySp = $recovery.SignInsBySp
    $assignmentRows = @($recovery.AssignmentRows)
    $signInRows = @($recovery.SignInRows)
    $candidateIds = @($recovery.CandidateIds)

    $spById = @{}
    foreach ($sp in $servicePrincipals) {
        $spById[[string]$sp.id] = $sp
    }

    if ('SignInLookbackDays' -in @($recovery.PSObject.Properties.Name) -and $recovery.SignInLookbackDays) {
        $SignInLookbackDays = [int]$recovery.SignInLookbackDays
    }
    if ('SkipSignInLogs' -in @($recovery.PSObject.Properties.Name)) {
        $SkipSignInLogs = [bool]$recovery.SkipSignInLogs
    }

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Status "Checkpoint loaded: $($candidateIds.Count) applications, $($permissionRows.Count) permissions, $($signInRows.Count) sign-ins." 'Success'
}
else {
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}

Import-Module Microsoft.Graph.Authentication

$scopes = @(
    'Application.Read.All'
    'Directory.Read.All'
    'DelegatedPermissionGrant.Read.All'
)
if (-not $SkipSignInLogs) { $scopes += 'AuditLog.Read.All' }

Write-Status 'Connecting to Microsoft Graph...'
Connect-MgGraph -Scopes $scopes -NoWelcome

$context = Get-MgContext
if (-not $context) { throw 'Microsoft Graph connection was not established.' }

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

Write-Status 'Reading enterprise applications and API definitions...'
$spSelect = 'id,appId,displayName,accountEnabled,appRoleAssignmentRequired,servicePrincipalType,signInAudience,publisherName,verifiedPublisher,createdDateTime,tags,appRoles'
$servicePrincipals = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$spSelect&`$top=999"
$spById = @{}
foreach ($sp in $servicePrincipals) { $spById[$sp.id] = $sp }

Write-Status 'Reading delegated permission grants...'
$delegatedGrants = Invoke-GraphPagedRequest -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'

$permissionRows = [System.Collections.Generic.List[object]]::new()

foreach ($grant in $delegatedGrants) {
    $client = $spById[$grant.clientId]
    $resource = $spById[$grant.resourceId]
    if (-not $client) { continue }

    foreach ($scope in @($grant.scope -split '\s+' | Where-Object { $_ })) {
        $risk = Get-PermissionRisk -Permission $scope
        $permissionRows.Add([pscustomobject]@{
            ApplicationName     = $client.displayName
            ApplicationId       = $client.appId
            ServicePrincipalId  = $client.id
            ResourceName        = if ($resource) { $resource.displayName } else { $grant.resourceId }
            Permission          = $scope
            PermissionType      = 'Delegated'
            ConsentType         = $grant.consentType
            ConsentedFor        = if ($grant.consentType -eq 'AllPrincipals') { 'Entire tenant' } else { $grant.principalId }
            GrantOrAssignmentId = $grant.id
            Risk                = $risk.Level
            RiskScore           = $risk.Score
        })
    }
}

Write-Status 'Discovering application permissions across resource APIs...'
$resourceApis = @($servicePrincipals | Where-Object { @($_.appRoles).Count -gt 0 })
$resourceIndex = 0

foreach ($resource in $resourceApis) {
    $resourceIndex++
    if (($resourceIndex % 25) -eq 0) {
        Write-Status "Checked $resourceIndex of $($resourceApis.Count) resource APIs..."
    }

    try {
        $assignments = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($resource.id)/appRoleAssignedTo?`$top=999"
    }
    catch {
        Write-Warning "Could not read app-role assignments for '$($resource.displayName)': $($_.Exception.Message)"
        continue
    }

    $roleById = @{}
    foreach ($role in @($resource.appRoles)) { $roleById[[string]$role.id] = $role.value }

    foreach ($assignment in @($assignments | Where-Object principalType -eq 'ServicePrincipal')) {
        $client = $spById[$assignment.principalId]
        if (-not $client) { continue }
        $permission = $roleById[[string]$assignment.appRoleId]
        if (-not $permission) { $permission = "Unknown app role: $($assignment.appRoleId)" }
        $risk = Get-PermissionRisk -Permission $permission

        $permissionRows.Add([pscustomobject]@{
            ApplicationName     = $client.displayName
            ApplicationId       = $client.appId
            ServicePrincipalId  = $client.id
            ResourceName        = $resource.displayName
            Permission          = $permission
            PermissionType      = 'Application'
            ConsentType         = 'AdminConsent'
            ConsentedFor        = 'Application identity'
            GrantOrAssignmentId = $assignment.id
            Risk                = $risk.Level
            RiskScore           = $risk.Score
        })
    }
}

$candidateIds = @($permissionRows.ServicePrincipalId | Sort-Object -Unique)
Write-Status "Found $($candidateIds.Count) applications with consented permissions. Collecting ownership and assignments..."

$ownersBySp = @{}
$assignmentsBySp = @{}
$signInsBySp = @{}
$assignmentRows = [System.Collections.Generic.List[object]]::new()
$signInRows = [System.Collections.Generic.List[object]]::new()
$startDate = (Get-Date).ToUniversalTime().AddDays(-$SignInLookbackDays)
$candidateNumber = 0

foreach ($spId in $candidateIds) {
    $candidateNumber++
    $sp = $spById[$spId]
    Write-Status "Enriching $candidateNumber of $($candidateIds.Count): $($sp.displayName)"

    try {
        $owners = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/owners?`$select=id,displayName,userPrincipalName"
    }
    catch {
        Write-Warning "Could not read owners for '$($sp.displayName)': $($_.Exception.Message)"
        $owners = @()
    }
    $ownersBySp[$spId] = @($owners)

    try {
        $assignments = Invoke-GraphPagedRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo?`$select=id,principalId,principalDisplayName,principalType,appRoleId,createdDateTime&`$top=999"
    }
    catch {
        Write-Warning "Could not read assignments for '$($sp.displayName)': $($_.Exception.Message)"
        $assignments = @()
    }
    $assignmentsBySp[$spId] = @($assignments)

    foreach ($assignment in $assignments) {
        $assignmentRows.Add([pscustomobject]@{
            ApplicationName    = $sp.displayName
            ApplicationId      = $sp.appId
            ServicePrincipalId = $sp.id
            PrincipalName      = $assignment.principalDisplayName
            PrincipalId        = $assignment.principalId
            PrincipalType      = $assignment.principalType
            AssignmentId       = $assignment.id
            CreatedDateTime    = $assignment.createdDateTime
        })
    }

    if (-not $SkipSignInLogs) {
        try {
            $events = Get-SignInEvents -AppId $sp.appId -StartDate $startDate
        }
        catch {
            Write-Warning "Could not read sign-ins for '$($sp.displayName)': $($_.Exception.Message)"
            $events = @()
        }
        $successfulEvents = @($events | Where-Object { $_.status.errorCode -eq 0 })
        $signInsBySp[$spId] = $successfulEvents

        foreach ($event in $successfulEvents) {
            $eventType = if (@($event.signInEventTypes).Count -gt 0) {
                $event.signInEventTypes -join ','
            }
            elseif ($event.isInteractive) {
                'interactiveUser'
            }
            else {
                'unknown'
            }

            $signInRows.Add([pscustomobject]@{
                ApplicationName    = $sp.displayName
                ApplicationId      = $sp.appId
                ServicePrincipalId = $sp.id
                CreatedDateTime    = $event.createdDateTime
                EventType          = $eventType
                Interactive        = $event.isInteractive
                UserDisplayName    = $event.userDisplayName
                UserPrincipalName  = $event.userPrincipalName
                UserId             = $event.userId
                IPAddress          = $event.ipAddress
            })
        }
    }
}



    $effectiveCheckpointPath = if ([string]::IsNullOrWhiteSpace($CheckpointPath)) {
        Join-Path $OutputPath 'EnterpriseAppAudit-Checkpoint.clixml'
    }
    else {
        $CheckpointPath
    }

    $checkpointParent = Split-Path -Parent $effectiveCheckpointPath
    if ($checkpointParent) {
        New-Item -ItemType Directory -Path $checkpointParent -Force | Out-Null
    }

    Write-Status "Saving collection checkpoint: $effectiveCheckpointPath"
    [pscustomobject]@{
        Context               = $context
        ServicePrincipals     = @($servicePrincipals)
        ServicePrincipalsById = $spById
        DelegatedGrants       = @($delegatedGrants)
        PermissionRows        = @($permissionRows)
        OwnersBySp            = $ownersBySp
        AssignmentsBySp       = $assignmentsBySp
        SignInsBySp           = $signInsBySp
        AssignmentRows        = @($assignmentRows)
        SignInRows            = @($signInRows)
        CandidateIds          = @($candidateIds)
        SignInLookbackDays    = $SignInLookbackDays
        SkipSignInLogs        = [bool]$SkipSignInLogs
        IncludeLowRisk        = [bool]$IncludeLowRisk
        CreatedDateTime       = Get-Date
    } | Export-Clixml -LiteralPath $effectiveCheckpointPath -Depth 10
    Write-Status 'Collection checkpoint saved.' 'Success'
}

Write-Status 'Calculating risk and recommended actions...'
$summaryRows = [System.Collections.Generic.List[object]]::new()

foreach ($spId in $candidateIds) {
    $sp = $spById[$spId]
    $permissions = @($permissionRows | Where-Object ServicePrincipalId -eq $spId)
    $owners = @($ownersBySp[$spId])
    $assignments = @($assignmentsBySp[$spId])
    $events = @($signInsBySp[$spId])
    $verifiedPublisher = -not [string]::IsNullOrWhiteSpace([string]$sp.verifiedPublisher.displayName)
    $assignmentRequired = [bool]$sp.appRoleAssignmentRequired
    $risk = Get-OverallRisk -Permissions $permissions -AssignmentRequired $assignmentRequired -OwnerCount $owners.Count -VerifiedPublisher $verifiedPublisher

    $lastSignIn = $null
    if ($events.Count -gt 0) {
        $lastSignIn = [datetime](($events.createdDateTime | Sort-Object -Descending)[0])
    }

    $uniqueUsers = @($events | Where-Object userId | Select-Object -ExpandProperty userId -Unique).Count
    $interactive = @($events | Where-Object { $_.isInteractive -eq $true }).Count
    $nonInteractive = @($events | Where-Object { $_.signInEventTypes -contains 'nonInteractiveUser' }).Count
    $servicePrincipalSignIns = @($events | Where-Object { $_.signInEventTypes -contains 'servicePrincipal' }).Count
    $action = Get-SuggestedAction -Permissions $permissions -AssignmentRequired $assignmentRequired -OwnerCount $owners.Count -LastSignIn $lastSignIn

    $summaryRows.Add([pscustomobject]@{
        Risk                  = $risk.Level
        RiskScore             = $risk.Score
        ApplicationName       = $sp.displayName
        ApplicationId         = $sp.appId
        ServicePrincipalId    = $sp.id
        Enabled               = $sp.accountEnabled
        AssignmentRequired    = $assignmentRequired
        Publisher             = $sp.publisherName
        VerifiedPublisher     = if ($verifiedPublisher) { $sp.verifiedPublisher.displayName } else { '' }
        OwnerCount             = $owners.Count
        Owners                 = (@($owners | ForEach-Object { if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName } }) -join '; ')
        AssignedPrincipalCount = $assignments.Count
        DelegatedPermissionCount = @($permissions | Where-Object PermissionType -eq 'Delegated').Count
        ApplicationPermissionCount = @($permissions | Where-Object PermissionType -eq 'Application').Count
        TenantWideConsent     = (@($permissions | Where-Object ConsentType -eq 'AllPrincipals').Count -gt 0)
        CriticalPermissions   = (@($permissions | Where-Object Risk -eq 'Critical' | Select-Object -ExpandProperty Permission -Unique) -join '; ')
        HighRiskPermissions   = (@($permissions | Where-Object Risk -eq 'High' | Select-Object -ExpandProperty Permission -Unique) -join '; ')
        LastSuccessfulSignIn  = $lastSignIn
        UniqueUsers           = $uniqueUsers
        InteractiveSignIns    = $interactive
        NonInteractiveSignIns = $nonInteractive
        ServicePrincipalSignIns = $servicePrincipalSignIns
        RiskReasons           = $risk.Reasons
        SuggestedAction       = $action
    })
}

$summaryRows = @($summaryRows | Sort-Object @{ Expression = 'RiskScore'; Descending = $true }, ApplicationName)
if (-not $IncludeLowRisk) {
    $reportRows = @($summaryRows | Where-Object Risk -ne 'Low')
}
else {
    $reportRows = $summaryRows
}

$summaryCsv = Join-Path $OutputPath 'EnterpriseAppAudit-Summary.csv'
$permissionCsv = Join-Path $OutputPath 'EnterpriseAppAudit-Permissions.csv'
$assignmentCsv = Join-Path $OutputPath 'EnterpriseAppAudit-Assignments.csv'
$signInCsv = Join-Path $OutputPath 'EnterpriseAppAudit-SignIns.csv'
$htmlPath = Join-Path $OutputPath 'EnterpriseAppAudit-Report.html'

$summaryRows | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding utf8BOM
$permissionRows | Sort-Object ApplicationName, PermissionType, ResourceName, Permission | Export-Csv -Path $permissionCsv -NoTypeInformation -Encoding utf8BOM
$assignmentRows | Sort-Object ApplicationName, PrincipalType, PrincipalName | Export-Csv -Path $assignmentCsv -NoTypeInformation -Encoding utf8BOM
$signInRows | Sort-Object ApplicationName, CreatedDateTime -Descending | Export-Csv -Path $signInCsv -NoTypeInformation -Encoding utf8BOM

$tenantName = ConvertTo-HtmlSafe $context.TenantId
$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
$criticalCount = @($reportRows | Where-Object Risk -eq 'Critical').Count
$highCount = @($reportRows | Where-Object Risk -eq 'High').Count
$mediumCount = @($reportRows | Where-Object Risk -eq 'Medium').Count
$unrestrictedCount = @($reportRows | Where-Object { $_.TenantWideConsent -and -not $_.AssignmentRequired }).Count

$detailSections = foreach ($row in $reportRows) {
    $spPermissions = @($permissionRows | Where-Object ServicePrincipalId -eq $row.ServicePrincipalId)
    $spAssignments = @($assignmentRows | Where-Object ServicePrincipalId -eq $row.ServicePrincipalId)
    $spSignIns = @($signInRows | Where-Object ServicePrincipalId -eq $row.ServicePrincipalId)

    $permissionHtml = if ($spPermissions.Count -eq 0) {
        '<p class="muted">No permission records found.</p>'
    }
    else {
        ($spPermissions | Sort-Object @{ Expression = 'RiskScore'; Descending = $true }, PermissionType, Permission | ForEach-Object {
            "<tr><td><span class='badge $($_.Risk.ToLower())'>$($_.Risk)</span></td><td>$(ConvertTo-HtmlSafe $_.PermissionType)</td><td>$(ConvertTo-HtmlSafe $_.ConsentType)</td><td>$(ConvertTo-HtmlSafe $_.ResourceName)</td><td><code>$(ConvertTo-HtmlSafe $_.Permission)</code></td></tr>"
        }) -join "`n"
    }

    $assignmentHtml = if ($spAssignments.Count -eq 0) {
        '<p class="muted">No user, group, or service-principal assignments found.</p>'
    }
    else {
        '<ul>' + (($spAssignments | ForEach-Object {
            "<li>$(ConvertTo-HtmlSafe $_.PrincipalType): $(ConvertTo-HtmlSafe $_.PrincipalName)</li>"
        }) -join '') + '</ul>'
    }

    $usageGroups = @($spSignIns | Where-Object UserPrincipalName | Group-Object UserPrincipalName | ForEach-Object {
        $latest = ($_.Group.CreatedDateTime | Sort-Object -Descending | Select-Object -First 1)
        [pscustomobject]@{ User = $_.Name; Count = $_.Count; Latest = $latest }
    } | Sort-Object Latest -Descending)

    $usageHtml = if ($SkipSignInLogs) {
        '<p class="muted">Sign-in collection was skipped.</p>'
    }
    elseif ($usageGroups.Count -eq 0) {
        "<p class='muted'>No successful user sign-ins found in the requested $SignInLookbackDays-day period.</p>"
    }
    else {
        '<ul>' + (($usageGroups | Select-Object -First 25 | ForEach-Object {
            "<li>$(ConvertTo-HtmlSafe $_.User) — $($_.Count) event(s), last $(ConvertTo-HtmlSafe $_.Latest)</li>"
        }) -join '') + '</ul>'
    }

    @"
<details class="app-card">
  <summary>
    <span class="badge $($row.Risk.ToLower())">$($row.Risk)</span>
    <strong>$(ConvertTo-HtmlSafe $row.ApplicationName)</strong>
    <span class="summary-note">Score $($row.RiskScore) · Assignment required: $($row.AssignmentRequired) · Last use: $(ConvertTo-HtmlSafe $row.LastSuccessfulSignIn)</span>
  </summary>
  <div class="detail-grid">
    <div><span class="label">Application ID</span><code>$(ConvertTo-HtmlSafe $row.ApplicationId)</code></div>
    <div><span class="label">Service principal ID</span><code>$(ConvertTo-HtmlSafe $row.ServicePrincipalId)</code></div>
    <div><span class="label">Publisher</span>$(ConvertTo-HtmlSafe $row.Publisher)</div>
    <div><span class="label">Verified publisher</span>$(ConvertTo-HtmlSafe $row.VerifiedPublisher)</div>
    <div><span class="label">Owners</span>$(ConvertTo-HtmlSafe $row.Owners)</div>
    <div><span class="label">Risk reasons</span>$(ConvertTo-HtmlSafe $row.RiskReasons)</div>
  </div>
  <div class="recommendation"><strong>Recommended action:</strong> $(ConvertTo-HtmlSafe $row.SuggestedAction)</div>
  <h3>Permissions</h3>
  <table><thead><tr><th>Risk</th><th>Type</th><th>Consent</th><th>Resource API</th><th>Permission</th></tr></thead><tbody>$permissionHtml</tbody></table>
  <div class="two-column">
    <section><h3>Assignments</h3>$assignmentHtml</section>
    <section><h3>Successful user activity</h3>$usageHtml</section>
  </div>
</details>
"@
}

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enterprise Application Permission Audit</title>
<style>
:root{--bg:#f4f6fb;--panel:#fff;--ink:#172033;--muted:#637083;--line:#dfe4ed;--purple:#5b3cc4;--critical:#a30d2d;--high:#c45100;--medium:#8a6500;--low:#28704c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Segoe UI,Arial,sans-serif}.wrap{max-width:1500px;margin:auto;padding:32px}.hero{padding:30px;border-radius:18px;color:#fff;background:linear-gradient(135deg,#352080,#6b4bd1);box-shadow:0 14px 34px #2c23602b}.hero h1{margin:0 0 8px;font-size:30px}.hero p{margin:5px 0;color:#eee9ff}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}.metric{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}.metric .number{font-size:30px;font-weight:750}.metric .caption{color:var(--muted);font-size:13px}.app-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:12px 0;overflow:hidden}.app-card summary{cursor:pointer;padding:17px;display:flex;align-items:center;gap:12px}.summary-note{color:var(--muted);font-size:13px;margin-left:auto}.app-card>div,.app-card>h3,.app-card>table{margin-left:18px;margin-right:18px}.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:14px 0;border-top:1px solid var(--line)}.detail-grid>div{overflow-wrap:anywhere}.label{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;margin-bottom:4px}.badge{display:inline-block;border-radius:999px;padding:4px 9px;font-weight:700;font-size:12px;color:#fff}.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}.recommendation{background:#f0edff;border-left:4px solid var(--purple);padding:13px;margin-top:8px!important}table{width:calc(100% - 36px);border-collapse:collapse;margin-bottom:18px}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}th{background:#f7f8fc}.two-column{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding-bottom:18px}.muted{color:var(--muted)}code{font-family:Cascadia Code,Consolas,monospace;font-size:12px;overflow-wrap:anywhere}.footer{color:var(--muted);font-size:12px;margin:28px 0}@media(max-width:850px){.cards,.detail-grid,.two-column{grid-template-columns:1fr}.summary-note{display:none}.wrap{padding:16px}}
.methodology{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:18px 0;padding:0 18px 18px}.methodology summary{cursor:pointer;padding:17px 0;font-weight:700}.methodology h2{font-size:20px;margin:12px 0 6px}.methodology h3{font-size:16px;margin:18px 0 6px}.methodology table{width:100%;margin-left:0;margin-right:0}.callout{background:#f0edff;border-left:4px solid var(--purple);padding:13px}.small{font-size:13px}
</style>
</head>
<body><main class="wrap">
<section class="hero">
  <h1>Enterprise Application Permission Audit</h1>
  <p>Tenant: $tenantName</p>
  <p>Generated: $(ConvertTo-HtmlSafe $generated) · Sign-in lookback: $(if ($SkipSignInLogs) {'Skipped'} else {"$SignInLookbackDays days"})</p>
</section>
<section class="cards">
  <div class="metric"><div class="number">$criticalCount</div><div class="caption">Critical applications</div></div>
  <div class="metric"><div class="number">$highCount</div><div class="caption">High-risk applications</div></div>
  <div class="metric"><div class="number">$mediumCount</div><div class="caption">Medium-risk applications</div></div>
  <div class="metric"><div class="number">$unrestrictedCount</div><div class="caption">Tenant-wide consent without required assignment</div></div>
</section>
<p class="muted">Expand an application for permissions, assignments, recent users, ownership, and remediation guidance. Application permissions are app-only and are not constrained by user assignment.</p>
<details class="methodology" open>
  <summary>How to read this report: definitions, scoring, and governance context</summary>
  <p class="callout"><strong>Client interpretation:</strong> Scores prioritize review. They do not prove that an application is malicious, compromised, or noncompliant. Validate business purpose, actual need, data sensitivity, and compensating controls before changing production access.</p>
  <h2>Risk rating rubric</h2>
  <table>
    <thead><tr><th>Rating</th><th>Score</th><th>Interpretation</th><th>Suggested response</th></tr></thead>
    <tbody>
      <tr><td><span class="badge critical">Critical</span></td><td>70+</td><td>Multiple material indicators, or a critical permission combined with broad access or governance weaknesses.</td><td>Validate immediately with the technical and business owner.</td></tr>
      <tr><td><span class="badge high">High</span></td><td>45–69</td><td>Privileged access or a combination of elevated permission and governance concerns.</td><td>Prioritize for near-term review.</td></tr>
      <tr><td><span class="badge medium">Medium</span></td><td>20–44</td><td>Meaningful exposure exists, with fewer high-impact indicators.</td><td>Review during the normal governance cycle.</td></tr>
      <tr><td><span class="badge low">Low</span></td><td>0–19</td><td>No major heuristic indicators were detected; Low does not mean risk-free.</td><td>Retain in inventory and review periodically.</td></tr>
    </tbody>
  </table>
  <h3>Score contributions</h3>
  <table>
    <thead><tr><th>Detected condition</th><th>Points</th><th>Why it matters</th></tr></thead>
    <tbody>
      <tr><td>One or more Critical permissions</td><td>+45</td><td>Can enable high-impact tenant, identity, role, policy, or application changes.</td></tr>
      <tr><td>Otherwise, one or more High permissions</td><td>+25</td><td>Provides broad read, write, send, full-control, or management capability.</td></tr>
      <tr><td>One or more app-only permissions</td><td>+20</td><td>The workload can act without a signed-in user and is not limited by user assignment.</td></tr>
      <tr><td>Privileged tenant-wide delegated consent</td><td>+20</td><td>A privileged delegated grant is available across the tenant.</td></tr>
      <tr><td>Tenant-wide consent and assignment not required</td><td>+15</td><td>Interactive access is not restricted to an approved user or group list.</td></tr>
      <tr><td>No enterprise-application owner found</td><td>+5</td><td>Accountability and periodic access review may be unclear.</td></tr>
      <tr><td>Publisher not verified</td><td>+5</td><td>One useful publisher trust signal is absent.</td></tr>
    </tbody>
  </table>
  <p class="small muted">Critical and High permission points are mutually exclusive: if a Critical permission is found, the separate High-permission contribution is not also added. The remaining contextual conditions are cumulative.</p>
  <h2>Key definitions</h2>
  <table>
    <thead><tr><th>Term</th><th>Meaning</th></tr></thead>
    <tbody>
      <tr><td>Delegated permission</td><td>Access used on behalf of a signed-in user and normally bounded by both the granted permission and the user's own access.</td></tr>
      <tr><td>Application permission / app-only</td><td>Access used by the workload itself without a signed-in user. User assignment does not restrict this access.</td></tr>
      <tr><td>Tenant-wide consent</td><td>Delegated consent granted for all users (<code>AllPrincipals</code>).</td></tr>
      <tr><td>Assignment required</td><td>Restricts interactive sign-in to explicitly assigned users and groups. It does not constrain app-only permissions.</td></tr>
      <tr><td>Verified publisher</td><td>A Microsoft publisher-verification signal; not proof that an app is safe or appropriately permissioned.</td></tr>
      <tr><td>Last successful sign-in</td><td>The latest matching event found within available Entra retention. No event found does not prove non-use.</td></tr>
    </tbody>
  </table>
  <h2>CIS and least-privilege context</h2>
  <p>This assessment supports review activities associated with CIS Microsoft 365 guidance and CIS access-control principles by surfacing broad consent, privileged API permissions, unrestricted interactive access, and missing ownership. It is <strong>CIS-informed, not a CIS compliance scan</strong>; the report score is a local prioritization model, not a CIS score or certification result.</p>
  <p>Potentially excessive permission means the granted capability may be broader than the application's documented need—for example, write instead of read, tenant-wide <code>.All</code> access instead of resource-scoped access, app-only access where delegated access would suffice, or retained access for an obsolete integration. The finding requires owner validation and should not be remediated solely from the score.</p>
</details>
$($detailSections -join "`n")
<div class="footer">This is a read-only point-in-time assessment. Absence of sign-ins means no activity was found within available Entra log retention; it does not prove the application is unused.</div>
</main></body></html>
"@

Set-Content -Path $htmlPath -Value $html -Encoding utf8BOM

Write-Status 'Audit completed successfully.' 'Success'
Write-Host "HTML report : $htmlPath" -ForegroundColor Green
Write-Host "Summary CSV : $summaryCsv" -ForegroundColor Green
Write-Host "Permissions : $permissionCsv" -ForegroundColor Green
Write-Host "Assignments : $assignmentCsv" -ForegroundColor Green
Write-Host "Sign-ins    : $signInCsv" -ForegroundColor Green

[pscustomobject]@{
    HtmlReport     = $htmlPath
    SummaryCsv     = $summaryCsv
    PermissionsCsv = $permissionCsv
    AssignmentsCsv = $assignmentCsv
    SignInsCsv     = $signInCsv
}
