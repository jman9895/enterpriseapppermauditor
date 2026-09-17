# Enterprise App Permission Auditor

A read-only PowerShell auditor for Microsoft Entra enterprise applications. It inventories consented Microsoft Graph and other API permissions, assignments, ownership, publisher verification, and recent successful sign-in activity, then produces an interactive HTML risk report and supporting CSV exports.

The script is intended to answer questions such as:

- Which enterprise applications have tenant-wide delegated consent?
- Which applications hold app-only permissions?
- Which apps can be used without an explicit user or group assignment?
- Which applications have privileged permissions but no accountable owner?
- Which users or workloads have recently used an application?
- Which applications deserve immediate review, restricted assignment, reduced consent, or removal?

> [!IMPORTANT]
> This tool provides a point-in-time, heuristic assessment. It does not replace a formal application security review, and it does not make changes to your tenant.

## Features

- Audits delegated OAuth grants, including:
  - Tenant-wide consent (`AllPrincipals`)
  - Individual-user consent (`Principal`)
- Discovers application permissions assigned to service principals
- Separates delegated permissions from app-only permissions
- Reports whether each enterprise application requires assignment
- Enumerates assigned users, groups, and service principals
- Retrieves enterprise application owners
- Identifies verified and unverified publishers
- Reviews successful:
  - Interactive user sign-ins
  - Non-interactive user sign-ins
  - Service-principal sign-ins
- Applies a transparent risk-scoring model
- Provides suggested remediation actions
- Generates a responsive, expandable HTML report
- Exports detailed CSV files for filtering and further analysis
- Uses only the `Microsoft.Graph.Authentication` PowerShell module
- Performs no tenant modifications

## Requirements

- PowerShell 7.2 or later
- A Microsoft Entra account able to consent to or use the required delegated scopes
- Access to Microsoft Graph
- The `Microsoft.Graph.Authentication` module

Install the required module:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

The script deliberately avoids importing the full Microsoft Graph PowerShell SDK. All data collection is performed through `Invoke-MgGraphRequest`.

## Required Microsoft Graph scopes

| Scope | Purpose | Required when |
|---|---|---|
| `Application.Read.All` | Reads enterprise applications, service principals, owners, app roles, and assignments | Always |
| `Directory.Read.All` | Reads related directory objects and assignment information | Always |
| `DelegatedPermissionGrant.Read.All` | Reads delegated OAuth permission grants | Always |
| `AuditLog.Read.All` | Reads interactive, non-interactive, and service-principal sign-in logs | Unless `-SkipSignInLogs` is used |

These are delegated scopes used by the signed-in administrator. The script does not request write permissions.

Depending on tenant consent policy, an administrator may need to approve these scopes the first time the script is run.

## Quick start

Clone the repository:

```powershell
git clone https://github.com/jman9895/enterpriseapppermauditor.git
cd enterpriseapppermauditor
```

Run the audit:

```powershell
.\EnterpriseAppPermissionAudit.ps1
```

A timestamped output directory is created beneath the current working directory.

## Usage examples

Run with the default 30-day sign-in lookback:

```powershell
.\EnterpriseAppPermissionAudit.ps1
```

Request 90 days of sign-in activity:

```powershell
.\EnterpriseAppPermissionAudit.ps1 -SignInLookbackDays 90
```

Include applications assessed as Low risk in the HTML report:

```powershell
.\EnterpriseAppPermissionAudit.ps1 -IncludeLowRisk
```

Write results to a specific directory:

```powershell
.\EnterpriseAppPermissionAudit.ps1 -OutputPath "C:\Reports\EnterpriseApps"
```

Skip sign-in collection and avoid requesting `AuditLog.Read.All`:

```powershell
.\EnterpriseAppPermissionAudit.ps1 -SkipSignInLogs
```

Combine options:

```powershell
.\EnterpriseAppPermissionAudit.ps1 `
    -OutputPath "C:\Reports\EnterpriseApps" `
    -SignInLookbackDays 90 `
    -IncludeLowRisk
```

## Parameters

| Parameter | Type | Default | Description |
|---|---|---:|---|
| `-OutputPath` | String | Timestamped directory in the current path | Directory for the HTML report and CSV exports |
| `-SignInLookbackDays` | Integer | `30` | Requested sign-in lookback, from 1 through 365 days |
| `-SkipSignInLogs` | Switch | Off | Skips interactive, non-interactive, and service-principal sign-in queries |
| `-IncludeLowRisk` | Switch | Off | Includes Low-risk applications in the HTML report |

Low-risk applications are always retained in the summary CSV. The switch only controls whether they appear in the HTML report.

## Output files

The script creates the following files:

| File | Contents |
|---|---|
| `EnterpriseAppAudit-Report.html` | Interactive executive and technical report organized by application |
| `EnterpriseAppAudit-Summary.csv` | One row per application with risk, configuration, ownership, usage, and suggested action |
| `EnterpriseAppAudit-Permissions.csv` | One row per delegated or application permission |
| `EnterpriseAppAudit-Assignments.csv` | User, group, and service-principal assignments to audited applications |
| `EnterpriseAppAudit-SignIns.csv` | Successful sign-in events found during the requested and available retention period |

Open the HTML report in a modern browser. Each application can be expanded to review its permissions, assignments, recent usage, owners, risk reasons, and recommended action.

## How applications are selected

The report focuses on enterprise applications that have at least one discovered consented permission:

- A delegated OAuth permission grant, or
- An application permission represented by an app-role assignment to a service principal

Applications without discovered consented permissions are not included as audit candidates.

## Permission classifications

### Delegated permissions

Delegated permissions are exercised by an application on behalf of a signed-in user. The audit distinguishes:

- `AllPrincipals`: administrator consent covering the entire tenant
- `Principal`: consent associated with a specific user

### Application permissions

Application permissions are exercised by the service principal itself, without a signed-in user. These are reported as:

- Permission type: `Application`
- Consent type: `AdminConsent`
- Consented for: `Application identity`

> [!WARNING]
> Setting **Assignment required?** to **Yes** restricts user sign-in to assigned users and groups. It does not constrain app-only permissions or stop a service principal from authenticating with its own credential or managed identity.

## Risk model

Risk scoring is intentionally understandable and easy to review. Permission names are matched against patterns, and application-level configuration adds contextual risk.

### Permission risk examples

Permissions such as the following are treated as Critical:

- `Directory.ReadWrite.All`
- `RoleManagement.ReadWrite.*`
- `AppRoleAssignment.ReadWrite.All`
- `DelegatedPermissionGrant.ReadWrite.All`
- `Application.ReadWrite.All`
- `Policy.ReadWrite.ConditionalAccess`
- `UserAuthenticationMethod.ReadWrite.All`

High-risk matching includes permissions containing `ReadWrite`, `FullControl`, or management capabilities, plus sensitive permissions such as `Mail.Send`, `AuditLog.Read.All`, and broad security or device-management reads.

Other permissions ending in `.All` are generally classified as Medium. Permissions that do not match a configured pattern are classified as Low.

### Application-level scoring

| Condition | Score contribution |
|---|---:|
| One or more Critical permissions | 45 |
| Otherwise, one or more High permissions | 25 |
| One or more app-only permissions | 20 |
| Privileged tenant-wide delegated consent | 20 |
| Tenant-wide consent while assignment is not required | 15 |
| No service-principal owner found | 5 |
| Publisher is not verified | 5 |

Overall levels:

| Score | Rating |
|---:|---|
| 70 or higher | Critical |
| 45–69 | High |
| 20–44 | Medium |
| Below 20 | Low |

The score is a prioritization aid, not a declaration that an application is malicious or improperly configured. Business purpose, data sensitivity, credential controls, vendor trust, and compensating controls still require human review.

## Recommended review workflow

1. Start with Critical and High applications in the HTML report.
2. Confirm the business owner and business purpose.
3. Validate whether every consented permission is still required.
4. Pay special attention to app-only permissions and credentials.
5. Review tenant-wide delegated grants.
6. For interactive applications, determine whether assignment should be required.
7. Compare current assignments with actual successful usage.
8. Remove obsolete grants, credentials, assignments, or service principals through your normal change-control process.
9. Record an approval and future review date for retained privileged applications.

## Important limitations

- Sign-in results are limited by the tenant's available Microsoft Entra log retention, even if a longer value is supplied to `-SignInLookbackDays`.
- No sign-in found does not prove that an application is unused.
- Some non-interactive activity may not identify a human user.
- The script reports successful events and does not currently analyze failed sign-ins.
- Permission risk is based on permission-name patterns and cannot understand every application's business context.
- Publisher verification is a useful signal, not a guarantee of safety.
- The script audits the current state; it does not establish who originally granted consent or changed an assignment.
- Large tenants can take time to process because app-role assignments are enumerated across resource APIs.
- Sign-in collection uses the Microsoft Graph beta sign-in endpoint because it queries multiple sign-in event types. Beta behavior can change.
- Conditional Access, workload identity risk, certificate expiration, secrets, federated credentials, and application registration ownership are outside the current scope.

## Troubleshooting

### Microsoft.Graph.Authentication is not installed

Install it for the current user:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Consent or authorization errors

Confirm that the signed-in identity is permitted to use the requested scopes. An administrator may need to grant consent under the tenant's consent policy.

To reduce the requested permissions while testing, omit sign-in collection:

```powershell
.\EnterpriseAppPermissionAudit.ps1 -SkipSignInLogs
```

### Sign-in queries return no data

Check:

- Whether `AuditLog.Read.All` was granted
- Whether the tenant retains data for the requested period
- Whether the application had successful activity during that period
- Whether the relevant activity appears under a different application ID or service principal

An empty result should be interpreted as **no matching events found in the available data**, not proof of inactivity.

### Some resource APIs generate warnings

The script continues when an individual app-role-assignment endpoint cannot be read. Review the warning text and verify that the account has the documented scopes. Partial results may still be generated.

### Execution policy blocks the script

If your organization's policy permits it, run the script in a process-scoped bypass session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\EnterpriseAppPermissionAudit.ps1
```

Do not weaken a managed organizational execution policy without approval.

### Authentication cache or WAM issues

Disconnect the current Graph session and retry:

```powershell
Disconnect-MgGraph
Connect-MgGraph -Scopes Application.Read.All,Directory.Read.All,DelegatedPermissionGrant.Read.All,AuditLog.Read.All
```

If your environment has persistent broker authentication problems, resolve them according to your organization's authentication standards before running the audit.

## Security and privacy

Reports may contain:

- User principal names
- Application and service-principal IDs
- Group names
- IP addresses
- Permission grants
- Recent sign-in timestamps

Treat the output as sensitive security information. Store it in an approved location, restrict access, and remove it when it is no longer required.

The script authenticates interactively to Microsoft Graph and does not embed credentials, client secrets, tenant IDs, or access tokens.

## Contributing

Issues and pull requests are welcome. When proposing changes to the risk model, include:

- The affected Microsoft Graph permission names
- The proposed severity
- The security rationale
- Any relevant Microsoft documentation

When changing Graph queries, preserve pagination and keep the script read-only unless a separate, clearly identified remediation mode is intentionally introduced.

## Disclaimer

This project is provided as an administrative assessment aid. Validate findings before changing production applications, permissions, consent grants, or assignments.
