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

Resume from a saved checkpoint without reconnecting to Microsoft Graph:

```powershell
.\EnterpriseAppPermissionAudit.ps1 `
    -ResumeFromCheckpoint "C:\Reports\EnterpriseAppAudit-Recovery-20260918-123456.clixml"
```

Choose a specific checkpoint location for a new collection run:

```powershell
.\EnterpriseAppPermissionAudit.ps1 `
    -CheckpointPath "C:\Reports\EnterpriseApps\CollectionCheckpoint.clixml"
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
| `-ResumeFromCheckpoint` | String | None | Loads a previously exported CLIXML checkpoint and skips Microsoft Graph collection |
| `-CheckpointPath` | String | Output directory | Sets the collection checkpoint path for a new audit run |

Low-risk applications are always retained in the summary CSV. The switch only controls whether they appear in the HTML report.

## Output files

Before report calculation, a normal collection run also saves `EnterpriseAppAudit-Checkpoint.clixml` in the output directory unless `-CheckpointPath` is supplied. This contains sensitive tenant data and should not be committed to a public repository.

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

## CIS benchmarks and least-privilege context

This audit supports the review activities behind the [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365) and the access-control principles in [CIS Controls](https://www.cisecurity.org/controls/access-control-management). In particular, it helps an assessor identify broad application consent, privileged API access, unrestricted interactive access, missing ownership, and permissions that may exceed a documented business need.

The report is **CIS-informed, not a CIS compliance scan**. It does not test every safeguard in a CIS Benchmark, and its risk score is not a CIS score. Benchmark versions and Microsoft 365 licensing requirements change, so findings should be mapped to the exact benchmark version and profile used by the organization.

### How assignment required applies

For an interactive enterprise application, enabling **Assignment required** creates an explicit access boundary: only assigned users and groups can sign in. Leaving it disabled can allow any tenant user to attempt to access the application, subject to the application's own authorization and other controls. Requiring assignment therefore supports least privilege when access is intended for a defined population.

Assignment is not automatically appropriate for every application. Broadly deployed productivity applications, background services, and some Microsoft-managed applications may intentionally use other access models. The setting should be validated with the application owner and tested before enforcement.

Most importantly, assignment controls **user sign-in**, not the effective reach of app-only permissions. A service principal with application permissions can continue to act as itself even when no users or groups are assigned. App-only access must be governed through permission consent, credential protection, workload identity controls, ownership, and periodic review.

### How excessive permissions apply

A permission is potentially excessive when its effective capability is broader than the application's approved business purpose. Common indicators include:

- Write or management access where read-only access would satisfy the use case
- Tenant-wide `.All` permissions where a resource-scoped or selected permission is available
- Application permissions where delegated access would be sufficient
- Tenant-wide delegated consent for an application used by only a small population
- Permissions retained after a feature, integration, or application is no longer used

The auditor highlights these indicators; it cannot determine business necessity by itself. A high score means **review first**, not **remove automatically**. Final disposition should compare the permission list with vendor documentation, actual usage, the application's data scope, and an approved business justification.

### Suggested client-facing finding language

> The assessment identified enterprise applications whose consented permissions or access configuration may provide broader access than is required for their documented business purpose. These findings should be reviewed under least-privilege and application-governance procedures. Risk ratings prioritize review and do not, by themselves, establish compromise, misuse, or noncompliance.

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

### Client interpretation of ratings

| Rating | What it means | Suggested response |
|---|---|---|
| Critical | Multiple material risk indicators or at least one critical permission combined with broad access or weak governance | Validate immediately; confirm owner and purpose, then reduce access or document compensating controls |
| High | Privileged access or a combination of elevated permission and governance concerns | Prioritize for near-term technical and business-owner review |
| Medium | Meaningful exposure exists, but fewer high-impact indicators were found | Review during the normal application-governance cycle |
| Low | No major heuristic indicators were detected by this tool | Retain in the inventory and review periodically; Low does not mean risk-free |

### Definitions used in the report

| Term | Plain-English meaning |
|---|---|
| Enterprise application | The service principal representing an application in the tenant |
| Delegated permission | Access exercised on behalf of a signed-in user and normally bounded by both the permission and that user's access |
| Application permission / app-only | Access exercised by the workload itself, without a signed-in user; user assignment does not restrict it |
| Tenant-wide consent | Delegated consent granted for all users (`AllPrincipals`), rather than for one individual user |
| Assignment required | Entra setting that limits interactive sign-in to explicitly assigned users or groups |
| Admin consent | Approval of permissions that require an administrator or that are being granted on behalf of the organization |
| Verified publisher | Microsoft publisher-verification status; a trust signal, not proof that the application is safe or appropriately permissioned |
| Owner | A directory object recorded as accountable for the enterprise application; absence of an owner is a governance concern |
| Last successful sign-in | Most recent matching event found within available Entra log retention; no event found does not prove non-use |
| Risk reason | A condition that contributed points to the application's overall score |
| Suggested action | Review guidance generated from detected conditions, not an automated remediation decision |

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

## Checkpoints and crash recovery

A normal run automatically exports all expensive collection results before risk calculation and report generation. If reporting fails, correct the reporting issue and reuse the checkpoint:

```powershell
.\EnterpriseAppPermissionAudit.ps1 `
    -ResumeFromCheckpoint "C:\Path\EnterpriseAppAudit-Checkpoint.clixml"
```

Resume mode does not authenticate to Microsoft Graph and does not repeat API collection. It creates a new output directory unless `-OutputPath` is specified.

Older manually-created recovery files are supported when they contain the required properties documented by the recovery workflow. Checkpoint files can include user principal names, IP addresses, group names, application identifiers, assignments, and permission details. Protect them like the generated reports and never commit tenant checkpoints to this public repository.

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
