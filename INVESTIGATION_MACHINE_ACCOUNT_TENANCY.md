# Investigation: Machine Account Tenancy in Zitadel

## Executive Summary

Based on the current codebase analysis, **machine accounts and their keys are NOT isolated per Zitadel tenant/organization**. All machine accounts from all Milo projects are stored in a **single shared Zitadel instance**, with isolation achieved through **namespace-based email identity** rather than organizational boundaries.

---

## Current Architecture

### 1. Milo Multi-Tenant Structure

The Milo platform uses a **two-tier control plane architecture**:

- **Core Control Plane** (Platform-wide): Central management, platform-level resources
- **Project Control Planes** (Per-project): Dynamically created for each tenant/project
  - Each project gets its own Kubernetes cluster
  - Each cluster runs its own copy of resources (MachineAccount, MachineAccountKey, User, etc.)

### 2. Zitadel Integration (Current Model)

**Single Shared Zitadel Instance**
```
┌─────────────────────────────────────┐
│       Zitadel Instance              │
│  (ONE for entire platform)          │
│                                     │
│  ├─ Machine User 1 (Project A)      │
│  ├─ Machine User 2 (Project A)      │
│  ├─ Machine User 3 (Project B)      │
│  ├─ Machine User 4 (Project B)      │
│  └─ ...                             │
└─────────────────────────────────────┘
          ↑
          │ (API calls from all projects)
          │
┌─────────────────────────────────────┐
│    Milo Multi-Tenant Platform       │
│                                     │
│  ┌────────────────────────────────┐ │
│  │  Project Control Plane A       │ │
│  │  ├─ MachineAccount (name: ma1) │ │
│  │  │  ├─ UID: <uuid-1>          │ │
│  │  │  └─ MachineAccountKey       │ │
│  │  │     └─ stores spec.publicKey│ │
│  │  └─ ...                        │ │
│  └────────────────────────────────┘ │
│                                     │
│  ┌────────────────────────────────┐ │
│  │  Project Control Plane B       │ │
│  │  ├─ MachineAccount (name: ma1) │ │
│  │  │  ├─ UID: <uuid-2>          │ │
│  │  │  └─ MachineAccountKey       │ │
│  │  │     └─ stores spec.publicKey│ │
│  │  └─ ...                        │ │
│  └────────────────────────────────┘ │
└─────────────────────────────────────┘
```

### 3. Isolation Mechanism

**Isolation is achieved through email-based identity, NOT organizational separation:**

```go
// From machineaccount_controller.go:253-254
func (r *MachineAccountController) computeEmailAddress(
  machineAccount *iammiloapiscomv1alpha1.MachineAccount,
  req mcreconcile.Request) string {
  return string(machineAccount.GetUID()) +
         "@" + machineAccount.GetNamespace() +
         "." + req.ClusterName +  // ClusterName = project name
         "." + r.EmailAddressSuffix
}
```

**Result:** Machine account identities are globally unique by construction:
- Project A's "ma1": `{uuid-1}@namespace.project-a.iam.miloapis.com`
- Project B's "ma1": `{uuid-2}@namespace.project-b.iam.miloapis.com`

Even if both have the same resource name, they have **different UIDs and different email addresses**, making them distinct users in Zitadel.

### 4. Machine Account Key Mapping

Machine account keys are **NOT isolated per Zitadel tenant/organization**. They are stored at the **Zitadel user level**:

```go
// From machineaccountkey_controller.go:191, 209
zitadelUserID := string(ma.GetUID())  // e.g., "uuid-1"
keyID, err := r.Zitadel.AddMachineKey(ctx, zitadelUserID, publicKeyBytes, expiration)
```

**Key relationship:**
- Zitadel User (MachineAccount) ← 1:N → Zitadel Keys (MachineAccountKeys)
- Each Zitadel User can have multiple keys (key rotation)
- Keys are stored with a user ID and key ID, both tracked in status

---

## Zitadel API Capabilities

### Organizations/Tenants in Zitadel

Zitadel DOES support multi-tenancy through **Organizations**:
- **Organization**: A container for users, applications, and policies
- **Org ID**: Required parameter in many Zitadel APIs
- Provides isolation boundaries for RBAC, policies, and resources

### Available APIs for Organization Management

Zitadel provides REST and gRPC APIs for organization management:

**Organization Management APIs (examples):**
- `POST /v1/organizations` – Create organization
- `GET /v1/organizations/{id}` – Get organization details
- `PATCH /v1/organizations/{id}` – Update organization
- `DELETE /v1/organizations/{id}` – Delete organization
- `GET /v1/organizations` – List organizations

**User APIs with Organization Support:**
- `POST /v1/organizations/{org_id}/members` – Add org member
- `GET /v1/organizations/{org_id}/members` – List org members
- Users can belong to multiple organizations with different roles

**Documentation:**
- [Zitadel API Docs: Organizations](https://zitadel.com/docs/apis/resources/management/organization)
- [Zitadel gRPC Org Management](https://github.com/zitadel/zitadel/tree/main/proto/zitadel/org)

---

## Analysis: Current vs. Tenant-Based Approach

### ✅ Current Approach (Single Zitadel Instance)

**Pros:**
1. **Simplicity**: Single Zitadel deployment, one API client, easier operations
2. **No UUID collision risk**: Each Milo project has unique UID
3. **Email identity isolation**: Email addresses are globally unique by design
4. **Less infrastructure**: Reduced operational overhead
5. **Works today**: Existing code is functional and tested

**Cons:**
1. **No API-level isolation**: All projects can theoretically access the same Zitadel instance
2. **Shared namespace for users**: Platform-wide user directory (single org)
3. **Audit trail mixing**: Logs and events from all projects in one Zitadel audit log
4. **Policy application**: Organization-level policies would apply across all projects
5. **Future compliance risk**: If regulatory isolation per project is needed later, refactoring required

---

## Proposed Alternative: Per-Project Zitadel Organizations

If the requirement is **organizational isolation per project**, the architecture would change to:

### Design Option: One Zitadel Organization per Milo Project

```
┌──────────────────────────────────────────────┐
│       Zitadel Instance                       │
│  (Still ONE Zitadel deployment)              │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │  Organization: "Project-A"              │ │
│  │  ├─ Machine User 1 (ID: uuid-1)        │ │
│  │  ├─ Machine User 2 (ID: uuid-2)        │ │
│  │  └─ Keys associated with users         │ │
│  └─────────────────────────────────────────┘ │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │  Organization: "Project-B"              │ │
│  │  ├─ Machine User 1 (ID: uuid-3)        │ │
│  │  ├─ Machine User 2 (ID: uuid-4)        │ │
│  │  └─ Keys associated with users         │ │
│  └─────────────────────────────────────────┘ │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │  Organization: "Platform"               │ │
│  │  └─ Human users (IAM management)        │ │
│  └─────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

### Implementation Requirements

If per-project organization isolation were needed:

**1. Controller Enhancement:**
```go
// MachineAccountController would need to:
// a) Accept Zitadel organization ID per project
// b) Ensure machine users are created within the correct org
// c) Pass org context to API calls

type MachineAccountController struct {
    Zitadel           *zitadel.Client
    ZitadelOrgIDFunc  func(ctx context.Context, projectName string) (string, error)
    // ... other fields
}

// Usage:
orgID, err := r.ZitadelOrgIDFunc(ctx, req.ClusterName) // ClusterName = project
userID := string(ma.GetUID())
// Then create user with orgID context
```

**2. MachineAccountKey Controller Changes:**
```go
// MachineAccountKeyController would:
// a) Inherit org context from parent MachineAccount
// b) Use org-scoped API calls for AddMachineKey/RemoveMachineKey
```

**3. Zitadel SDK Client Changes:**
```go
// pkg/zitadel/sdk_client.go would need methods like:
func (c *SDKClient) AddMachineKeyInOrg(
    ctx context.Context,
    orgID string,      // Organization context
    userID string,
    publicKey []byte,
    expirationDate *time.Time,
) (string, error)
```

**4. Configuration:**
```go
// cmd/controller/controller.go would need to:
// - Map project names to Zitadel organization IDs
// - Either:
//   a) Accept org mapping as flags/config
//   b) Query Zitadel to find/create org per project
//   c) Use a naming convention (org = project-name)
```

**5. Bootstrap Requirement:**
```
// Before controller runs, ensure Zitadel organizations exist:
// For each Milo project, create corresponding Zitadel org
// Could be done via:
// - Zitadel REST API
// - Controller startup hook
// - External provisioning process
```

---

## Recommendation

### When to Keep Current Approach (Single Shared Zitadel)

✅ **Keep current design if:**
- Projects don't need API-level isolation
- Regulatory requirements don't mandate org separation
- Email-based identity isolation is sufficient
- Operational simplicity is valued
- No cross-project access control policies are needed

### When to Adopt Per-Project Organizations

🚀 **Adopt per-project orgs if:**
- Compliance requires organizational isolation (e.g., SOC 2, HIPAA, GDPR)
- Projects need separate RBAC policies in Zitadel
- Projects need separate audit logs
- Enterprise customers expect organizational boundaries
- Future roadmap includes project-level security policies

---

## Current Code References

**No organization/tenant handling in current code:**

```go
// pkg/zitadel/api.go - API interface
type API interface {
    AddMachineKey(ctx context.Context, userID string, publicKey []byte, ...) (keyID string, err error)
    RemoveMachineKey(ctx context.Context, userID, keyID string) error
    // No OrgID parameter
}

// sdk_client.go - Creates SDK client
conf := zitadel.New(host)  // No org context
cl, err := client.New(ctx, conf, ...)
```

**Organization APIs available in Zitadel gRPC but not used:**

```go
// From Zitadel go SDK (not used in this codebase):
import "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v1"
// org management APIs are available but not integrated
```

---

## Summary Table

| Aspect | Current Implementation | Per-Project Organization |
|--------|------------------------|-------------------------|
| **Zitadel Instances** | 1 shared | 1 shared (1 org per project) |
| **Isolation Mechanism** | Email identity | Zitadel Organization |
| **User Directory** | Platform-wide | Per-organization |
| **Key Storage** | At user level (shared org) | At user level (org-scoped) |
| **API Complexity** | Simple | Moderate (org context needed) |
| **Operational Overhead** | Low | Medium (org management) |
| **Audit Isolation** | All projects mixed | Per-organization |
| **RBAC Scope** | Platform-wide policies | Per-organization policies |
| **Compliance Ready** | Limited | Better for regulated workloads |

---

## Questions to Answer Before Implementation

1. **Regulatory Requirement?**
   - Do compliance requirements mandate per-project isolation?

2. **Cross-Project Access Control?**
   - Will projects ever need different RBAC policies in Zitadel?

3. **Audit Log Separation?**
   - Does the platform need per-project audit trails?

4. **User Visibility?**
   - Should users from Project A be able to see users from Project B in Zitadel?

5. **Multi-Tenancy SLA?**
   - Is organizational isolation a selling point for enterprise customers?

If the answer to any of these is **"yes, required"**, then per-project Zitadel organizations should be implemented. Otherwise, the current email-identity-based isolation is sufficient.
