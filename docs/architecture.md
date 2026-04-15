# Auth Provider Zitadel Architecture

## Overview

This document explains the architecture of the Auth Provider Zitadel binary,
which does two things in a single process:

1. **Aggregated API server** — serves `identity.miloapis.com/v1alpha1` resources
   via Kubernetes API aggregation:
   - `machineaccounts` (cluster-scoped, etcd-backed, this binary is the authority)
   - `machineaccountkeys` (cluster-scoped, Zitadel-backed, no etcd)
   - `sessions` and `useridentities` (Zitadel-backed)
2. **Controller manager** — uses multicluster-runtime to watch `MachineAccount`
   resources across Milo project control planes and reconcile machine user state
   to Zitadel.

## Background

### Milo Platform Integration

The Milo platform provides a multi-tenant architecture where:
- **Core Control Plane**: Platform-wide resource management and user lifecycle
- **Project Control Planes**: Per-project resource management, dynamically
  created

This binary integrates with Milo to synchronize authentication state with
Zitadel and to serve the canonical storage for `MachineAccount`.

### Why Etcd for MachineAccount?

`MachineAccount` was previously defined as a CRD in the Milo repo. That CRD has
been removed; this binary now becomes the authority for
`identity.miloapis.com/machineaccounts` by serving it through the aggregated
API server with an etcd backing store.  The controller still watches
`MachineAccount` resources through Milo's APIService proxy (project control
planes route reads through the aggregated API server), so the multicluster-runtime
topology is unchanged.

## Architecture

### Aggregated API Server

The binary registers `identity.miloapis.com/v1alpha1` as an aggregated API group
via a Kubernetes `APIService` object.  Milo routes requests for this group to
this binary.

Resource storage breakdown:

| Resource            | Scope   | Backend  | Notes                              |
|---------------------|---------|----------|------------------------------------|
| machineaccounts     | Cluster | etcd     | Authoritative; replaced Milo CRD   |
| machineaccounts/status | Cluster | etcd  | Status subresource only            |
| machineaccountkeys  | Cluster | Zitadel  | No persistent storage in etcd      |
| sessions            | Cluster | Zitadel  | Read-only Zitadel proxy            |
| useridentities      | Cluster | Zitadel  | Read-only Zitadel proxy            |

### Controller Manager (Dual Manager Architecture)

Two coordinated managers handle the different Milo control plane topologies
while maintaining a single Zitadel integration point.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Auth Provider Zitadel Process                        │
├──────────────────────────────┬──────────────────────────────────────────┤
│   Aggregated API Server      │   Controller Manager                     │
│                              │                                          │
│  identity.miloapis.com/v1α1  │  ┌──────────────────────────────────┐    │
│  ┌──────────────────────┐    │  │    Main Multi-Tenant Manager     │    │
│  │ machineaccounts      │    │  │  • Leader Election: ✓ Enabled    │    │
│  │ (etcd)               │◄───┼──┤  • Discovers: Project CPs        │    │
│  └──────────────────────┘    │  │                                  │    │
│  ┌──────────────────────┐    │  │  ┌────────────────────────────┐  │    │
│  │ machineaccountkeys   │    │  │  │  MachineAccountController  │  │    │
│  │ (Zitadel)            │    │  │  │  • Watches MachineAccount  │  │    │
│  └──────────────────────┘    │  │  │    across project CPs      │  │    │
│  ┌──────────────────────┐    │  │  │  • Reconciles to Zitadel   │  │    │
│  │ sessions             │    │  │  └────────────────────────────┘  │    │
│  │ useridentities       │    │  └──────────────────────────────────┘    │
│  │ (Zitadel)            │    │                                          │
│  └──────────────────────┘    │  ┌──────────────────────────────────┐    │
│                              │  │   Core Control Plane Manager     │    │
│                              │  │  • Leader Election: Disabled     │    │
│                              │  │  • Target: Milo core CP          │    │
│                              │  │  • Starts: only when leader      │    │
│                              │  │                                  │    │
│                              │  │  ┌────────────────────────────┐  │    │
│                              │  │  │ UserDeactivationController │  │    │
│                              │  │  │  • Watches UserDeactivation│  │    │
│                              │  │  │  • Reconciles to Zitadel   │  │    │
│                              │  │  └────────────────────────────┘  │    │
│                              │  └──────────────────────────────────┘    │
└──────────────────────────────┴──────────────────────────────────────────┘
                                              │
                                              ▼
                                    ┌─────────────────┐
                                    │     Zitadel     │
                                    │ • Machine Users │
                                    │ • Human Users   │
                                    └─────────────────┘

Milo Multi-Tenant Platform (Project Control Planes):
┌─────────────────┐  ┌─────────────────┐  ┌──────────────────┐
│ Project CP #1   │  │ Project CP #2   │  │ Core Control     │
│ (Tenant A)      │  │ (Tenant B)      │  │ Plane            │
│                 │  │                 │  │ (Platform-wide)  │
│ MachineAccount  │  │ MachineAccount  │  │                  │
│ (via APIService │  │ (via APIService │  │ UserDeactivation │
│  → this binary) │  │  → this binary) │  │ resources        │
└─────────────────┘  └─────────────────┘  └──────────────────┘
```

## Component Details

### Aggregated API Server

**Purpose**: Serve `identity.miloapis.com` resources to the Kubernetes API.

- `MachineAccount` is stored in etcd; this binary is the write authority.
  The etcd connection is configured via `--etcd-servers` (and related TLS
  flags).
- `MachineAccountKey` is a virtual resource backed entirely by Zitadel API
  calls — no data is stored in etcd.
- `sessions` and `useridentities` are Zitadel-backed read-only projections.

### Main Multi-Tenant Manager

**Purpose**: Watches `MachineAccount` resources across project control planes
and reconciles machine user state in Zitadel.

- Integrates with Milo's discovery system to find project control planes as
  projects are created.
- `MachineAccount` reads flow through Milo's APIService proxy to this binary's
  aggregated API server, which returns objects from etcd.
- Manages project-level machine user lifecycle in Zitadel (create, activate,
  deactivate, delete).
- Coordinates overall process leadership.

### Core Control Plane Manager

**Purpose**: Handles `UserDeactivation` authentication on Milo's core control
plane.

- Integrates directly with Milo's core control plane.
- Manages `UserDeactivation` resources that need to be reconciled with Zitadel.
- Operates as subordinate to main manager (starts only when main manager has
  leadership).

### Leadership Coordination

The two managers coordinate through a leader election mechanism to ensure
consistent authentication operations.

The main multi-tenant manager participates in leader election and becomes the
single active instance across all deployments. Once it achieves leadership, it
signals the core control plane manager to start.

The core control plane manager operates as a subordinate — it only starts when
the main manager has established leadership and stops if leadership is lost.
This prevents multiple instances from simultaneously modifying user state in
Zitadel and ensures coordinated authentication management across the entire Milo
platform.

## Milo Integration Points

### Resource Synchronization

#### MachineAccountController (Tenant Level)

- **API Group**: `identity.miloapis.com` (moved from `iam.miloapis.com`)
- **Milo Integration**: Watches `MachineAccount` resources in project control
  planes via multicluster-runtime; the APIService routes reads through this
  binary's etcd-backed storage.
- **Finalizer**: `identity.miloapis.com/machineaccount`
- **Zitadel Operations**:
  - Creates machine users in Zitadel when `MachineAccount` is created
  - Updates machine user state (Active/Inactive) based on `spec.state`
  - Deletes machine users when `MachineAccount` is deleted
- **Identity Format**: `{uid}@{namespace}.{project}.iam.miloapis.com`

#### UserDeactivationController (Platform Level)

- **API Group**: `iam.miloapis.com` (unchanged)
- **Milo Integration**: Watches `UserDeactivation` resources in core control
  plane.
- **Zitadel Operations**:
  - Deactivates users in Zitadel when `UserDeactivation` is created
  - Reactivates users in Zitadel when `UserDeactivation` is deleted
  - Updates corresponding `User` resource status in Milo

### Discovery Integration

- Uses Milo's native discovery to find project control planes.
- Supports Milo's internal service discovery for efficient communication.
- Automatically handles tenant lifecycle (onboarding/offboarding).
