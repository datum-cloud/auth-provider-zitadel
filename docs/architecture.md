# Auth Provider Zitadel Controller Architecture

## Overview

This document explains the architecture of the Auth Provider Zitadel controller,
which manages Zitadel authentication for users and machine accounts across the
Milo multi-tenant platform using a dual-manager setup.

## Background

### Milo Platform Integration

The Milo platform provides a multi-tenant architecture where:
- **Core Control Plane**: Platform-wide resource management and user lifecycle
- **Project Control Planes**: Per-project resource management, dynamically
  created

This controller integrates with Milo to synchronize authentication state with
Zitadel.

### The Authentication Challenge

This controller handles Zitadel authentication but faces a topology challenge in
Milo's architecture:

- **MachineAccount resources**: Live in project control planes (per-tenant,
  discovered dynamically)
- **UserDeactivation resources**: Live in the core control plane (platform-wide)

Both resource types need to interact with the same Zitadel instance for
authentication management.

## Solution: Dual Manager Architecture

We use two coordinated managers to handle the different Milo control plane
topologies while maintaining a single Zitadel integration point.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────-┐
│                Auth Provider Zitadel Process                     │
├─────────────────────────────────────────────────────────────────-┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Main Multi-Tenant Manager                      │ │
│  │  • Leader Election: ✓ Enabled                               │ │
│  │  • Discovers: Project control planes (via Milo provider)    │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐    │ │
│  │  │         MachineAccountController                    │    │ │
│  │  │  • Watches: MachineAccount resources                │    │ │
│  │  │  • Reconciles across: All project control planes    │    │ │
│  │  │  • Zitadel: Creates/manages machine users           │    │ │
│  │  └─────────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │            Core Control Plane Manager                       │ │
│  │  • Leader Election: Disabled (subordinate)                  │ │
│  │  • Target: Milo core control plane                          │ │
│  │  • Starts: Only when main manager is leader                 │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐    │ │
│  │  │       UserDeactivationController                    │    │ │
│  │  │  • Watches: UserDeactivation resources              │    │ │
│  │  │  • Reconciles on: Core control plane only           │    │ │
│  │  │  • Zitadel: Deactivates/reactivates users           │    │ │
│  │  └─────────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────-─┘
                              │
                              ▼
                    ┌─────────────────┐
                    │     Zitadel     │
                    │                 │
                    │ • Machine Users │
                    │ • Human Users   │
                    └─────────────────┘

Milo Multi-Tenant Platform:
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Project CP #1   │  │ Project CP #2   │  │ Core Control    │
│ (Tenant A)      │  │ (Tenant B)      │  │ Plane           │
│                 │  │                 │  │ (Platform-wide) │
│ MachineAccount  │  │ MachineAccount  │  │                 │
│ resources       │  │ resources       │  │ UserDeactivation│
│                 │  │                 │  │ resources       │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Component Details

### Main Multi-Tenant Manager

**Purpose**: Handles MachineAccounts and other project-level resources that
exist in Milo

- Integrates with Milo's discovery system to find project control planes as
  projects are created
- Manages project-level Milo resources that need to be reconciled with Zitadel
  (e.g. MachineAccounts)
- Coordinates overall process leadership

### Core Control Plane Manager

**Purpose**: Handles UserDeactivation authentication on Milo's core control
plane

- Integrates directly with Milo's core control plane
- Manages core Milo resources that needs to be reconciled with Zitadel (e.g.
  UserDeactivations)
- Operates as subordinate to main manager (starts only when main manager has
  leadership)

### Leadership Coordination

The two managers coordinate through a leader election mechanism to ensure
consistent authentication operations:

The main multi-tenant manager participates in leader election and becomes the
single active instance across all deployments. Once it achieves leadership, it
signals the core control plane manager to start.

The core control plane manager operates as a subordinate - it only starts when
the main manager has established leadership and stops if leadership is lost.
This prevents multiple instances from simultaneously modifying user state in
Zitadel and ensures coordinated authentication management across the entire Milo
platform.

## Milo Integration Points

### Resource Synchronization

#### MachineAccountController (Tenant Level)

- **Milo Integration**: Watches `MachineAccount` resources in project control
  planes
- **Zitadel Operations**:
  - Creates machine users in Zitadel when MachineAccount is created in Milo
  - Updates machine user state (Active/Inactive) based on MachineAccount spec
  - Deletes machine users when MachineAccount is deleted from Milo
- **Identity Format**: `{uid}@{namespace}.{project}.iam.miloapis.com`

#### UserDeactivationController (Platform Level)

- **Milo Integration**: Watches `UserDeactivation` resources in core control
  plane
- **Zitadel Operations**:
  - Deactivates users in Zitadel when UserDeactivation is created in Milo
  - Reactivates users in Zitadel when UserDeactivation is deleted from Milo
  - Updates corresponding `User` resource status in Milo

### Discovery Integration

- Uses Milo's native discovery to find project control planes
- Supports Milo's internal service discovery for efficient communication
- Automatically handles tenant lifecycle (onboarding/offboarding)
