# PR Title: feat: Implement MachineAccountKey controller, e2e tests, and key rotation lifecycle

## Description

This Pull Request introduces full lifecycle management for Machine Account Keys via the new `MachineAccountKey` controller. It securely automates the provisioning, rotation, and revocation of asymmetric machine keys within Zitadel, ensuring strict cryptographic hygiene without exposing private keys.

### Core Features Added

- **MachineAccountKey Controller**: Implementation of the reconciliation loop, complete with garbage-collection through finalizers and parent `OwnerReferences` linked to `MachineAccount` resources.
- **Secure and Resilient Key Rotation**: Engineered a crash-safe rotation flow that prioritizes the revocation of the old Zitadel key before the registration of a new one. This ensures that a failure during rotation does not leave active, potentially leaked credentials.
- **Enhanced Logging**: Integrated structured logging throughout the controller to provide clear visibility into key lifecycle events (registration, rotation, and revocation) and detailed context for any reconciliation failures.
- **Zitadel API Integration**: Expanded `sdk_client.go` to wrap Zitadel's gRPC `UserServiceV2` for managing machine keys (`AddMachineKey` and `RemoveMachineKey`).

### E2E Testing & Test-Infra Updates

- **Comprehensive Chainsaw Suites**: Added robust end-to-end tests validating:
  - Machine account deactivation effects on key-based authentication.
  - Secure key rotation and old key revocation (asserting `invalid_grant` for revoked keys).
  - Cascade deletion of keys when parent accounts are removed.
- **Stabilized CI Restart Task**: Updated `Taskfile.yaml` to include a namespace update trigger, forcing `Kyverno` to sync critical secrets (`iam-admin`, `ci-ca-secret`) into the application namespace before rolling out restarts.
- **Unit Testing**: Refactored controller unit tests to align with the new security-first rotation pattern (requiring successful revocation) and added coverage for the new logging paths.

### Motivation

This implementation enables programmatic, asymmetrically signed authentication for service accounts, allowing downstream services and CI builders to authenticate securely with Zitadel while maintaining perfect cryptographic lifecycle management.
