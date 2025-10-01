# Milo Zitadel Auth Provider

Authentication infrastructure for Milo's business operating system backed by
Zitadel - enabling secure identity management, token generation, and account
lifecycle management across business entities like users, organizations, and
machine accounts.

## Overview

This project provides the authentication foundation for the [Milo business
operating system](https://github.com/datum-cloud/milo), which uses Kubernetes
APIServer patterns to manage business entities for product-led B2B companies.
The auth provider integrates Milo's business APIs with Zitadel's identity and
access management platform to handle complex authentication scenarios like:

- *"How do sales reps securely authenticate to access customer data?"*
- *"How can we manage machine-to-machine authentication for automated
workflows?"*
- *"How do we handle user lifecycle management across organizational
  boundaries?"*

### Key Capabilities

1. **Identity Management** - Centralized user authentication and identity
   lifecycle management for Milo resources
2. **Token Generation & Validation** - Secure JWT token issuance and validation
   for API access
3. **Account Management** - User registration, profile management, and
   organizational membership handling
4. **Machine Account Management** - Automated service account creation and
   credential management for system integrations

## How It Works

1. **Identity Registration**: Users and machine accounts are registered in
   Zitadel with appropriate organizational context and metadata
2. **Authentication Flow**: The system handles OAuth2/OIDC flows for user login
   and machine-to-machine authentication
3. **Token Management**: Secure JWT tokens are issued with appropriate claims
   and scopes based on user context and permissions
4. **Account Lifecycle**: User onboarding, profile updates, and deactivation
   are managed through Zitadel's APIs
5. **Machine Account Provisioning**: key creation and rotation for
   service accounts used by Milo's internal systems
6. **Session Management**: Secure session handling with configurable token
   lifetimes and refresh capabilities
7. **Integration Bridge**: Seamless integration with Milo's Kubernetes-based
APIs

## Aggregated Zitadel API Server (virtual Sessions)

This repository includes a small aggregated API server that exposes Zitadel sessions as a Kubernetes-native API under the provider group/version:

- Group/Version: `zitadel.identity.milo.io/v1alpha1`
- Resource: `sessions`
- Scope: cluster-scoped, virtual (no etcd)
- Types: reuses Milo Identity public `Session` types bound to the provider G/V

### What it does

- Authn/Authz via the Kubernetes aggregation layer (delegating to the core apiserver)
- Enforces self-scoping (users only see and act on their own sessions)
- Proxies list/get/delete to Zitadel Session Service v2 using the official `zitadel-go/v3` SDK

### Deploy

Kustomize base manifests live under `config/base/services/apiserver/` and are included in `config/base/kustomization.yaml`.

- ServiceAccount & RBAC: `zitadel-apiserver` bound to `system:auth-delegator`
- Deployment: runs the `apiserver` subcommand from this binary
- Service: ClusterIP on 443 -> container 8443
- APIService: registers `v1alpha1.zitadel.identity.milo.io` with the aggregator (currently `insecureSkipTLSVerify: true` – replace with `caBundle` for production)

Environment variables (mounted via Secret/ConfigMap as you prefer):

- `ZITADEL_BASE_URL`: e.g. `https://<tenant>.<region>.zitadel.cloud`
- `ZITADEL_MACHINE_ACCOUNT_KEY_PATH`: path to Zitadel machine account JSON key (mounted to the container)
- Optional: `ZITADEL_PAT` (for testing)

### Run locally

```bash
# Build and run the aggregated server (example):
go run ./cmd apiserver \
  --secure-port=8443 \
  --tls-cert-file=/path/to/tls.crt \
  --tls-private-key-file=/path/to/tls.key \
  --kubeconfig=/path/to/kubeconfig
  
```

### Test in a cluster

```bash
# Verify APIService is registered
kubectl get apiservices | grep zitadel.identity.milo.io

# Discover group/version
kubectl get --raw /apis/zitadel.identity.milo.io/v1alpha1 | jq

# As a real user (with delegated auth):
kubectl get sessions.zitadel.identity.milo.io
kubectl get sessions.zitadel.identity.milo.io <session-id> -o yaml
kubectl delete sessions.zitadel.identity.milo.io <session-id>
```

### Notes

- The apiserver is stateless and does not use etcd
- It relies on the core apiserver for authentication and authorization
- The service user (machine account JSON key) is used to authenticate to Zitadel

## Testing

Follow these steps to run the end-to-end (e2e) tests locally:

1. Create a local Kind cluster:

   ```bash
   make kind-create
   ```

2. Run the e2e test suite:

   ```bash
   make test-e2e
   ```

3. Inspect the controller logs once the tests have finished:

   ```bash
   cat test/controller.log
   ```

## Zitadel Instance Setup

1. Create an Actions V2 target that points to the `create-user-webhook` endpoint:

`https://localhost:8888/v1/actions/create-user-account`

1. Create an Actions V2 action based on your UI type:
   - **Zitadel UI**: Configure the event `user.human.selfregistered` with the previously created target
   - **Zitadel Custom UI**: Configure the event `user.human.added` with the previously created target
