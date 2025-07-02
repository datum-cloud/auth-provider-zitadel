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


