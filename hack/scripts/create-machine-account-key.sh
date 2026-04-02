#!/bin/bash
# kubectl plugin to create a machine account key
# Install: cp create-machine-account-key.sh ~/.local/share/kubectl-plugins/kubectl-create_machine_account_key
# Usage: kubectl create-machine-account-key
#        or: ./create-machine-account-key.sh

set -euo pipefail

# ============================================================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================================================

# The project ID (organization ID in Zitadel)
PROJECT_ID="single"

# API server URL (leave empty to use kubectl proxy on localhost:8080)
API_SERVER_URL="http://localhost:8080"

# ============================================================================
# SCRIPT - MODIFY THE PAYLOAD BELOW WITH YOUR VALUES
# ============================================================================

echo "Creating machine account key..."
echo "  Project ID: $PROJECT_ID"
echo "  API Server: $API_SERVER_URL"
echo ""

echo "Sending request to $API_SERVER_URL..."

# Make the request with hardcoded payload
# Modify the spec fields as needed:
# - machineAccountUserName: required
# - publicKey: optional (PEM format, RSA or ECDSA - if omitted, Zitadel generates one)
# - expirationDate: optional (ISO 8601 format, e.g., "2029-12-31T23:59:59Z" - if omitted, Zitadel uses default)

# Build the JSON payload with public key
# Note: expirationDate is optional. If omitted, Zitadel uses the default from configuration.
#
PAYLOAD=$(cat <<'PAYLOAD_EOF'
{
  "apiVersion": "identity.miloapis.com/v1alpha1",
  "kind": "MachineAccountKey",
  "metadata": {
    "name": "key-TIMESTAMP"
  },
  "spec": {
    "machineAccountUserName": "example-service-account@single.identity.miloapis.com"
  }
}
PAYLOAD_EOF
)

# Replace timestamp placeholder
PAYLOAD="${PAYLOAD//TIMESTAMP/$(date +%s)}"

RESPONSE=$(curl -s -X POST \
  "$API_SERVER_URL/apis/identity.miloapis.com/v1alpha1/machineaccountkeys" \
  -H "Content-Type: application/json" \
  -H "Impersonate-User: admin" \
  -H "Impersonate-Extra-project: $PROJECT_ID" \
  -d "$PAYLOAD")

# Check if the response is valid JSON
if echo "$RESPONSE" | jq . >/dev/null 2>&1; then
    echo "Success! Response:"
    echo "$RESPONSE" | jq .

    # Extract and display the key ID and private key
    KEY_ID=$(echo "$RESPONSE" | jq -r '.status.authProviderKeyID // empty')
    PRIVATE_KEY=$(echo "$RESPONSE" | jq -r '.status.privateKey // empty')

    if [ -n "$KEY_ID" ]; then
        echo ""
        echo "Key ID: $KEY_ID"
    fi

    if [ -n "$PRIVATE_KEY" ]; then
        echo ""
        echo "Private Key (save this safely):"
        echo "$PRIVATE_KEY" | jq .
    fi
else
    echo "Error response:"
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    exit 1
fi
