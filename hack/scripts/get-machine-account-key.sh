#!/bin/bash
# kubectl plugin to get a specific machine account key
# Install: cp get-machine-account-key.sh ~/.local/share/kubectl-plugins/kubectl-get_machine_account_key
# Usage: ./get-machine-account-key.sh <KEY_ID>

set -euo pipefail

# ============================================================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================================================

# The project ID (organization ID in Zitadel)
PROJECT_ID="single"

# API server URL (leave empty to use kubectl proxy on localhost:8080)
API_SERVER_URL="http://localhost:8080"

# ============================================================================
# SCRIPT - NO NEED TO MODIFY BELOW
# ============================================================================

# Check if KEY_ID argument is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <KEY_ID>"
    echo ""
    echo "Example: $0 366667937748090903"
    exit 1
fi

KEY_ID="$1"

echo "Getting machine account key..."
echo "  Project ID: $PROJECT_ID"
echo "  Key ID: $KEY_ID"
echo ""

echo "Sending request to $API_SERVER_URL..."

# Make the request
RESPONSE=$(curl -s -X GET \
  "$API_SERVER_URL/apis/identity.miloapis.com/v1alpha1/machineaccountkeys/$KEY_ID" \
  -H "Content-Type: application/json" \
  -H "Impersonate-User: admin" \
  -H "Impersonate-Extra-project: $PROJECT_ID")

# Check if the response is valid JSON
if echo "$RESPONSE" | jq . >/dev/null 2>&1; then
    KIND=$(echo "$RESPONSE" | jq -r '.kind // "Unknown"')

    if [ "$KIND" = "MachineAccountKey" ]; then
        echo "Found key:"
        echo ""
        echo "$RESPONSE" | jq '{
            name: .metadata.name,
            machineAccount: .spec.machineAccountUserName,
            keyID: .status.authProviderKeyID,
            created: .metadata.creationTimestamp,
            expires: .spec.expirationDate
        }'
    else
        echo "Error: Key not found or invalid response"
        echo ""
        echo "Full response:"
        echo "$RESPONSE" | jq .
        exit 1
    fi
else
    echo "Error response:"
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    exit 1
fi
