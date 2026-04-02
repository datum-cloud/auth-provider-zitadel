#!/bin/bash
# kubectl plugin to delete a machine account key
# Install: cp delete-machine-account-key.sh ~/.local/share/kubectl-plugins/kubectl-delete_machine_account_key
# Usage: ./delete-machine-account-key.sh

set -euo pipefail

# ============================================================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================================================

# The project ID (organization ID in Zitadel)
PROJECT_ID="single"

# The key ID to delete (from Zitadel)
KEY_ID="366525074351587355"

# API server URL (leave empty to use kubectl proxy on localhost:8080)
API_SERVER_URL="http://localhost:8080"

# ============================================================================
# SCRIPT - NO NEED TO MODIFY BELOW
# ============================================================================

if [ -z "$KEY_ID" ]; then
    echo "Error: KEY_ID must be set"
    exit 1
fi

echo "Deleting machine account key..."
echo "  Project ID: $PROJECT_ID"
echo "  Key ID: $KEY_ID"
echo ""

# Confirm deletion
read -p "Are you sure you want to delete this key? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

echo "Sending delete request to $API_SERVER_URL..."

# Build the resource name in format: {machineAccountName}:{keyID}
# Using ":" as separator to avoid RBAC sub-resource issues with "/"
RESOURCE_NAME="$KEY_ID"

# Make the request - the resource name contains both machineAccountName and keyID
RESPONSE=$(curl -s -X DELETE \
  "$API_SERVER_URL/apis/identity.miloapis.com/v1alpha1/machineaccountkeys/$RESOURCE_NAME" \
  -H "Content-Type: application/json" \
  -H "Impersonate-User: admin" \
  -H "Impersonate-Extra-project: $PROJECT_ID")

# Check if the response is valid JSON
if echo "$RESPONSE" | jq . >/dev/null 2>&1; then
    STATUS=$(echo "$RESPONSE" | jq -r '.status // "Success"')

    if [ "$STATUS" = "Success" ]; then
        echo "✓ Key deleted successfully!"
    else
        echo "Response:"
        echo "$RESPONSE" | jq .

        # Check if it's an error status
        if [ "$STATUS" = "Failure" ]; then
            echo ""
            echo "Error: $(echo "$RESPONSE" | jq -r '.message // "Unknown error"')"
            exit 1
        fi
    fi
else
    echo "Error response:"
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    exit 1
fi
