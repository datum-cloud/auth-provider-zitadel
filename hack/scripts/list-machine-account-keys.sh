#!/bin/bash
# kubectl plugin to list machine account keys
# Install: cp list-machine-account-keys.sh ~/.local/share/kubectl-plugins/kubectl-list_machine_account_keys
# Usage: ./list-machine-account-keys.sh

set -euo pipefail

# ============================================================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================================================

# The project ID (organization ID in Zitadel)
PROJECT_ID="single"

# The machine account username (must exist in the project's Zitadel organization)
# Leave empty to list all keys in the project
MACHINE_ACCOUNT_NAME="6f07d882-5f3d-45e7-8d23-4131c2508448@default.single.iam.miloapis.com"

# API server URL (leave empty to use kubectl proxy on localhost:8080)
API_SERVER_URL="http://localhost:8080"

# ============================================================================
# SCRIPT - NO NEED TO MODIFY BELOW
# ============================================================================

echo "Listing machine account keys..."
echo "  Project ID: $PROJECT_ID"
if [ -n "$MACHINE_ACCOUNT_NAME" ]; then
    echo "  Machine Account: $MACHINE_ACCOUNT_NAME"
fi
echo ""

echo "Sending request to $API_SERVER_URL..."

# Build the URL with optional fieldSelector query parameter
URL="$API_SERVER_URL/apis/identity.miloapis.com/v1alpha1/machineaccountkeys"
if [ -n "$MACHINE_ACCOUNT_NAME" ]; then
    URL="$URL?fieldSelector=spec.machineAccountName=$MACHINE_ACCOUNT_NAME"
fi

# Make the request
RESPONSE=$(curl -s -X GET \
  "$URL" \
  -H "Content-Type: application/json" \
  -H "Impersonate-User: admin" \
  -H "Impersonate-Extra-project: $PROJECT_ID")

# Check if the response is valid JSON
if echo "$RESPONSE" | jq . >/dev/null 2>&1; then
    ITEMS=$(echo "$RESPONSE" | jq '.items // []')
    COUNT=$(echo "$ITEMS" | jq 'length')

    echo "Found $COUNT key(s):"
    echo ""

    if [ "$COUNT" -gt 0 ]; then
        echo "$ITEMS" | jq -r '.[] | "\(.metadata.name) | Key ID: \(.status.authProviderKeyID)"'
        echo ""
        echo "Full response:"
        echo "$RESPONSE" | jq .
    else
        echo "No keys found."
    fi
else
    echo "Error response:"
    echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
    exit 1
fi
