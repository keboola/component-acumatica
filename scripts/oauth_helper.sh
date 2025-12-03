#!/bin/bash

# OAuth Authorization Code Flow Helper Script
# This script helps you get OAuth tokens from Acumatica

set -e

echo "=========================================="
echo "Acumatica OAuth Authorization Helper"
echo "=========================================="
echo

# Prompt for configuration
read -p "Enter Acumatica URL (e.g., http://34.31.156.162/AcumaticaERP1): " ACUMATICA_URL
read -p "Enter Client ID (e.g., 392B04F6-6CA4-43FA-48D9-45A6E6DF5579@Company): " CLIENT_ID
read -sp "Enter Client Secret: " CLIENT_SECRET
echo
read -p "Enter Redirect URI (e.g., http://localhost:8080/callback): " REDIRECT_URI

# Remove trailing slash from URL if present
ACUMATICA_URL="${ACUMATICA_URL%/}"

# URL encode the redirect URI (using printf to avoid trailing newline)
ENCODED_REDIRECT_URI=$(printf '%s' "$REDIRECT_URI" | jq -sRr @uri)

echo

# Generate authorization URL
AUTH_URL="${ACUMATICA_URL}/identity/connect/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${ENCODED_REDIRECT_URI}&scope=api%20offline_access"

echo
echo "=========================================="
echo "STEP 1: Get Authorization Code"
echo "=========================================="
echo
echo "Open this URL in your browser:"
echo
echo "$AUTH_URL"
echo
echo "After logging in, you'll be redirected to something like:"
echo "${REDIRECT_URI}?code=AUTHORIZATION_CODE_HERE"
echo
read -sp "Enter the authorization code from the URL: " AUTH_CODE
echo

echo
echo "=========================================="
echo "STEP 2: Exchange Code for Tokens"
echo "=========================================="
echo

# Exchange authorization code for tokens
TOKEN_URL="${ACUMATICA_URL}/identity/connect/token"

echo "Requesting tokens..."
RESPONSE=$(curl -s -X POST "$TOKEN_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "code=${AUTH_CODE}" \
  -d "redirect_uri=${REDIRECT_URI}")

echo
echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"

# Try to extract tokens
ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token // empty' 2>/dev/null)
REFRESH_TOKEN=$(echo "$RESPONSE" | jq -r '.refresh_token // empty' 2>/dev/null)

if [ -n "$ACCESS_TOKEN" ]; then
    echo
    echo "=========================================="
    echo "SUCCESS! Tokens retrieved"
    echo "=========================================="
    echo
    echo "Access Token: $ACCESS_TOKEN"
    echo
    echo "Refresh Token: $REFRESH_TOKEN"
    echo
    echo "You can now paste these tokens into your config.json file."
else
    echo
    echo "=========================================="
    echo "ERROR: Failed to get tokens"
    echo "=========================================="
    echo
    echo "Please check the error message above."
fi
