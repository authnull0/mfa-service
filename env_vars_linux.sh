#!/bin/bash

# Database Configuration
export PORT="8080"
export DB_NAME="development"
export DB_USER="kloudone"
export DB_PASSWORD="authnull@kloudone@2007"
export DB_HOST="postgresql.authnull-io.svc.cluster.local"
export DB_PORT="5432"
export DB_SCHEMA="did"
export JWT_SECRET="7f9b2a3c8e6d4f1b9a0c3e7d2f5b8a1c9e3d6f2a4b7c8e0d1f9a2b3c"
export LOG_LEVEL="info"
export GIN_MODE="debug"
export AUTH_MANAGER_URL="http://localhost:7469"

# WebAuthn Configuration
export WEBAUTHN_RP_NAME="AuthSec WebAuthn Service"
export WEBAUTHN_RP_ID="localhost"
export WEBAUTHN_ORIGIN="http://localhost:5501"
export ENVIRONMENT="development"

# Optional WebAuthn settings
export WEBAUTHN_TIMEOUT="60000"
export WEBAUTHN_DEBUG="true"

# TOTP Configuration
export TOTP_ENCRYPTION_KEY="6AB33320B8A8E177655F72CEDDAE56593D045BE5A47416FDE7C7CF983D5B80D6"

export TWILIO_ACCOUNT_SID=ACae107f79839c9dfca676307c7ecb4ddb
export TWILIO_AUTH_TOKEN=fec14070a514a0bd3c3a03332557b275
export TWILIO_PHONE=+18554251760%

# CORS Configuration (for multiple frontend origins)
export CORS_ALLOWED_ORIGINS="http://localhost:5501,http://localhost:3000,http://127.0.0.1:5501"
export CORS_ALLOWED_METHODS="GET,POST,PUT,DELETE,OPTIONS"
export CORS_ALLOWED_HEADERS="Content-Type,Authorization,X-Requested-With"

# SMTP host configurations
export SMTP_HOST="smtp.elasticemail.com"
export SMTP_PORT="2525"
export SMTP_FROM="support@authnull.com"
export SMTP_PASSWORD="E2AA24DAB22D3996F76B2DCA9F2BFCEDD478"

echo "Environment variables set for Unix/Linux environment."
echo "WebAuthn configured for:"
echo "  - RP Name: $WEBAUTHN_RP_NAME"
echo "  - RP ID: $WEBAUTHN_RP_ID" 
echo "  - Origin: $WEBAUTHN_ORIGIN"
echo "  - Server Port: $SERVER_PORT"



# Optional: Make variables available to subprocesses
set -a
