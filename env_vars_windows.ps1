$env:PORT="8080"
$env:DB_NAME="authnull_dev"
$env:DB_USER="kloudone"
$env:DB_PASSWORD="authnull@kloudone@2007"
$env:DB_HOST="localhost"
$env:DB_PORT="5430"
$env:DB_SCHEMA="did"
$env:JWT_SECRET="7f9b2a3c8e6d4f1b9a0c3e7d2f5b8a1c9e3d6f2a4b7c8e0d1f9a2b3c"
$env:LOG_LEVEL="info"
$env:GIN_MODE="debug"
$env:AUTH_MANAGER_URL="http://localhost:7469"

# WebAuthn Configuration
$env:WEBAUTHN_RP_NAME="authnull.dev"
$env:WEBAUTHN_RP_ID="localhost"
$env:WEBAUTHN_ORIGIN="http://localhost:5501"
$env:ENVIRONMENT="development"

# Optional WebAuthn settings
$env:WEBAUTHN_TIMEOUT="60000"
$env:WEBAUTHN_DEBUG="true"

$env:TOTP_ENCRYPTION_KEY="6AB33320B8A8E177655F72CEDDAE56593D045BE5A47416FDE7C7CF983D5B80D6"

# $env:TWILIO_ACCOUNT_SID="ACae107f79839c9dfca676307c7ecb4ddb"
# $env:TWILIO_AUTH_TOKEN="fec14070a514a0bd3c3a03332557b275"
# $env:TWILIO_PHONE="+18554251760%"

$env:TWILIO_ACCOUNT_SID="ACae107f79839c9dfca676307c7ecb4ddb"
$env:TWILIO_AUTH_TOKEN="83ab52ad796cfd96f3ef2ecb66142ead"
$env:TWILIO_PHONE="+18554251760%"


# CORS Configuration (for multiple frontend origins)
$env:CORS_ALLOWED_ORIGINS="http://localhost:5501,http://localhost:3000,http://127.0.0.1:5501"
$env:CORS_ALLOWED_METHODS="GET,POST,PUT,DELETE,OPTIONS"
$env:CORS_ALLOWED_HEADERS="Content-Type,Authorization,X-Requested-With"

# SMTP host configurations
$env:SMTP_HOST="smtp.elasticemail.com"
$env:SMTP_PORT="2525"
$env:SMTP_FROM="support@authnull.com"
$env:SMTP_PASSWORD="E2AA24DAB22D3996F76B2DCA9F2BFCEDD478"

echo "Environment variables set for Windows environment."
echo "WebAuthn configured for:"
echo "  - RP Name: $env:WEBAUTHN_RP_NAME"
echo "  - RP ID: $env:WEBAUTHN_RP_ID" 
echo "  - Origin: $env:WEBAUTHN_ORIGIN"
echo "  - Server Port: $env:SERVER_PORT"

# To run this script, use the command: .\env_vars_windows.ps1
# Ensure to run it in a PowerShell session with appropriate permissions