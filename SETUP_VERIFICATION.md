# SAML Plugin Setup Verification

This script helps verify that your SAML plugin is configured correctly.

## Quick Setup Checklist

Run through this checklist before starting Caldera:

### 1. Settings File Exists
```bash
ls -la plugins/saml/conf/settings.json
```
**Expected**: File exists and is readable

**If missing**:
```bash
cd plugins/saml
cp conf/sample_entra_id.json conf/settings.json
# Then edit settings.json with your IdP details
```

### 2. Settings File is Valid JSON
```bash
python3 -c "import json; json.load(open('plugins/saml/conf/settings.json'))" && echo "✓ Valid JSON"
```
**Expected**: "✓ Valid JSON"

**If error**: Check for syntax errors, missing commas, unescaped quotes

### 3. Required Settings Present
```bash
python3 << 'EOF'
import json
with open('plugins/saml/conf/settings.json') as f:
    config = json.load(f)

required = ['sp', 'idp', 'security']
missing = [k for k in required if k not in config]

if missing:
    print(f"✗ Missing required sections: {missing}")
else:
    print("✓ All required sections present")

    # Check SP config
    if 'entityId' in config.get('sp', {}):
        print(f"✓ SP Entity ID: {config['sp']['entityId']}")
    else:
        print("✗ Missing sp.entityId")

    if 'url' in config.get('sp', {}).get('assertionConsumerService', {}):
        print(f"✓ ACS URL: {config['sp']['assertionConsumerService']['url']}")
    else:
        print("✗ Missing sp.assertionConsumerService.url")

    # Check IdP config
    if 'entityId' in config.get('idp', {}):
        print(f"✓ IdP Entity ID: {config['idp']['entityId']}")
    else:
        print("✗ Missing idp.entityId")

    if 'url' in config.get('idp', {}).get('singleSignOnService', {}):
        print(f"✓ IdP SSO URL: {config['idp']['singleSignOnService']['url']}")
    else:
        print("✗ Missing idp.singleSignOnService.url")

    if 'x509cert' in config.get('idp', {}):
        cert = config['idp']['x509cert']
        if cert and cert != "base64-encoded certificate data":
            print(f"✓ X.509 Certificate configured ({len(cert)} chars)")
        else:
            print("✗ X.509 Certificate not configured (still placeholder)")
    else:
        print("✗ Missing idp.x509cert")

    # Check user provisioning
    if 'user_provisioning' in config:
        up = config['user_provisioning']
        print(f"✓ User provisioning enabled: {up.get('enabled', False)}")
        if up.get('enabled'):
            print(f"  - Create missing users: {up.get('create_missing_users', True)}")
            print(f"  - Default role: {up.get('default_role', 'blue')}")
    else:
        print("⚠ User provisioning not configured (will use defaults)")
EOF
```

### 4. Caldera Configuration
Check your Caldera main config file (usually `conf/default.yml` or similar):

```yaml
# Should include:
plugins:
  - saml

auth:
  login:
    handler:
      module: plugins.saml.app.saml_login_handler
```

### 5. IdP Configuration Matches
Verify your IdP (Entra ID) configuration matches:

**In Entra ID Enterprise Application:**
- Reply URL (ACS): Should match `sp.assertionConsumerService.url` in settings.json
- Identifier (Entity ID): Should match `sp.entityId` in settings.json

**In settings.json:**
- `idp.entityId`: Should be `https://sts.windows.net/YOUR-TENANT-ID/`
- `idp.singleSignOnService.url`: Should be `https://login.microsoftonline.com/YOUR-TENANT-ID/saml2`
- `idp.x509cert`: Should be the current certificate from Entra ID (Base64, without headers)

### 6. Test SAML Configuration Syntax
```bash
python3 << 'EOF'
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import json

try:
    with open('plugins/saml/conf/settings.json') as f:
        config = json.load(f)

    settings = OneLogin_Saml2_Settings(config)
    errors = settings.check_settings()

    if errors:
        print("✗ SAML configuration has errors:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("✓ SAML configuration is valid")

except Exception as e:
    print(f"✗ Error validating SAML config: {e}")
EOF
```

## Common Issues and Solutions

### Issue: "SAML configuration not loaded"
**Cause**: settings.json doesn't exist or has wrong path
**Solution**:
```bash
cd plugins/saml
ls -la conf/settings.json  # Verify it exists
# If not, copy from sample
cp conf/sample_entra_id.json conf/settings.json
```

### Issue: "SAML service not found in service registry"
**Cause**: Plugin not enabled in Caldera config
**Solution**: Add `saml` to plugins list in Caldera config and restart

### Issue: "Not redirecting to IdP"
**Cause**: Login handler not set
**Solution**: Add to Caldera config:
```yaml
auth.login.handler.module: plugins.saml.app.saml_login_handler
```

### Issue: "Session not established after SAML login"
**Causes**:
1. User doesn't exist and provisioning disabled
2. Role mismatch

**Solution**:
Enable user provisioning in settings.json:
```json
"user_provisioning": {
    "enabled": true,
    "create_missing_users": true,
    "default_role": "blue"
}
```

### Issue: "Signature verification failed"
**Causes**:
1. Wrong certificate in settings.json
2. Certificate expired/rotated in IdP

**Solution**:
1. Go to Entra ID → Enterprise Applications → Your App → Single sign-on
2. Download current Base64 certificate
3. Copy content (without BEGIN/END headers) to `idp.x509cert` in settings.json

## Log Messages to Look For

**Successful Startup:**
```
INFO - Enabling SAML plugin...
INFO - SAML configuration loaded successfully from .../conf/settings.json
INFO - SAML service registered successfully
INFO - SAML plugin enabled successfully
```

**Successful Login:**
```
DEBUG - Handling SAML login redirect
DEBUG - Redirecting to IdP: https://login.microsoftonline.com/...
DEBUG - Processing SAML response from IdP
INFO - User "user@example.com" (...) authenticated via SAML as "blue"
DEBUG - Session established for user "blue"
```

**Configuration Errors:**
```
ERROR - SAML configuration file not found: .../conf/settings.json
ERROR - Please create .../conf/settings.json with valid SAML settings
```

**Service Registration Errors:**
```
ERROR - SAML service failed to register in service registry!
ERROR - SAML authentication will not work. Check configuration.
```

## Debugging Steps

1. **Check Caldera logs** for SAML-related messages
2. **Enable debug mode** in settings.json: `"debug": true`
3. **Check browser developer tools** for redirects and cookies
4. **Decode SAML response** at https://www.samltool.com/decode.php to verify attributes
5. **Verify network connectivity** to IdP SSO URL
6. **Check clock synchronization** (SAML assertions are time-sensitive)

## Getting Help

If issues persist:

1. Review `TROUBLESHOOTING.md` for detailed solutions
2. Check Caldera logs with debug logging enabled
3. Verify all steps in this checklist are completed
4. Ensure IdP configuration matches exactly

## Testing Sequence

1. Start Caldera with SAML plugin enabled
2. Check logs for successful plugin loading
3. Navigate to Caldera URL in browser
4. Should redirect to IdP login
5. Login with IdP credentials
6. Should redirect back to Caldera
7. Should be logged in with session established
8. Check logs for authentication success

If any step fails, check corresponding section above.
