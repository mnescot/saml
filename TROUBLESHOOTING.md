# SAML Plugin Troubleshooting Guide

This guide provides solutions to common issues when configuring and using the SAML plugin with Microsoft Entra ID (Azure AD) and other identity providers.

## Common Issues and Solutions

### 1. Authentication Fails - User Redirected to Default Login

**Symptoms:**
- After successful SAML authentication with IdP, user is redirected to `/login`
- No error messages visible to user

**Possible Causes & Solutions:**

#### A. User Account Not Provisioned
**Solution:** Enable automatic user provisioning in `conf/settings.json`:
```json
"user_provisioning": {
    "enabled": true,
    "create_missing_users": true,
    "default_role": "blue"
}
```

#### B. Incorrect Role Mapping
**Solution:** Check that the Caldera role determined from SAML attributes exists. Review logs for:
```
Determined Caldera role: <role_name>
```
Ensure this role is valid (admin, red, blue, user).

#### C. Missing Email Attribute
**Solution:** Verify your IdP sends the email claim. Check logs for:
```
Extracted user info: {...}
```
If email is missing, configure the correct attribute in `user_provisioning.email_attribute`.

### 2. Session Not Established

**Symptoms:**
- User authenticates but session cookie (`API_SESSION`) is not set
- User is not logged in after SAML redirect

**Solution:**
Ensure `aiohttp_security` is properly configured in your Caldera instance. The plugin now uses the standard `remember()` function from `aiohttp_security`.

Check Caldera's main configuration has session encryption key configured.

### 3. ACS Endpoint Not Found (404)

**Symptoms:**
- IdP shows error posting to ACS URL
- Caldera returns 404 for `/saml/acs`

**Solutions:**

#### A. Plugin Not Enabled
Verify the plugin is listed in Caldera's main configuration:
```yaml
plugins:
  - saml
```

#### B. Wrong URL in IdP
Ensure IdP is configured with correct ACS URL:
- Modern configuration: `https://your-server.com/saml/acs`
- Legacy configuration: `https://your-server.com/saml`

### 4. Signature Verification Failures

**Symptoms:**
- Error: "Error when processing SAML response: ..."
- Logs show signature validation errors

**Solutions:**

#### A. Certificate Mismatch
Ensure the X.509 certificate in `conf/settings.json` matches the current certificate from your IdP.

For Entra ID:
1. Go to Enterprise Applications → Your App → Single sign-on
2. Download the Base64 certificate
3. Copy certificate content (without headers) to `idp.x509cert` in settings

#### B. Clock Skew
Ensure server time is synchronized with NTP. SAML assertions have strict time windows.

```bash
# Check system time
timedatectl status

# Sync time
sudo systemctl restart systemd-timesyncd
```

#### C. Security Settings Too Strict
If using `strict: true`, try temporarily setting to `false` for testing:
```json
{
    "strict": false,
    "debug": true,
    ...
}
```

### 5. Attribute Claims Not Received

**Symptoms:**
- User provisions with default role instead of assigned role
- Email or name not captured

**Solution:**

#### For Entra ID:
1. Go to Enterprise Applications → Your App → Single sign-on → Attributes & Claims
2. Ensure these claims exist:
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`
   - (Optional) `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`

3. Verify claim values are populated:
   - Email → `user.mail` or `user.userprincipalname`
   - Name → `user.displayname`

4. Check that users assigned to the application have these attributes populated in Entra ID

### 6. Metadata Generation Fails

**Symptoms:**
- `/saml/metadata` returns 500 error
- Error: "SAML metadata validation failed"

**Solution:**
Check your `conf/settings.json` for:
- Valid SP entity ID (must be proper URL)
- Valid ACS URL (must be proper URL)
- Correct binding specifications

Example valid configuration:
```json
{
    "sp": {
        "entityId": "https://your-server.com",
        "assertionConsumerService": {
            "url": "https://your-server.com/saml/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        }
    }
}
```

### 7. Multiple Roles/Groups Not Working

**Symptoms:**
- User has multiple roles in IdP but only one is considered
- Group-based role assignment not working

**Solution:**

#### A. Enable Group Claims in Entra ID
1. Go to Enterprise Applications → Your App → Single sign-on → Attributes & Claims
2. Add a group claim with appropriate filter
3. Note: Entra ID limits group claims to 150 groups per token

#### B. Configure Group Mappings
In `conf/user_mapping.json`:
```json
{
    "group_mappings": {
        "12345678-1234-1234-1234-123456789abc": "admin",
        "87654321-4321-4321-4321-cba987654321": "red"
    }
}
```

Use the Object ID of the groups from Entra ID.

## Debugging Tips

### Enable Debug Logging

In `conf/settings.json`:
```json
{
    "debug": true,
    ...
}
```

### Check Caldera Logs
```bash
# If running with Docker
docker logs caldera_server

# If running directly
tail -f logs/caldera.log
```

Look for messages containing:
- `SAML`
- `saml_svc`
- `Handling SAML`
- `authenticated via SAML`

### Test SAML Response Manually

Use a SAML decoder tool:
1. Capture the SAMLResponse parameter from browser developer tools
2. Decode at https://www.samltool.com/decode.php
3. Verify:
   - Assertion is signed
   - Attributes are present
   - NameID format matches configuration
   - Audience matches your SP Entity ID
   - ACS URL matches your configuration

### Verify Plugin Registration
Check that routes are registered:
```python
# In Caldera Python console or logs
app.router._resources
```

Should show `/saml/acs`, `/saml/login`, etc.

## Entra ID Specific Issues

### Issue: "AADSTS50011: The reply URL does not match"

**Solution:**
Ensure the Reply URL in Entra ID exactly matches the ACS URL in your settings:
- Entra ID Reply URL: `https://your-server.com/saml/acs`
- Settings ACS URL: `https://your-server.com/saml/acs`

URLs must match exactly including:
- Protocol (http vs https)
- Domain
- Port (if non-standard)
- Path

### Issue: "AADSTS700016: Application not found"

**Solution:**
Verify:
1. Application ID (Client ID) is correct
2. Application is enabled
3. Users are assigned to the application
4. Application has been saved after configuration changes

### Issue: User Has No Mail Attribute

**Solution:**
If user accounts don't have email addresses populated:

Option 1 - Use UPN as email:
```json
{
    "user_provisioning": {
        "email_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    }
}
```

Option 2 - Configure claim transformation in Entra ID to populate email from UPN

## Getting Additional Help

1. Check the [python3-saml documentation](https://github.com/onelogin/python3-saml)
2. Review [Entra ID SAML documentation](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol)
3. Enable debug mode and capture full logs
4. Check that xmlsec native libraries are properly installed

## Configuration Validation Checklist

Use this checklist to verify your configuration:

- [ ] Plugin enabled in Caldera configuration
- [ ] `conf/settings.json` exists and is valid JSON
- [ ] SP Entity ID matches Caldera server URL
- [ ] ACS URL configured in both IdP and settings.json
- [ ] IdP Entity ID matches from IdP metadata
- [ ] SSO URL matches from IdP metadata
- [ ] X.509 certificate is current and correctly formatted
- [ ] Required attribute claims configured in IdP
- [ ] User provisioning enabled (if using automatic provisioning)
- [ ] Test user is assigned to application in IdP
- [ ] Server time is synchronized
- [ ] HTTPS is configured (recommended for production)
- [ ] Login handler module configured in Caldera config:
  ```yaml
  auth.login.handler.module: plugins.saml.app.saml_login_handler
  ```
