# SAML User Mapping Configuration

This file explains how to configure `user_mapping.json` to map SAML users to specific Caldera roles.

## Overview

The `user_mapping.json` file allows you to override the default role assigned in `settings.json` by mapping SAML attributes to specific Caldera roles.

## How Role Assignment Works

When a user authenticates via SAML, the system determines their Caldera role using this priority order:

1. **Admin Roles** (from `settings.json`) - Checked first
2. **Admin Groups** (from `settings.json`) - Checked second
3. **Role Mappings** (from `user_mapping.json`) - Maps SAML roles to Caldera roles
4. **Group Mappings** (from `user_mapping.json`) - Maps SAML groups to Caldera roles
5. **Email Domain Mappings** (from `user_mapping.json`) - Maps email domains to Caldera roles
6. **Default Role** (from `settings.json`) - Used if no matches found

## Caldera Roles

Available Caldera roles:
- `admin` - Full access (red + blue privileges)
- `red` - Offensive/red team operations
- `blue` - Defensive/blue team operations
- `user` - Read-only access

## Configuration Examples

### Role Mappings
Maps SAML role attributes to Caldera roles. Case-insensitive matching.

```json
"role_mappings": {
  "admin": ["Admin", "Administrator", "Global Administrator"],
  "red": ["Red Team", "Penetration Tester"],
  "blue": ["Blue Team", "SOC Analyst", "Defender"],
  "user": ["User", "Viewer"]
}
```

**Example:** If a user has SAML role "SOC Analyst", they get Caldera role "blue".

### Group Mappings
Maps SAML group attributes to Caldera roles. Exact match required.

```json
"group_mappings": {
  "Caldera-Admins": "admin",
  "Caldera-Red-Team": "red",
  "Caldera-Blue-Team": "blue"
}
```

**Example:** If a user is in SAML group "Caldera-Red-Team", they get Caldera role "red".

### Email Domain Mappings
Maps email domains to Caldera roles.

```json
"email_domain_mappings": {
  "admin.example.com": "admin",
  "contractor.example.com": "user"
}
```

**Example:** If a user's email is "john@contractor.example.com", they get Caldera role "user".

## Finding Your SAML Attributes

To determine what attributes your IdP sends, check the Caldera logs after authentication:

```bash
# Look for log entries showing extracted user info
grep "Extracted user info" /var/log/caldera/caldera.log
```

### Common SAML Attribute Names

**Microsoft Entra ID (Azure AD):**
- Email: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
- Name: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`
- Role: `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`
- Groups: `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`

**Okta:**
- Email: `email`
- Name: `displayName`
- Groups: `groups`

**Generic SAML:**
Attributes vary by IdP. Check your IdP documentation or SAML response.

## Configuration Files Location

When deployed to Caldera, these files should be at:
```
plugins/saml/conf/settings.json
plugins/saml/conf/user_mapping.json
```

## Testing Your Configuration

1. Deploy the updated configuration files
2. Restart Caldera
3. Authenticate via SAML
4. Check Caldera logs for role assignment:
   ```bash
   grep "Determined Caldera role" /var/log/caldera/caldera.log
   ```

## Example: Entra ID Setup

For Microsoft Entra ID with App Roles:

**In Entra ID:**
1. Create App Roles in your Enterprise Application:
   - Name: "Caldera Admin", Value: "Admin"
   - Name: "Caldera Red Team", Value: "Red Team"
   - Name: "Caldera Blue Team", Value: "Blue Team"
2. Assign users to these App Roles
3. Configure the role claim in Token Configuration

**In user_mapping.json:**
```json
{
  "role_mappings": {
    "admin": ["Admin"],
    "red": ["Red Team"],
    "blue": ["Blue Team"]
  },
  "group_mappings": {},
  "email_domain_mappings": {}
}
```

**In settings.json:**
```json
{
  ...
  "user_provisioning": {
    "enabled": true,
    "default_role": "user",
    "role_attribute": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
  }
}
```

## Troubleshooting

**Users getting default role instead of expected role:**
- Check SAML attributes being sent (see logs)
- Verify attribute names match in `settings.json`
- Ensure role/group names match exactly (roles are case-insensitive, groups/domains are case-sensitive)
- Check priority order - admin roles/groups override mappings

**Users not being created:**
- Verify `"enabled": true` in `settings.json` user_provisioning
- Verify `"create_missing_users": true` in settings.json
- Check logs for provisioning errors

**Auto-redirect not working:**
- Ensure `hook.py` calls `await saml_svc.set_saml_login_handler()`
- Restart Caldera after changes
