# CRITICAL FIX: User Object Structure - Resolves 500 Errors

## Problem Summary

After SAML authentication succeeded, users experienced 500 Internal Server Errors when accessing the Caldera UI. The authentication completed successfully (logs showed "admin logging in"), but subsequent API calls to render UI components failed with generic 500 errors.

## Root Cause

The SAML plugin was creating **dictionary objects** in `auth_svc.user_map` when it should have been creating **User namedtuples**.

### What Caldera Expects

```python
from collections import namedtuple
User = namedtuple('User', ['username', 'password', 'permissions'])

# Example:
user_map['mnescot@fredhutch.org'] = User(
    username='mnescot@fredhutch.org',
    password='hashed_password',
    permissions=('admin', 'app')
)
```

### What SAML Plugin Was Creating (BROKEN)

```python
# BROKEN: Dictionary, not User namedtuple
auth_svc.user_map['admin'] = {
    'password': 'randomPassword123',
    'privileges': ['red', 'blue'],
    'created_via_saml': True,
    'saml_email': 'mnescot@fredhutch.org',
    # ...
}
```

### Why This Caused 500 Errors

When the Caldera UI tried to access user properties:

```python
username = user.username  # AttributeError: 'dict' object has no attribute 'username'
```

This `AttributeError` was caught by Caldera's exception handlers and returned as a generic 500 error to the browser, with no detailed error logged.

## The Fix

### Changes to `_provision_user()` (lines 246-297)

**BEFORE (BROKEN):**
```python
# Check if user exists
user_exists = caldera_role in auth_svc.user_map

if not user_exists and create_missing:
    # Create new user
    self.log.info(f'Creating new user: {caldera_role} for {email}')

    # Define privileges based on role
    privileges = self._get_role_privileges(caldera_role)

    # BROKEN: Creates dictionary, not User namedtuple
    auth_svc.user_map[caldera_role] = {
        'password': self._generate_temp_password(),
        'privileges': privileges,  # WRONG: list instead of tuple
        # ...
    }
```

**AFTER (FIXED):**
```python
# Use email as username (key in user_map)
username = email

# Check if user exists by username (email), not role
user_exists = username in auth_svc.user_map

if not user_exists and create_missing:
    # Create new user using Caldera's create_user method
    self.log.info(f'Creating new user: {username} with role {caldera_role}')

    password = self._generate_temp_password()

    # FIXED: Use auth_svc.create_user() to ensure proper User namedtuple structure
    # This automatically creates: user_map[username] = User(username, password, (group, 'app'))
    await auth_svc.create_user(username, password, caldera_role)
```

### Changes to `_authenticate_user()` (lines 321-340)

**BEFORE (BROKEN):**
```python
if caldera_role in auth_svc.user_map:
    # BROKEN: Uses role as key, passes role to handle_successful_login
    self.log.info(f'User "{display_name}" ({email}) authenticated via SAML as "{caldera_role}"')
    await auth_svc.handle_successful_login(request, caldera_role)
```

**AFTER (FIXED):**
```python
# Use email as username (key in user_map), not role!
username = email

if username in auth_svc.user_map:
    # FIXED: Pass username (email), not role, to handle_successful_login
    self.log.info(f'User "{display_name}" ({username}) authenticated via SAML with role "{caldera_role}"')
    await auth_svc.handle_successful_login(request, username)
```

## Key Changes

1. **Use email as username (key in user_map)**, not the role
2. **Use `auth_svc.create_user()`** instead of manually creating dictionary entries
3. **Pass username (email) to `handle_successful_login()`**, not role

## Expected Results After Fix

✅ SAML authentication succeeds (as before)
✅ User is properly provisioned with correct User namedtuple structure
✅ No more 500 errors when accessing Caldera UI
✅ All UI components render correctly
✅ User properties (username, permissions) accessible without errors

## Verification

After deploying this fix, verify with:

```bash
# 1. Login via SAML
# 2. Check logs for successful user creation:
journalctl -u caldera -f | grep "Creating new user"

# Expected output:
# Creating new user: mnescot@fredhutch.org with role admin
# User mnescot@fredhutch.org created successfully with role admin

# 3. Verify no 500 errors in browser Network tab
# 4. Verify all UI elements render correctly
```

## Commit Information

- **Commit**: 1923f33
- **Branch**: dev
- **Repository**: mnescot/saml
- **Date**: 2025-12-08
