# Technical Analysis: User Object Structure Mismatch

## Executive Summary

The persistent 500 errors after SAML authentication in Caldera were caused by a data structure mismatch. The SAML plugin created dictionary objects when Caldera expected User namedtuples, causing `AttributeError` exceptions when the UI attempted to access user properties.

## Detailed Problem Analysis

### The Authentication Flow

1. ✅ User initiates SAML login
2. ✅ IdP authentication succeeds
3. ✅ SAML plugin processes response
4. ✅ User provisioning completes (logs: "admin logging in")
5. ❌ UI attempts to render → 500 errors on all API endpoints

### Why Logs Showed No Errors

The 500 errors were "silent" because:

1. Caldera's HTTP handlers catch all exceptions
2. Generic 500 responses sent to browser
3. No detailed tracebacks logged
4. Only generic "Server got itself in trouble" shown to user

This made diagnosis extremely difficult without enhanced logging.

### The Data Structure Mismatch

#### Caldera's Expected Structure

Source: `app/service/auth_svc.py` in Caldera core

```python
from collections import namedtuple

# User namedtuple definition
User = namedtuple('User', ['username', 'password', 'permissions'])

# Storage structure
user_map = {
    'mnescot@fredhutch.org': User(
        username='mnescot@fredhutch.org',
        password='hashed_password',
        permissions=('admin', 'app')  # Tuple: (group, scope)
    )
}

# Access pattern in UI code
user = user_map[username]
print(user.username)      # Works: returns 'mnescot@fredhutch.org'
print(user.password)      # Works: returns 'hashed_password'
print(user.permissions)   # Works: returns ('admin', 'app')
```

#### SAML Plugin's Broken Structure

Source: `app/saml_svc.py` (before fix)

```python
# BROKEN: Dictionary instead of User namedtuple
user_map = {
    'admin': {  # WRONG KEY: using role instead of email
        'password': 'randomPassword123',
        'privileges': ['red', 'blue'],  # WRONG: list instead of tuple
        'created_via_saml': True,
        'saml_email': 'mnescot@fredhutch.org',
        'saml_display_name': 'Mike Nescot',
        'last_saml_login': '2025-12-08T10:30:00'
    }
}

# Access pattern in UI code FAILS
user = user_map['admin']   # Gets dictionary, not User namedtuple
print(user.username)       # AttributeError: 'dict' object has no attribute 'username'
print(user.password)       # Would work if we got this far (dict['password'])
print(user.permissions)    # AttributeError: 'dict' object has no attribute 'permissions'
```

## Multiple Issues Identified

### Issue 1: Wrong Data Type

**Problem:** Dictionary vs. User namedtuple
**Impact:** `AttributeError` when accessing `.username`, `.permissions`
**Fix:** Use `auth_svc.create_user()` to create proper User namedtuples

### Issue 2: Wrong Map Key

**Problem:** Using role ('admin') as key instead of username (email)
**Impact:** Multiple users with same role would overwrite each other
**Fix:** Use email as username and map key

### Issue 3: Wrong Permissions Format

**Problem:** List `['red', 'blue']` instead of tuple `('admin', 'app')`
**Impact:** Even if other issues fixed, permissions would fail validation
**Fix:** Let `create_user()` handle proper permissions format

### Issue 4: Wrong Parameter to handle_successful_login()

**Problem:** Passing role instead of username
**Impact:** Session tracking fails, user lookup fails
**Fix:** Pass username (email) to `handle_successful_login()`

## The Fix Explained

### Using `auth_svc.create_user()`

This method is Caldera's official way to create users:

```python
async def create_user(self, username: str, password: str, group: str):
    """Create or update a user account"""
    # Hash the password
    hashed = self._hash_password(password)

    # Create proper User namedtuple with correct permissions format
    self.user_map[username] = User(
        username=username,
        password=hashed,
        permissions=(group, 'app')  # Tuple: (group, scope)
    )
```

### Updated _provision_user()

```python
async def _provision_user(self, user_info: Dict[str, Any], caldera_role: str):
    """Provision or update user in Caldera using proper User namedtuple structure"""
    email = user_info.get('email')
    username = email  # Use email as username

    if not user_exists and create_missing:
        password = self._generate_temp_password()

        # CORRECT: Creates User(username, password, (role, 'app'))
        await auth_svc.create_user(username, password, caldera_role)
```

### Updated _authenticate_user()

```python
async def _authenticate_user(self, request, caldera_role: str, user_info: Dict[str, Any]):
    """Authenticate user with Caldera using email as username"""
    email = user_info.get('email', 'unknown@unknown.com')
    username = email  # Use email as username

    if username in auth_svc.user_map:
        # CORRECT: Pass username (email), not role
        await auth_svc.handle_successful_login(request, username)
```

## Comparison: Before vs After

### Before (BROKEN)

```python
# Provisioning
auth_svc.user_map['admin'] = {
    'password': 'pwd',
    'privileges': ['red', 'blue'],
    # ...
}

# Authentication
if 'admin' in auth_svc.user_map:
    await auth_svc.handle_successful_login(request, 'admin')

# Result
user_map = {
    'admin': {
        'password': 'pwd',
        'privileges': ['red', 'blue'],
        # ...
    }
}

# UI Access
user = user_map['admin']
username = user.username  # ❌ AttributeError
```

### After (FIXED)

```python
# Provisioning
await auth_svc.create_user('mnescot@fredhutch.org', 'pwd', 'admin')

# Authentication
if 'mnescot@fredhutch.org' in auth_svc.user_map:
    await auth_svc.handle_successful_login(request, 'mnescot@fredhutch.org')

# Result
user_map = {
    'mnescot@fredhutch.org': User(
        username='mnescot@fredhutch.org',
        password='hashed_pwd',
        permissions=('admin', 'app')
    )
}

# UI Access
user = user_map['mnescot@fredhutch.org']
username = user.username  # ✅ Returns 'mnescot@fredhutch.org'
```

## Testing the Fix

### 1. Verify User Structure

Add temporary logging to see the structure:

```python
# In _provision_user() after create_user()
user_obj = auth_svc.user_map.get(username)
self.log.debug(f'User object type: {type(user_obj)}')
self.log.debug(f'User object: {user_obj}')
```

Expected output:
```
User object type: <class '__main__.User'>
User object: User(username='mnescot@fredhutch.org', password='$2b$...', permissions=('admin', 'app'))
```

### 2. Verify No 500 Errors

1. Login via SAML
2. Open browser DevTools → Network tab
3. Watch all API requests
4. All should return 200/201/204, no 500s

### 3. Verify UI Rendering

1. Dashboard loads completely
2. User menu shows correct username
3. All navigation works
4. No console errors

## Related Issues Resolved

This fix also resolves:

1. ✅ Multiple users with same role overwriting each other
2. ✅ Session tracking failures
3. ✅ Permissions validation errors
4. ✅ User lookup failures in subsequent requests

## Prevention: Best Practices

To prevent similar issues:

1. **Always use framework methods** (`create_user()`) instead of direct dict manipulation
2. **Match expected data structures** - check core code for namedtuple definitions
3. **Add comprehensive logging** - especially for data structure types
4. **Test with actual user flows** - not just authentication, but subsequent UI access
5. **Add type hints** - would have caught this: `user_map: Dict[str, User]`

## Timeline of Discovery

1. **Initial report**: 500 errors after SAML auth update
2. **First investigation**: Found HTTPS/port issues (already fixed)
3. **Enhanced logging**: Added DEBUG and exception tracebacks
4. **User insight**: "user object data structure doesn't align"
5. **Web research**: Found Caldera's User namedtuple definition
6. **Root cause**: Dictionary vs User namedtuple mismatch
7. **Fix applied**: Use `create_user()` method, email as username

## Conclusion

This was a classic data structure mismatch issue that was difficult to diagnose because:

1. Authentication appeared to succeed
2. Errors were generic 500s with no details
3. No exceptions logged due to broad exception handlers
4. Issue only manifested when UI tried to access user properties

The fix ensures the SAML plugin creates user objects in the exact format Caldera expects, eliminating the AttributeError that caused the 500 errors.
