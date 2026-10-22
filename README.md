# MITRE Caldera Plugin: SAML

## Overview
`saml` is a Caldera plugin that provides SAML authentication for Caldera by establishing Caldera as
a SAML Service Provider (SP). To use this plugin, users will need to have Caldera configured as an application
in their Identity Provider (IdP), and a `conf/settings.json` file will need to be created in the plugin 
with the appropriate SAML settings and IdP and SP information.

When enabled and configured, this plugin will provide the following:
- When browsing to the main Caldera site (e.g. `http://localhost:8888/`) or to the `/enter` URL for the Caldera site
(e.g. `http://localhost:8888/enter`), unauthenticated users will
be redirected to their IdP login page rather than to the default Caldera login page. If the SAML
settings are not properly configured or if there is an issue with attempting the redirect, the user will
be redirected to the default Caldera login page as a failsafe.
- When users access the Caldera application directly from their IdP, they will immediately authenticate
into Caldera without having to provide login credentials, provided that Caldera was configured correctly
within the IdP settings. If the SAML login fails for whatever reason (e.g. the application was provisioned
using a username that does not exist within Caldera), the user will be taken to the default Caldera login page.

## Setup
There are two main setup components required for SAML authentication within this plugin:
1. The IdP administrators need to configure Caldera as an application within the IdP platform
1. Caldera administrators need to configure the `conf/settings.json` settings file within the `saml` plugin.

### Installing Dependencies
To install dependencies, run the following from within the plugin directory::
```
pip3 install -r requirements.txt
```
Note that `requirements.txt` requires `xmlsec`, which in turn requires certain native libraries. 
See the [xmlsec page](https://pypi.org/project/xmlsec/) for more details and to see which native libraries are required
for the operating system that is hosting Caldera in your particular environment.

### Configuring Caldera Within the IdP Platform
To provision Caldera access for users within the Identity Provider, follow the instructions for your particular
Identity Provider to create the Caldera application with the appropriate SAML settings. 

- When asked for the "Single Sign On URL", "Recipient URL", and "Destination URL", set this to
the `/saml` URL for your Caldera server (e.g. `http://localhost:8888/saml`). When the plugin is enabled, the server will listen on this endpoint for SAML requests.
- When asked for the "Audience URI" or "SP Entity ID", use the HTTP endpoint for your Caldera server without the trailing slash (e.g. `http://localhost:8888`). 
- You may keep the "Default RelayState" blank
- If asked for a Name ID format, you may keep it as unspecified
- Include a `username` attribute statement with a value that contains
the user's username or login name for the Identity Provider (e.g. email address). 
This is required by Caldera to track which users are logging into the system under which
Caldera accounts.

Once the application is created with the appropriate SAML settings, follow your IdP instructions to provision 
access to the necessary users. You will also need to follow your IdP's instructions to find
the SSO URL for the IdP, the IdP Issuer URL, and the X.509 Certificate for the IdP.
This information is needed to configure the SAML settings within this plugin.

#### Application Usernames
To avoid having to create individual Caldera accounts for each user in the IdP, one method is to create a fixed
set of Caldera user accounts (e.g. `red` and `blue` users) and assign the Caldera username as the
application username for the user assignment. This way, multiple users can log in using the same
Caldera username, and the SAML request will also include their `username` attribute statement, so that
Caldera's authentication service can distinguish between different users from the IdP platform.

### Configuring SAML settings within Caldera
Once Caldera is configured as an application within your IdP, you can start creating the `conf/settings.json`
file within the plugin according to the [python3-saml instructions](https://github.com/onelogin/python3-saml#settings)
. The following settings are required unless marked otherwise:
- Set `strict` to `true`
- Under `sp`:
    - For `entityId`, use the HTTP endpoint for the C2 Server (e.g. `"http://localhost:8888"`)
    - Under `assertionConsumerService`:
        - The `url` must be the `/saml` endpoint for the C2 server (e.g. `"http://localhost:8888/saml"`)
        - For `binding`, use `"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`
    - Do not include an entry for `singleLogoutService`
- Under `idp`:
    - For `entityId`, use the Identity Provider's identifier URI. You will need to obtain this from
    your Caldera application configuration for the Identity Provider.
    - Under `singleSignOnService`:
        - For `url`, use the IdP's SSO URL as provided by the IdP for the
        Caldera application configuration.
        - For `binding`, use `"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"`
    - For the `x509cert`, use the base64-encoded string for the IdP's X.509 certificate.
- Under `security`:
    - Set `wantAttributeStatement` to `true`
    - Set the remaining security settings as needed for your environment. 
    - Note that the security settings as shown in the 
    [`python3-saml` readme](https://github.com/onelogin/python3-saml/#settings) are placed in a separate
    file called `advanced_settings.json`. For simplicity, the `saml` plugin requires you to combine all settings
    into the same `conf/settings.json` file, as shown in the example below.
    
You may adjust settings as needed for your environment.
  
Below is a sample template for the SAML settings JSON file, which is also located in `config/sample.json` in the plugin.
Refer to the [python3-saml page](https://github.com/onelogin/python3-saml/) for full documentation and examples.
```json
{
    "strict": true,
    "debug": true,
    "sp": {
        "entityId": "http://localhost:8888",
        "assertionConsumerService": {
            "url": "http://localhost:8888/saml",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        }
    },
    "idp": {
        "entityId": "http://myidentityprovider.com/connector_id_url",
        "singleSignOnService": {
            "url": "https://myidentityprovider.com/sso_url",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "base64-encoded certificate data"
    },
    "security": {
        "wantMessagesSigned": true,
        "wantAssertionsSigned": true,
        "wantAttributeStatement": true
    }
}
```

### Setting the SAML Login Handler
Once Caldera's SAML settings are configured and Caldera is set up on the IdP platform, the final
step requires setting the SAML login handler as the main login handler in the Caldera config YAML file. 
Within the config file, set `auth.login.handler.module` to `plugins.saml.app.saml_login_handler`
as shown below:
```yaml
auth.login.handler.module: plugins.saml.app.saml_login_handler
```

Restart the Caldera server, and any future authentication requests will now be handled via SAML according
to the previously established settings.

### Four group-based roles

A deployment can enable `group_role_policy` in `conf/settings.json`:

```json
{"group_role_policy":{"enabled":true,"groups":{
  "admin":["<Entra Admin group object ID>"],
  "red":["<Entra Red group object ID>"],
  "blue":["<Entra Blue group object ID>"],
  "report":["<Entra Report group object ID>"]}}}
```

A deployment can pin the same JSON policy through the root-managed
`CALDERA_SAML_RBAC_POLICY` environment variable. It takes precedence over the
settings file; malformed deployment policy denies access.

The standard Entra group-claim URI
`http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` is recognized
by default. A configured `user_provisioning.group_attribute` still takes
precedence when the deployment uses a custom claim name.

Only group membership in the validated SAML assertion grants these roles.
Role attributes, email domains and the legacy default role do not grant access
in this mode. The picker offers exactly the user's memberships; no match shows
**No access**. The selected role determines that browser session's permissions.
An Admin-group member choosing Red receives a Red session; Admin permissions
require selecting Admin in a new verified sign-in. Admin receives core Red/Blue
permissions; Red and Blue keep their corresponding core permissions; Report
receives application access only. InfoSec Agent separately enforces the same
group policy and selected session role for its UI, API and tools. The deployment
must configure both. The hierarchy orders available choices and supplies the
account's membership ceiling; selecting a lower role does not activate it.
Concurrent browser sessions keep independent role limits. Core permission
checks and `AuthService.get_permissions(request)` both enforce that limit.

Existing account-creation/update opt-outs still apply. If the exact permissions
cannot be applied, sign-in is refused rather than retaining an older role.

Other server-side plugins may call `verified_group_identity(request)` when they
need verified SAML groups and the `selected_role`, including alongside Cognito. It authenticates
the core cookie session and returns only a live, server-owned assertion record,
bound to that account and NameID. `current_group_identity(record)` revalidates
it after changes; copied records, revoked/replaced accounts and machine
credentials cannot supply this evidence. The record contains no password or
account credential object.

Successful group-mode sessions are bound to their verified NameID and exact
core account entry. If a later assertion removes membership or cannot apply a
role change, old sessions are denied independently of account provisioning.
Cleanup can delete only an entry this service created, with account updates
enabled; preconfigured or replaced local accounts are preserved. Denied login
GETs do not change accounts, and failed SSO does not fall back to passwords or
loop back through the login page.
`group_role_policy` absent/disabled preserves the legacy picker for other
installations.

This plugin runs inside Caldera's single-process server. Core `user_map`, pending
role-selection tokens and session-revocation bindings are process-local. Running
concurrent workers or serving replicas requires a shared core identity/session
backend and is not a supported deployment mode of this plugin. Blue/green
deployments must send traffic to one active server at a time rather than split
authenticated sessions across replicas.

Direct-SAML plugin evidence is immutable and belongs only to the browser session
that completed SSO. A restart or blue/green cutover intentionally expires these
process-local assertion grants: the next HTML navigation redirects to
`/saml/login`, while API requests return HTTP 401 with
`error=saml_reauthentication_required` and `login_url=/saml/login`. Complete SAML
sign-in again to restore access; existing cookies cannot inherit another login's
new privileges. Machine credentials retain their separately bounded permissions.
Each completed browser login has its own marker. Concurrent SAML sessions remain
valid when the subject and asserted groups are unchanged; entitlement/account
changes invalidate prior grants before another picker completes. Unmarked
legacy/password cookies also require SAML reauthentication in group-only mode.
Browser grants expire at the earliest validated assertion/session deadline, with
a maximum of one hour (also the fallback when the IdP omits a deadline). A new
login never extends an older browser's grant. Expiry also invalidates copied
plugin evidence used by background work; reauthenticate to obtain a fresh grant.
