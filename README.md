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
the `/saml/acs` URL for your Caldera server (e.g. `http://localhost:8888/saml/acs` or `https://your-server.example.com/saml/acs`). When the plugin is enabled, the server will listen on this endpoint for SAML responses.
  - **Note**: The legacy `/saml` endpoint is also supported for backward compatibility.
- When asked for the "Audience URI" or "SP Entity ID", use the HTTP endpoint for your Caldera server without the trailing slash (e.g. `http://localhost:8888` or `https://your-server.example.com`).
- You may keep the "Default RelayState" blank
- If asked for a Name ID format, you may keep it as unspecified or use email address
- For user provisioning to work properly, ensure the following attribute claims are configured:
  - Email address (recommended attribute name: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`)
  - Display name (recommended attribute name: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`)
  - Roles (optional, attribute name: `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`)
  - Groups (optional, attribute name: `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`)

Once the application is created with the appropriate SAML settings, follow your IdP instructions to provision
access to the necessary users. You will also need to follow your IdP's instructions to find
the SSO URL for the IdP, the IdP Issuer URL, and the X.509 Certificate for the IdP.
This information is needed to configure the SAML settings within this plugin.

#### Microsoft Entra ID (Azure AD) Specific Configuration
For Microsoft Entra ID, use the following configuration:

1. **Entity ID**: Use your Caldera server URL (e.g., `https://your-caldera-server.example.com`)
2. **Reply URL (ACS URL)**: `https://your-caldera-server.example.com/saml/acs`
3. **Sign-on URL**: Leave blank or set to your Caldera server URL
4. **Identifier (Entity ID)**: Same as Entity ID above
5. **IdP metadata**:
   - Entity ID: `https://sts.windows.net/YOUR-TENANT-ID/`
   - SSO URL: `https://login.microsoftonline.com/YOUR-TENANT-ID/saml2`
6. **Attribute Claims**: Entra ID provides these by default, but verify:
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` → `user.mail`
   - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` → `user.displayname`
   - (Optional) `http://schemas.microsoft.com/ws/2008/06/identity/claims/role` → for role-based provisioning
   - (Optional) `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` → for group-based provisioning

See `conf/sample_entra_id.json` for a complete Entra ID configuration example.

#### Application Usernames and User Provisioning

The SAML plugin supports two modes for managing user accounts:

**Option 1: Automatic User Provisioning (Recommended)**
When automatic user provisioning is enabled in your `settings.json`, the plugin will automatically create Caldera user accounts for authenticated SAML users who don't already exist. This eliminates the need to pre-create accounts manually.

To enable automatic provisioning, add the `user_provisioning` section to your `conf/settings.json`:
```json
"user_provisioning": {
    "enabled": true,
    "create_missing_users": true,
    "update_on_login": true,
    "default_role": "blue",
    "admin_roles": ["admin", "administrator"]
}
```

Users will be automatically assigned to Caldera roles based on:
- Their SAML role attributes
- Their SAML group memberships
- The configured role mappings
- The default role (if no matching role is found)

**Option 2: Manual Account Management (Legacy)**
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
