import json
import os
import logging
import base64
import urllib.parse
from typing import Dict, Any, Optional

from aiohttp import web
from pathlib import Path
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.metadata import create_metadata_string
from saml2.response import AuthnResponse
from app.utility.base_service import BaseService


class SamlService(BaseService):
    def __init__(self):
        self.config_dir_path = os.path.join(Path(__file__).parents[1], 'conf')
        self.settings_path = os.path.join(self.config_dir_path, 'settings.json')
        self.user_mapping_path = os.path.join(self.config_dir_path, 'user_mapping.json')

        # Load SAML configuration with better error handling
        try:
            with open(self.settings_path, 'rb') as settings_file:
                self._saml_config = json.load(settings_file)
        except FileNotFoundError:
            self.log.error(f'SAML configuration file not found: {self.settings_path}')
            self._saml_config = {}
        except json.JSONDecodeError as e:
            self.log.error(f'Invalid JSON in SAML configuration: {e}')
            self._saml_config = {}

        # Load user mapping configuration
        try:
            with open(self.user_mapping_path, 'r') as mapping_file:
                self._user_mapping_config = json.load(mapping_file)
        except FileNotFoundError:
            self.log.info(f'User mapping file not found: {self.user_mapping_path}, using defaults')
            self._user_mapping_config = self._get_default_user_mapping()
        except json.JSONDecodeError as e:
            self.log.error(f'Invalid JSON in user mapping configuration: {e}')
            self._user_mapping_config = self._get_default_user_mapping()

        self.log = self.add_service('saml_svc', self)

    def _convert_onelogin_config_to_pysaml2(self, onelogin_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert OneLogin python3-saml config format to pysaml2 config format.
        This maintains backward compatibility with existing settings.json files.
        """
        sp = onelogin_config.get('sp', {})
        idp = onelogin_config.get('idp', {})
        security = onelogin_config.get('security', {})

        # Extract SP entity ID and ACS URL
        sp_entity_id = sp.get('entityId', 'http://localhost:8888')
        acs_info = sp.get('assertionConsumerService', {})
        acs_url = acs_info.get('url', f'{sp_entity_id}/saml/acs')
        acs_binding = acs_info.get('binding', BINDING_HTTP_POST)

        # Extract IdP information
        idp_entity_id = idp.get('entityId', '')
        sso_info = idp.get('singleSignOnService', {})
        sso_url = sso_info.get('url', '')
        sso_binding = sso_info.get('binding', BINDING_HTTP_REDIRECT)

        # Extract certificate (remove whitespace and newlines)
        idp_cert = idp.get('x509cert', '').replace('\n', '').replace('\r', '').replace(' ', '')

        # Build pysaml2 config
        pysaml2_config = {
            'entityid': sp_entity_id,
            'service': {
                'sp': {
                    'name': 'Caldera SAML SP',
                    'endpoints': {
                        'assertion_consumer_service': [
                            (acs_url, acs_binding),
                        ],
                    },
                    'allow_unsolicited': True,
                    'authn_requests_signed': security.get('authnRequestsSigned', False),
                    'want_assertions_signed': security.get('wantAssertionsSigned', True),
                    'want_response_signed': security.get('wantMessagesSigned', True),
                },
            },
            'metadata': {
                'inline': [self._build_idp_metadata(idp_entity_id, sso_url, sso_binding, idp_cert)],
            },
            'debug': onelogin_config.get('debug', False),
        }

        return pysaml2_config

    def _build_idp_metadata(self, entity_id: str, sso_url: str, sso_binding: str, cert: str) -> str:
        """Build IdP metadata XML from OneLogin config parameters"""
        binding_map = {
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': BINDING_HTTP_REDIRECT,
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST': BINDING_HTTP_POST,
        }
        binding = binding_map.get(sso_binding, BINDING_HTTP_REDIRECT)

        # Format certificate with proper PEM structure if not already formatted
        if cert and not cert.startswith('-----BEGIN CERTIFICATE-----'):
            cert_formatted = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"
        else:
            cert_formatted = cert

        metadata = f'''<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{cert}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="{binding}" Location="{sso_url}"/>
  </IDPSSODescriptor>
</EntityDescriptor>'''

        return metadata

    def _get_saml2_client(self) -> Saml2Client:
        """Create and return a pysaml2 client instance"""
        pysaml2_config = self._convert_onelogin_config_to_pysaml2(self._saml_config)
        config = Saml2Config()
        config.load(pysaml2_config)
        client = Saml2Client(config=config)
        return client

    def _get_default_user_mapping(self) -> Dict[str, Any]:
        """Default user mapping configuration"""
        return {
            "role_mappings": {
                "admin": ["admin", "administrator", "sysadmin"],
                "blue": ["blue_team", "defender", "analyst"],
                "red": ["red_team", "attacker", "pentester"],
                "user": ["user", "viewer", "readonly"]
            },
            "group_mappings": {},
            "email_domain_mappings": {}
        }

    async def saml(self, request):
        """Legacy handler - routes to appropriate specific handler based on path and method"""
        path = request.path
        method = request.method

        self.log.debug(f'SAML legacy handler called: {method} {path}')

        try:
            # Route to specific handlers based on path
            if path.endswith('/metadata'):
                return await self.saml_metadata_handler(request)
            elif path.endswith('/acs'):
                return await self.saml_acs_handler(request)
            elif path.endswith('/sls'):
                return await self.saml_sls_handler(request)
            elif path.endswith('/login') or path in ['/saml', '/auth/saml']:
                return await self.saml_login_handler(request)
            else:
                # Default behavior - check if it's a SAML response or login initiation
                if method == 'POST' and 'SAMLResponse' in (await request.post()):
                    return await self.saml_acs_handler(request)
                else:
                    return await self.saml_login_handler(request)

        except web.HTTPRedirection as http_redirect:
            raise http_redirect
        except Exception as e:
            self.log.exception('Exception when handling SAML request: %s', e)
            self.log.debug('Redirecting to main login page')
            raise web.HTTPFound('/login')

    async def _saml_login(self, request):
        """Core SAML login logic using pysaml2"""
        self.log.debug(f'Handling SAML login: {request.method} {request.path}')

        try:
            client = self._get_saml2_client()

            # Check if this is a SAML response (POST from IdP) or login initiation (GET)
            if request.method == 'POST':
                post_data = await request.post()
                if 'SAMLResponse' in post_data:
                    # Process SAML response from IdP
                    self.log.debug('Processing SAML response from IdP')

                    saml_response = post_data['SAMLResponse']

                    # Parse the SAML response
                    authn_response = client.parse_authn_request_response(
                        saml_response,
                        BINDING_HTTP_POST
                    )

                    # Get user identity from response
                    identity = authn_response.get_identity()
                    subject = authn_response.get_subject()

                    if not identity or not subject:
                        self.log.error('SAML authentication failed: no identity or subject')
                        raise web.HTTPFound('/login')

                    self.log.debug(f'SAML authentication successful for subject: {subject.text}')

                    # Extract user info from SAML attributes
                    user_info = self._extract_user_info_from_identity(identity, subject)

                    # Determine Caldera role
                    caldera_role = self._determine_caldera_role(user_info)

                    # Provision user if enabled
                    if self._is_user_provisioning_enabled():
                        await self._provision_user(user_info, caldera_role)

                    # Authenticate user
                    return await self._authenticate_user(request, caldera_role, user_info)

            # GET request or no SAML response - initiate login
            self.log.debug('Initiating SAML login redirect to IdP')

            # Get IdP SSO URL from client
            session_id, info = client.prepare_for_authenticate()

            # Extract redirect URL (first tuple element is the redirect URL)
            redirect_url = None
            for key, value in info['headers']:
                if key == 'Location':
                    redirect_url = value
                    break

            if not redirect_url:
                self.log.error('Failed to get redirect URL from SAML client')
                raise web.HTTPFound('/login')

            self.log.debug(f'Redirecting to IdP: {redirect_url}')
            raise web.HTTPFound(redirect_url)

        except web.HTTPRedirection:
            raise
        except Exception as e:
            self.log.exception(f'SAML login error: {e}')
            raise web.HTTPFound('/login')

    def _extract_user_info_from_identity(self, identity: Dict[str, Any], subject) -> Dict[str, Any]:
        """Extract user information from SAML identity attributes"""
        user_info = {
            'name_id': subject.text,
            'email': None,
            'display_name': None,
            'roles': [],
            'groups': [],
        }

        # Common attribute names for email
        email_attrs = ['email', 'emailAddress', 'mail', 'urn:oid:0.9.2342.19200300.100.1.3']
        for attr in email_attrs:
            if attr in identity and identity[attr]:
                user_info['email'] = identity[attr][0] if isinstance(identity[attr], list) else identity[attr]
                break

        # Common attribute names for display name
        name_attrs = ['displayName', 'cn', 'commonName', 'name', 'urn:oid:2.5.4.3']
        for attr in name_attrs:
            if attr in identity and identity[attr]:
                user_info['display_name'] = identity[attr][0] if isinstance(identity[attr], list) else identity[attr]
                break

        # Extract roles and groups
        role_attrs = ['role', 'roles', 'Role', 'Roles']
        group_attrs = ['group', 'groups', 'Group', 'Groups', 'memberOf']

        for attr in role_attrs:
            if attr in identity:
                user_info['roles'] = identity[attr] if isinstance(identity[attr], list) else [identity[attr]]

        for attr in group_attrs:
            if attr in identity:
                user_info['groups'] = identity[attr] if isinstance(identity[attr], list) else [identity[attr]]

        return user_info

    async def _handle_enhanced_authentication(self, request, saml_auth):
        """Enhanced authentication handler with automatic user provisioning"""
        try:
            # Extract user information from SAML response
            user_info = self._extract_user_info(saml_auth)
            self.log.debug(f'Extracted user info: {user_info}')

            # Determine Caldera role based on SAML attributes
            caldera_role = self._determine_caldera_role(user_info)
            self.log.debug(f'Determined Caldera role: {caldera_role}')

            # Provision or update user if enabled
            if self._is_user_provisioning_enabled():
                await self._provision_user(user_info, caldera_role)

            # Authenticate user (will raise HTTPFound redirect on success)
            await self._authenticate_user(request, caldera_role, user_info)

        except web.HTTPRedirection:
            # Re-raise redirects (this is expected for successful login)
            raise
        except Exception as e:
            self.log.error(f'Enhanced authentication failed: {e}')
            raise web.HTTPFound('/login')

    def _extract_user_info(self, saml_auth) -> Dict[str, Any]:
        """Extract user information from SAML response"""
        attributes = saml_auth.get_attributes()
        name_id = saml_auth.get_nameid()

        # Get configuration for attribute names
        user_provisioning = self._saml_config.get('user_provisioning', {})
        email_attr = user_provisioning.get('email_attribute', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')
        name_attr = user_provisioning.get('name_attribute', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name')
        role_attr = user_provisioning.get('role_attribute', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role')
        group_attr = user_provisioning.get('group_attribute', 'http://schemas.xmlsoap.org/claims/Group')

        # Extract values
        user_info = {
            'name_id': name_id,
            'email': self._get_attribute_value(attributes, email_attr),
            'display_name': self._get_attribute_value(attributes, name_attr),
            'roles': self._get_attribute_values(attributes, role_attr),
            'groups': self._get_attribute_values(attributes, group_attr),
            'all_attributes': attributes
        }

        # Use name_id as email if email not found
        if not user_info['email'] and name_id:
            user_info['email'] = name_id

        return user_info

    def _get_attribute_value(self, attributes: Dict, attr_name: str) -> Optional[str]:
        """Get single attribute value"""
        values = attributes.get(attr_name, [])
        return values[0] if values else None

    def _get_attribute_values(self, attributes: Dict, attr_name: str) -> list:
        """Get multiple attribute values"""
        return attributes.get(attr_name, [])

    def _determine_caldera_role(self, user_info: Dict[str, Any]) -> str:
        """Determine Caldera role based on SAML attributes and mapping configuration"""
        user_provisioning = self._saml_config.get('user_provisioning', {})
        default_role = user_provisioning.get('default_role', 'blue')
        admin_roles = user_provisioning.get('admin_roles', ['admin', 'administrator'])
        admin_groups = user_provisioning.get('admin_groups', [])

        # Check if user has admin roles
        for role in user_info.get('roles', []):
            if role.lower() in [r.lower() for r in admin_roles]:
                return 'red'

        # Check if user is in admin groups
        for group in user_info.get('groups', []):
            if group in admin_groups:
                return 'red'

        # Check role mappings
        role_mappings = self._user_mapping_config.get('role_mappings', {})
        for caldera_role, saml_roles in role_mappings.items():
            for user_role in user_info.get('roles', []):
                if user_role.lower() in [r.lower() for r in saml_roles]:
                    return caldera_role

        # Check group mappings
        group_mappings = self._user_mapping_config.get('group_mappings', {})
        for group in user_info.get('groups', []):
            if group in group_mappings:
                return group_mappings[group]

        # Check email domain mappings
        email_domain_mappings = self._user_mapping_config.get('email_domain_mappings', {})
        if user_info.get('email'):
            domain = user_info['email'].split('@')[-1] if '@' in user_info['email'] else ''
            if domain in email_domain_mappings:
                return email_domain_mappings[domain]

        return default_role

    def _is_user_provisioning_enabled(self) -> bool:
        """Check if user provisioning is enabled"""
        user_provisioning = self._saml_config.get('user_provisioning', {})
        return user_provisioning.get('enabled', False)

    async def _provision_user(self, user_info: Dict[str, Any], caldera_role: str):
        """Provision or update user in Caldera using proper User namedtuple structure"""
        try:
            auth_svc = self.get_service('auth_svc')
            if not auth_svc:
                raise Exception('Auth service not available')

            email = user_info.get('email')
            display_name = user_info.get('display_name', email)

            if not email:
                self.log.warning('No email found in SAML response, cannot provision user')
                return

            # Use email as username (key in user_map)
            username = email

            # Check if user exists by username (email), not role
            user_exists = username in auth_svc.user_map

            user_provisioning = self._saml_config.get('user_provisioning', {})
            create_missing = user_provisioning.get('create_missing_users', True)
            update_on_login = user_provisioning.get('update_on_login', True)

            if not user_exists and create_missing:
                # Create new user using Caldera's create_user method
                # This creates: User(username=email, password=pwd, permissions=(caldera_role, 'app'))
                self.log.info(f'Creating new user: {username} with role {caldera_role}')

                password = self._generate_temp_password()

                # Use auth_svc.create_user() to ensure proper User namedtuple structure
                # This automatically creates: user_map[username] = User(username, password, (group, 'app'))
                await auth_svc.create_user(username, password, caldera_role)

                self.log.info(f'User {username} created successfully with role {caldera_role}')

            elif user_exists and update_on_login:
                # Update existing user's password (User namedtuples are immutable, so recreate)
                self.log.debug(f'Updating existing user: {username}')

                password = self._generate_temp_password()

                # Recreate user with updated password
                await auth_svc.create_user(username, password, caldera_role)

                self.log.debug(f'User {username} updated successfully')

        except Exception as e:
            self.log.error(f'User provisioning failed: {e}')
            # Don't fail authentication if provisioning fails
            pass

    def _get_role_privileges(self, role: str) -> list:
        """Get privileges for a Caldera role"""
        role_privileges = {
            'admin': ['red', 'blue'],
            'red': ['red'],
            'blue': ['blue'],
            'user': []
        }
        return role_privileges.get(role, [])

    def _generate_temp_password(self) -> str:
        """Generate a temporary password for SAML users"""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(16))

    def _get_current_timestamp(self) -> str:
        """Get current timestamp as string"""
        from datetime import datetime
        return datetime.utcnow().isoformat()

    async def _authenticate_user(self, request, caldera_role: str, user_info: Dict[str, Any]):
        """Authenticate user with Caldera using email as username"""
        auth_svc = self.get_service('auth_svc')
        if not auth_svc:
            raise Exception('Auth service not available')

        email = user_info.get('email', 'unknown@unknown.com')
        display_name = user_info.get('display_name', email)

        # Use email as username (key in user_map), not role!
        username = email

        if username in auth_svc.user_map:
            # Pass username (email), not role, to handle_successful_login
            # Will raise redirect on success
            self.log.info(f'User "{display_name}" ({username}) authenticated via SAML with role "{caldera_role}"')
            await auth_svc.handle_successful_login(request, username)
        else:
            self.log.warning(f'User "{username}" not found in user_map. Role: "{caldera_role}", Display name: "{display_name}"')
            raise web.HTTPFound('/login')

    # Specific handler methods for different SAML endpoints
    async def saml_login_handler(self, request):
        """Handle SAML login initiation (GET)"""
        self.log.debug('SAML login handler called')
        return await self._saml_login(request)

    async def saml_acs_handler(self, request):
        """Handle SAML assertion consumer service (POST)"""
        self.log.debug('SAML ACS handler called')
        return await self._saml_login(request)

    async def saml_metadata_handler(self, request):
        """Generate and return SAML SP metadata"""
        try:
            client = self._get_saml2_client()

            # Generate metadata
            metadata = create_metadata_string(
                configfile=None,
                config=client.config,
                valid_for=24  # hours
            )

            return web.Response(
                text=metadata.decode('utf-8') if isinstance(metadata, bytes) else metadata,
                content_type='application/xml'
            )
        except Exception as e:
            self.log.exception(f'Error generating SAML metadata: {e}')
            return web.Response(text='Error generating metadata', status=500)

    async def saml_sls_handler(self, request):
        """Handle SAML Single Logout Service (SLS)"""
        self.log.debug('SAML SLS (logout) not yet implemented')
        raise web.HTTPFound('/login')

    async def set_saml_login_handler(self):
        """Set self as the optional login handler for the auth service."""
        self.log.debug('SAML login handler initialization complete.')
        pass


# Legacy compatibility methods (to be removed in future versions)

    async def get_saml_auth(self, request):
        """
        DEPRECATED: Legacy method for OneLogin compatibility.
        Returns a wrapper object for backward compatibility.
        """
        self.log.warning('get_saml_auth() is deprecated - using pysaml2 client instead')

        class LegacySamlAuthWrapper:
            """Wrapper to provide OneLogin-like interface for legacy code"""
            def __init__(self, service, request):
                self.service = service
                self.request = request
                self.client = service._get_saml2_client()
                self._authenticated = False
                self._identity = None
                self._subject = None

            def login(self, return_to=None):
                """Initiate login - returns redirect URL"""
                session_id, info = self.client.prepare_for_authenticate()
                for key, value in info['headers']:
                    if key == 'Location':
                        return value
                return None

            def process_response(self):
                """Process SAML response"""
                # This is a no-op in the wrapper - actual processing happens elsewhere
                pass

            def is_authenticated(self):
                """Check if authenticated"""
                return self._authenticated

            def get_attributes(self):
                """Get user attributes"""
                return self._identity if self._identity else {}

            def get_nameid(self):
                """Get name ID"""
                return self._subject.text if self._subject else None

            def get_errors(self):
                """Get errors - returns empty list for compatibility"""
                return []

        return LegacySamlAuthWrapper(self, request)

    async def _prepare_auth_parameter(self, request):
        """
        DEPRECATED: Legacy method for OneLogin compatibility.
        Convert aiohttp request to auth parameter format.
        """
        self.log.warning('_prepare_auth_parameter() is deprecated')

        post_data = {}
        if request.method == 'POST':
            post_data = await request.post()
            post_data = {k: v for k, v in post_data.items()}

        get_data = {k: v for k, v in request.query.items()}

        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'server_port': request.url.port or (443 if request.scheme == 'https' else 80),
            'script_name': request.path,
            'get_data': get_data,
            'post_data': post_data,
            'query_string': request.query_string,
        }

    def _handle_saml_auth_errors(self, saml_auth):
        """
        DEPRECATED: Legacy method for OneLogin compatibility.
        Check for and handle SAML authentication errors.
        """
        self.log.warning('_handle_saml_auth_errors() is deprecated')
        # No-op for compatibility
        pass

    @staticmethod
    def _get_saml_login_username(saml_auth):
        """Get username from SAML NameID"""
        name_id = saml_auth.get_nameid()
        if name_id:
            return name_id
        return SamlService._get_saml_username_attribute(saml_auth)

    @staticmethod
    def _get_saml_username_attribute(saml_auth):
        """Get username from SAML attributes"""
        attributes = saml_auth.get_attributes()
        username_attr_list = attributes.get('username', [])
        return username_attr_list[0] if len(username_attr_list) > 0 else None
