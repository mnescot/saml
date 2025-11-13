import logging
from aiohttp import web

from app.service.interfaces.i_login_handler import LoginHandlerInterface

HANDLER_NAME = 'SAML Login Handler'


def load_login_handler(services):
    return SamlLoginHandler(services)


class SamlLoginHandler(LoginHandlerInterface):
    def __init__(self, services):
        super().__init__(services, HANDLER_NAME)
        self.services = services
        self.log = logging.getLogger('saml_login_handler')

    async def handle_login(self, request, **kwargs):
        """Redirects login request to SAML login page. If username/password were included in the request, then
        the default login handler mechanism will be used.
        """
        # Only handle login if username and password are not included in the request. If username and password
        # are included, then this is a standard login request and should not redirect to SAML.
        try:
            data = await request.post()
        except Exception:
            # Handle GET requests or invalid POST data
            data = {}

        if 'username' not in data and 'password' not in data:
            self.log.debug('Handling SAML login redirect')
            await self.handle_login_redirect(request)
        else:
            auth_svc = self.services.get('auth_svc', None)
            if not auth_svc:
                raise Exception('Auth service not found.')
            self.log.debug('Requester provided login credentials. Using default login handler instead.')
            return await auth_svc.default_login_handler.handle_login(request, **kwargs)

    async def handle_login_redirect(self, request, **kwargs):
        """Will raise web.HTTPFound for identity provider redirect on success."""
        saml_svc = self.services.get('saml_svc', None)
        if not saml_svc:
            error_msg = 'SAML service not found in service registry. Ensure the SAML plugin is enabled and loaded.'
            self.log.error(error_msg)
            self.log.error(f'Available services: {list(self.services.keys())}')
            raise Exception(error_msg)

        try:
            auth = await saml_svc.get_saml_auth(request)
            redirect = auth.login()
            self.log.debug(f'Redirecting to IdP: {redirect[:100]}...')
            raise web.HTTPFound(redirect)
        except Exception as e:
            self.log.error(f'Failed to initiate SAML login: {e}')
            self.log.error('Falling back to default Caldera login page')
            raise web.HTTPFound('/login')
