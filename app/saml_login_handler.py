import logging
import os
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

    def _group_only(self):
        if os.environ.get('CALDERA_SAML_RBAC_POLICY') is not None:
            return True
        service = self.services.get('saml_svc')
        if service is None:
            # The selected SAML handler cannot prove that password fallback is
            # allowed when its policy-owning service is unavailable.
            return True
        try:
            return service._group_role_policy() is not None
        except Exception:
            return True

    async def handle_login(self, request, **kwargs):
        """Redirects login request to SAML login page. If username/password were included in the request, then
        the default login handler mechanism will be used.
        """
        if self._group_only():
            return await self.handle_login_redirect(request, **kwargs)
        # Only handle login if username and password are not included in the request. If username and password
        # are included, then this is a standard login request and should not redirect to SAML.
        data = await request.post()
        if 'username' not in data and 'password' not in data:
            self.log.debug('Handling SAML login')
            await self.handle_login_redirect(request)
        else:
            auth_svc = self.services.get('auth_svc', None)
            if not auth_svc:
                raise Exception('Auth service not found.')
            self.log.debug('Requester provided login credentials. Using default login handler instead.')
            return await auth_svc.default_login_handler.handle_login(request, kwargs=kwargs)

    async def handle_login_redirect(self, request, **kwargs):
        """Will raise web.HTTPFound for identity provider redirect on success."""
        if self._group_only():
            # Core AuthService falls back to passwords on arbitrary exceptions.
            # HTTPForbidden is explicitly propagated by that service instead.
            try:
                service = self.services.get('saml_svc')
                if service is None:
                    raise RuntimeError('SAML service unavailable')
                return await service.saml_login_handler(request)
            except web.HTTPRedirection as redirect:
                if redirect.location == '/login':
                    raise web.HTTPForbidden(text='SAML sign-in could not complete. Contact your administrator.') from None
                raise
            except (web.HTTPUnauthorized, web.HTTPForbidden):
                raise
            except Exception:
                raise web.HTTPForbidden(text='SAML sign-in is unavailable. Please try again.') from None
        saml_svc = self.services.get('saml_svc', None)
        if not saml_svc:
            raise Exception('SAML service not found.')
        auth = await saml_svc.get_saml_auth(request)
        redirect = auth.login()
        raise web.HTTPFound(redirect)
