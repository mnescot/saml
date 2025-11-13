import logging
from plugins.saml.app.saml_svc import SamlService

name = 'SAML'
description = 'A plugin that provides SAML authentication for CALDERA'
address = None

log = logging.getLogger('saml_plugin')

async def enable(services):
    """Enable SAML plugin and register routes"""
    log.info('Enabling SAML plugin...')

    app = services.get('app_svc').application

    # Create and register SAML service
    # Note: SamlService.__init__ will register itself in the service registry
    saml_svc = SamlService()

    # Verify service was registered
    if 'saml_svc' not in services:
        log.error('SAML service failed to register in service registry!')
        log.error('SAML authentication will not work. Check configuration.')
        return

    log.info('SAML service registered successfully')

    # Register SAML endpoints
    # Primary endpoints using /saml prefix (recommended for Entra ID)
    routes = [
        ('GET', '/saml/login', saml_svc.saml_login_handler, 'SAML login initiation'),
        ('POST', '/saml/acs', saml_svc.saml_acs_handler, 'SAML assertion consumer'),
        ('GET', '/saml/metadata', saml_svc.saml_metadata_handler, 'SAML SP metadata'),
        ('GET', '/saml/sls', saml_svc.saml_sls_handler, 'SAML single logout (GET)'),
        ('POST', '/saml/sls', saml_svc.saml_sls_handler, 'SAML single logout (POST)'),
        ('GET', '/saml', saml_svc.saml_login_handler, 'SAML legacy login'),
        ('POST', '/saml', saml_svc.saml_acs_handler, 'SAML legacy ACS'),
    ]

    for method, path, handler, desc in routes:
        app.router.add_route(method, path, handler)
        log.debug(f'Registered route: {method} {path} - {desc}')

    log.info('SAML plugin enabled successfully')
    log.info('Ensure auth.login.handler.module is set to: plugins.saml.app.saml_login_handler')