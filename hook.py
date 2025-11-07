from plugins.saml.app.saml_svc import SamlService

name = 'SAML'
description = 'A plugin that provides SAML authentication for CALDERA'
address = None

async def enable(services):
    app = services.get('app_svc').application
    saml_svc = SamlService()

    # Register SAML endpoints
    # Primary endpoints using /saml prefix (recommended for Entra ID)
    app.router.add_route('GET', '/saml/login', saml_svc.saml_login_handler)
    app.router.add_route('POST', '/saml/acs', saml_svc.saml_acs_handler)
    app.router.add_route('GET', '/saml/metadata', saml_svc.saml_metadata_handler)
    app.router.add_route('GET', '/saml/sls', saml_svc.saml_sls_handler)
    app.router.add_route('POST', '/saml/sls', saml_svc.saml_sls_handler)

    # Legacy /saml endpoint - handles both GET (login) and POST (ACS)
    # This maintains backward compatibility with older configurations
    app.router.add_route('GET', '/saml', saml_svc.saml_login_handler)
    app.router.add_route('POST', '/saml', saml_svc.saml_acs_handler)