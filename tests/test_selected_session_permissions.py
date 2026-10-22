"""The same operator can keep independent, least-privilege browser sessions."""
import ast
import asyncio
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
import aiohttp_security as security
import aiohttp_session as session
from aiohttp_security.abc import AbstractAuthorizationPolicy

from test_four_group_roles import service


def test_selected_roles_bound_core_permissions_in_concurrent_browser_sessions():
    svc, auth = service()
    svc.set_saml_login_handler = AsyncMock()
    info = {'email': 'operator@example.org', 'name_id': 'verified-subject',
            'groups': ['A', 'R', 'B', 'P']}

    class Access(Enum):
        RED = 'red'
        BLUE = 'blue'
        APP = 'app'

    class CorePolicy(AbstractAuthorizationPolicy):
        async def authorized_userid(self, identity):
            return identity if identity in auth.user_map else None

        async def permits(self, identity, permission, context=None):
            return permission in auth.user_map[identity].permissions

    async def native_permissions(request):
        if request.headers.get('KEY') in ('test-red-key', 'test-blue-key'):
            native = 'red' if request.headers['KEY'] == 'test-red-key' else 'blue'
            return [Access[native.upper()], Access.APP]
        who = await security.authorized_userid(request)
        return [Access[p.upper()] for p in auth.user_map[who].permissions]

    auth.get_permissions = native_permissions
    auth.request_has_valid_api_key = lambda request: request.headers.get('KEY') in ('test-red-key', 'test-blue-key')

    async def exercise():
        app = web.Application()
        tree = ast.parse((Path(__file__).parents[1] / 'hook.py').read_text())
        enable = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'enable')
        namespace = {'web': web, 'SamlService': lambda: svc}
        exec(compile(ast.Module(body=[enable], type_ignores=[]), 'saml-hook', 'exec'), namespace)
        await namespace['enable']({'app_svc': SimpleNamespace(application=app)})
        session.setup(app, session.SimpleCookieStorage())
        security.setup(app, security.SessionIdentityPolicy(), CorePolicy())

        async def core_login(request, username):
            response = web.HTTPFound('/')
            await security.remember(request, response, username)
            raise response
        auth.handle_successful_login = core_login

        async def select(request):
            current = dict(info)
            role = request.query['role']
            assert await svc._apply_group_role(current, role)
            return await svc._authenticate_user(request, role, current)

        async def who(request):
            await asyncio.sleep(0.01)  # Interleave different sessions deliberately.
            record = await svc.verified_group_identity(request)
            checked = [name for name in ('red', 'blue', 'app') if await security.permits(request, name)]
            enumerated = [p.value for p in await auth.get_permissions(request)]
            return web.json_response({'role': record['selected_role'], 'checked': checked,
                                      'enumerated': enumerated})

        async def machine_permissions(request):
            return web.json_response([p.value for p in await auth.get_permissions(request)])

        app.router.add_get('/saml/select', select)
        app.router.add_get('/who', who)
        app.router.add_get('/machine-permissions', machine_permissions)
        async with TestClient(TestServer(app)) as client:
            cookies = {}
            for role in ('admin', 'red', 'blue', 'report'):
                client.session.cookie_jar.clear()
                assert (await client.get('/saml/select', params={'role': role}, allow_redirects=False)).status == 302
                cookies[role] = {key: value.value for key, value in
                                 client.session.cookie_jar.filter_cookies(client.make_url('/')).items()}
            client.session.cookie_jar.clear()
            async def check(role):
                response = await client.get('/who', cookies=cookies[role])
                assert response.status == 200
                payload = await response.json()
                assert payload['role'] == role
                expected = list(svc._role_permissions(role))
                assert payload['checked'] == expected
                assert payload['enumerated'] == expected
            await asyncio.gather(*(check(role) for role in cookies for _ in range(3)))
            assert auth.user_map[info['email']].permissions == ('red', 'blue', 'app')
            # Switching this browser to Red retires its old Admin grant while
            # other browsers retain their own independently selected roles.
            client.session.cookie_jar.update_cookies(cookies['admin'])
            assert (await client.get('/saml/select', params={'role': 'red'}, allow_redirects=False)).status == 302
            assert (await (await client.get('/who')).json())['role'] == 'red'
            client.session.cookie_jar.clear()
            assert (await client.get('/who', cookies=cookies['admin'])).status == 401
            for role in ('blue', 'report'):
                client.session.cookie_jar.clear()
                await check(role)
            for native in ('red', 'blue'):
                client.session.cookie_jar.clear()
                response = await client.get('/machine-permissions', headers={'KEY': 'test-' + native + '-key'})
                assert await response.json() == [native, 'app']
            # Removing the selected entitlement invalidates existing grants.
            assert await svc._apply_group_role({**info, 'groups': ['P']}, 'report')
            for cookie in cookies.values():
                assert (await client.get('/who', cookies=cookie)).status == 401

    asyncio.run(exercise())
