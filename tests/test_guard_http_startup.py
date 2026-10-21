"""Exercise the real aiohttp session/security chain in Caldera's load order."""
import asyncio
import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

security = pytest.importorskip('aiohttp_security')
session = pytest.importorskip('aiohttp_session')
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from aiohttp_security.abc import AbstractAuthorizationPolicy

from test_four_group_roles import owned_account


def test_guard_runs_inside_session_storage_and_preserves_unrelated_requests():
    svc, auth, info = owned_account()
    peer = 'peer@example.org'
    auth.user_map[peer] = auth.User(peer, 'unchanged', ('blue', 'app'))
    svc.set_saml_login_handler = AsyncMock()

    class CorePolicy(AbstractAuthorizationPolicy):
        async def authorized_userid(self, identity):
            return identity if identity in auth.user_map else None

        async def permits(self, identity, permission, context=None):
            user = auth.user_map.get(identity)
            return user is not None and permission in user.permissions

    async def exercise():
        app = web.Application()
        source = ast.parse((Path(__file__).parents[1] / 'hook.py').read_text())
        enable = next(n for n in source.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'enable')
        namespace = {'web': web, 'SamlService': lambda: svc}
        exec(compile(ast.Module(body=[enable], type_ignores=[]), 'saml-hook', 'exec'), namespace)
        await namespace['enable']({'app_svc': SimpleNamespace(application=app)})
        # Match Caldera: load plugins first, then AuthService.apply's setup.
        session.setup(app, session.SimpleCookieStorage())
        security.setup(app, security.SessionIdentityPolicy(), CorePolicy())
        executed = []

        async def login(request):
            response = web.Response(text='test login')
            await security.remember(request, response, request.query['who'])
            return response

        async def operation(request):
            who = await security.authorized_userid(request)
            if who is None:
                raise web.HTTPUnauthorized()
            executed.append(who)
            return web.Response(text=who)

        app.router.add_get('/login', login)
        app.router.add_get('/api/v2/operations', operation)
        async with TestClient(TestServer(app)) as client:
            assert (await client.get('/login', params={'who': info['email']})).status == 200
            assert (await client.get('/api/v2/operations')).status == 200
            old = auth.user_map[info['email']]
            svc._saml_config['user_provisioning']['update_on_login'] = False
            assert not await svc._apply_group_role({**info, 'groups': ['P']}, 'report')
            assert auth.user_map[info['email']] is old
            assert (await client.get('/api/v2/operations')).status == 403
            assert executed == [info['email']]
            assert (await client.get('/login', params={'who': peer})).status == 200
            assert (await client.get('/api/v2/operations')).status == 200
            client.session.cookie_jar.clear()
            assert (await client.get('/api/v2/operations')).status == 401
            assert await svc._apply_group_role(info, 'admin')
            assert (await client.get('/login', params={'who': info['email']})).status == 200
            assert (await client.get('/api/v2/operations')).status == 200

    asyncio.run(exercise())
