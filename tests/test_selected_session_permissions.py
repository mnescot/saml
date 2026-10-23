"""The same operator can keep independent, least-privilege browser sessions."""
import ast
import asyncio
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
import aiohttp_security as security
import aiohttp_session as session
import pytest
from aiohttp_security.abc import AbstractAuthorizationPolicy

from test_four_group_roles import service


@pytest.mark.parametrize('groups', [['A', 'R', 'B', 'P'], ['R', 'B', 'P']])
def test_selected_roles_bound_core_permissions_in_concurrent_browser_sessions(groups):
    svc, auth = service()
    svc.set_saml_login_handler = AsyncMock()
    info = {'email': 'operator@example.org', 'name_id': 'verified-subject',
            'groups': groups}

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
    auth.Access = Access
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
            reset = svc._session_permission_scope.set(None) if request.query.get('fresh') else None
            try:
                if request.query.get('missing_marker'):
                    (await session.get_session(request)).pop('saml_assertion_marker', None)
                return web.json_response([p.value for p in await auth.get_permissions(request)])
            finally:
                if reset is not None:
                    svc._session_permission_scope.reset(reset)

        async def unscoped_policy(request):
            reset = svc._session_permission_scope.set(None)
            try:
                return web.json_response(await security.permits(request, 'red'))
            finally:
                svc._session_permission_scope.reset(reset)

        executed = []
        async def core_check(request):
            # Match core's check_authorization decorator: its return value
            # is ignored, so denied checks must raise before this handler runs.
            reset = svc._session_permission_scope.set(None) if request.query.get('fresh') else None
            try:
                if request.query.get('missing_marker'):
                    (await session.get_session(request)).pop('saml_assertion_marker', None)
                await auth.check_permissions(request.match_info['permission'], request)
                executed.append(request.match_info['permission'])
                return web.Response(text='allowed')
            finally:
                if reset is not None:
                    svc._session_permission_scope.reset(reset)

        app.router.add_get('/saml/select', select)
        app.router.add_get('/who', who)
        app.router.add_get('/machine-permissions', machine_permissions)
        app.router.add_get('/unscoped-policy', unscoped_policy)
        app.router.add_get('/core-check/{permission}', core_check)
        async with TestClient(TestServer(app)) as client:
            cookies = {}
            for role in svc._group_roles(info):
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
            for role in cookies:
                for key in (None, 'test-red-key', 'test-blue-key'):
                    client.session.cookie_jar.clear()
                    response = await client.get('/machine-permissions', cookies=cookies[role],
                                                headers={'KEY': key} if key else {})
                    assert await response.json() == list(svc._role_permissions(role))
                    for permission in ('red', 'blue', 'app'):
                        client.session.cookie_jar.clear()
                        before = len(executed)
                        response = await client.get('/core-check/' + permission, cookies=cookies[role],
                            headers={'KEY': key} if key else {})
                        assert response.status == (200 if permission in svc._role_permissions(role) else 403)
                        assert len(executed) == before + int(permission in svc._role_permissions(role))
            for role in cookies:
                client.session.cookie_jar.clear()
                # Raw policy checks without request scope never use a SAML
                # account ceiling, even when that account is Admin-eligible.
                response = await client.get('/unscoped-policy', cookies=cookies[role])
                assert await response.json() is False
                # The request-aware APIs recover only this browser's live
                # marker and selected role in a fresh ContextVar context.
                response = await client.get('/machine-permissions?fresh=1', cookies=cookies[role],
                    headers={'KEY': 'test-red-key'})
                assert await response.json() == list(svc._role_permissions(role))
                for permission in ('red', 'blue', 'app'):
                    response = await client.get('/core-check/' + permission + '?fresh=1',
                        cookies=cookies[role], headers={'KEY': 'test-red-key'})
                    assert response.status == (200 if permission in svc._role_permissions(role) else 403)
            for role in cookies:
                for path in ('/machine-permissions', '/core-check/red'):
                    client.session.cookie_jar.clear()
                    response = await client.get(path + '?fresh=1&missing_marker=1', cookies=cookies[role],
                        headers={'KEY': 'test-red-key'})
                    assert response.status == 403
            client.session.cookie_jar.clear()
            assert auth.user_map[info['email']].permissions == ('red', 'blue', 'app')
            # Switching this browser to Red retires its old Admin grant while
            # other browsers retain their own independently selected roles.
            previous, selected = ('admin', 'red') if 'admin' in cookies else ('red', 'blue')
            client.session.cookie_jar.update_cookies(cookies[previous])
            assert (await client.get('/saml/select', params={'role': selected}, allow_redirects=False)).status == 302
            assert (await (await client.get('/who')).json())['role'] == selected
            client.session.cookie_jar.clear()
            assert (await client.get('/who', cookies=cookies[previous])).status == 401
            for role in ('blue', 'report'):
                client.session.cookie_jar.clear()
                await check(role)
            for native in ('red', 'blue'):
                client.session.cookie_jar.clear()
                response = await client.get('/machine-permissions', headers={'KEY': 'test-' + native + '-key'})
                assert await response.json() == [native, 'app']
                for permission in ('red', 'blue', 'app'):
                    # Key-only requests retain core's existing grants.
                    response = await client.get('/core-check/' + permission,
                                                headers={'KEY': 'test-' + native + '-key'})
                    assert response.status == 200
                # A browser carrying a machine key still cannot escape its
                # selected role through core's account-based enumerator.
                response = await client.get('/machine-permissions', cookies=cookies['blue'],
                                            headers={'KEY': 'test-' + native + '-key'})
                assert await response.json() == ['blue', 'app']
            # Removing the selected entitlement invalidates existing grants.
            assert await svc._apply_group_role({**info, 'groups': ['P']}, 'report')
            for cookie in cookies.values():
                assert (await client.get('/who', cookies=cookie)).status == 401

    asyncio.run(exercise())


def test_group_mode_requires_the_core_permission_checker_at_startup():
    svc, auth = service()
    auth.check_permissions = None
    app = web.Application()
    from aiohttp_security import api
    app[api.AUTZ_KEY] = SimpleNamespace()
    with pytest.raises(RuntimeError, match='AuthService.check_permissions'):
        svc.install_session_permissions(app)


@pytest.mark.parametrize('header', ['Authorization', 'KEY'])
def test_alternate_credentials_cannot_inherit_an_ambient_browser_role(header):
    svc, _ = service()
    svc._session_group_identity = AsyncMock()
    request = SimpleNamespace(headers={header: 'unverified credential'}, cookies={'API_SESSION': 'ambient'})
    assert asyncio.run(svc.verified_group_identity(request)) is None
    svc._session_group_identity.assert_not_called()


def test_group_mode_fails_startup_if_permission_installation_has_no_scope():
    svc, _ = service()
    svc.set_saml_login_handler = AsyncMock()
    svc.install_session_permissions = Mock()

    async def exercise():
        app = web.Application()
        tree = ast.parse((Path(__file__).parents[1] / 'hook.py').read_text())
        enable = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'enable')
        namespace = {'web': web, 'SamlService': lambda: svc}
        exec(compile(ast.Module(body=[enable], type_ignores=[]), 'saml-hook', 'exec'), namespace)
        await namespace['enable']({'app_svc': SimpleNamespace(application=app)})
        app.freeze()
        with pytest.raises(RuntimeError, match='authorization was not installed'):
            await app.startup()
    asyncio.run(exercise())
