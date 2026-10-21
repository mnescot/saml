"""Exercise the real aiohttp session/security chain in Caldera's load order."""
import asyncio
import ast
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

security = pytest.importorskip('aiohttp_security')
session = pytest.importorskip('aiohttp_session')
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from aiohttp_security.abc import AbstractAuthorizationPolicy

from test_four_group_roles import owned_account


def test_guard_runs_inside_session_storage_and_preserves_unrelated_requests():
    svc, auth, info = owned_account()
    info['authn_expires_at'] = time.time() + 120
    peer = 'peer@example.org'
    peer_info = {'email': peer, 'name_id': 'peer-subject', 'groups': ['B']}
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

        async def core_login(request, username):
            response = web.HTTPFound('/')
            await security.remember(request, response, username)
            raise response

        async def logout(request):
            response = web.Response(text='signed out')
            await security.forget(request, response)
            return response

        auth.handle_successful_login = core_login

        async def saml_login(request):
            selected = peer_info if request.query.get('who') == peer else info
            return await svc._authenticate_user(request, 'blue' if selected is peer_info else 'admin', selected)

        async def operation(request):
            if request.headers.get('KEY') == 'test-machine-key':
                return web.Response(text='machine')
            who = await security.authorized_userid(request)
            if who is None:
                raise web.HTTPUnauthorized()
            executed.append(who)
            return web.Response(text=who)

        async def group_evidence(request):
            identity = await svc.verified_group_identity(request)
            assert not svc.current_group_identity(dict(identity)) if identity else True
            if identity:
                with pytest.raises(TypeError):
                    identity['groups'] = ('forged-admin',)
                assert svc.current_group_identity(identity)
            return web.json_response({'groups': list(identity['groups']) if identity else []})

        app.router.add_get('/login', login)
        app.router.add_get('/logout', logout)
        app.router.add_get('/saml/test-login', saml_login)
        app.router.add_get('/api/v2/operations', operation)
        app.router.add_get('/test/group-evidence', group_evidence)
        async with TestClient(TestServer(app)) as client:
            assert (await client.get('/login', params={'who': info['email']})).status == 200
            old_cookie = dict(client.session.cookie_jar.filter_cookies(client.make_url('/')))
            # Even a core password cookie cannot bypass group-only SSO.
            assert (await client.get('/api/v2/operations')).status == 401
            assert executed == []
            assert (await client.get('/saml/test-login', allow_redirects=False)).status == 302
            assert (await client.get('/api/v2/operations')).status == 200
            assert await (await client.get('/test/group-evidence')).json() == {'groups': ['A']}
            current_cookie = dict(client.session.cookie_jar.filter_cookies(client.make_url('/')))
            first_grant = next(iter(svc._group_role_session_markers[info['email']].values()))
            client.session.cookie_jar.clear()
            client.session.cookie_jar.update_cookies({k: v.value for k, v in old_cookie.items()})
            assert (await client.get('/test/group-evidence')).status == 401
            client.session.cookie_jar.clear()
            client.session.cookie_jar.update_cookies({k: v.value for k, v in current_cookie.items()})
            # Another unchanged SSO has its own marker and keeps the first alive.
            client.session.cookie_jar.clear()
            info['authn_expires_at'] = time.time() + 3600
            assert await svc._apply_group_role(info, 'admin')
            assert (await client.get('/saml/test-login', allow_redirects=False)).status == 302
            second_cookie = dict(client.session.cookie_jar.filter_cookies(client.make_url('/')))
            assert second_cookie != current_cookie
            for active_cookie in (current_cookie, second_cookie):
                client.session.cookie_jar.clear()
                client.session.cookie_jar.update_cookies({k: v.value for k, v in active_cookie.items()})
                assert await (await client.get('/test/group-evidence')).json() == {'groups': ['A']}
            # Newer SSO does not extend the older browser's authentication life.
            with patch('time.time', return_value=first_grant['expires_at'] + 1):
                assert not svc.current_group_identity(first_grant)
                client.session.cookie_jar.clear()
                client.session.cookie_jar.update_cookies({k: v.value for k, v in current_cookie.items()})
                assert (await client.get('/test/group-evidence')).status == 401
                client.session.cookie_jar.clear()
                client.session.cookie_jar.update_cookies({k: v.value for k, v in second_cookie.items()})
                assert await (await client.get('/test/group-evidence')).json() == {'groups': ['A']}
            client.session.cookie_jar.clear()
            assert (await client.get('/saml/test-login', allow_redirects=False)).status == 302
            current_cookie = dict(client.session.cookie_jar.filter_cookies(client.make_url('/')))
            client.session.cookie_jar.clear()
            client.session.cookie_jar.update_cookies({k: v.value for k, v in current_cookie.items()})
            assert (await client.get('/logout')).status == 200
            client.session.cookie_jar.clear()
            client.session.cookie_jar.update_cookies({k: v.value for k, v in current_cookie.items()})
            assert (await client.get('/test/group-evidence')).status == 401
            client.session.cookie_jar.clear()
            client.session.cookie_jar.update_cookies({k: v.value for k, v in second_cookie.items()})
            assert await (await client.get('/test/group-evidence')).json() == {'groups': ['A']}
            client.session.cookie_jar.clear()
            assert (await client.get('/saml/test-login', allow_redirects=False)).status == 302
            current_cookie = dict(client.session.cookie_jar.filter_cookies(client.make_url('/')))
            # Changed claims invalidate both grants before a new picker completes.
            assert await svc._apply_group_role({**info, 'groups': ['A', 'P']}, 'admin')
            for active_cookie in (current_cookie, second_cookie):
                client.session.cookie_jar.clear()
                client.session.cookie_jar.update_cookies({k: v.value for k, v in active_cookie.items()})
                assert (await client.get('/test/group-evidence')).status == 401
            for forged in ({'KEY': 'not-a-key'}, {'Authorization': 'Bearer not-a-token'}):
                client.session.cookie_jar.clear()
                client.session.cookie_jar.update_cookies({k: v.value for k, v in current_cookie.items()})
                rejected = await client.get('/api/v2/operations', headers=forged)
                assert rejected.status == 401
                assert executed == [info['email']]
            client.session.cookie_jar.clear()
            client.session.cookie_jar.update_cookies({k: v.value for k, v in current_cookie.items()})
            expired = await client.get('/test/group-evidence')
            assert expired.status == 401
            assert await expired.json() == {'error': 'saml_reauthentication_required', 'login_url': '/saml/login'}
            assert await svc._apply_group_role(info, 'admin')
            assert (await client.get('/saml/test-login', allow_redirects=False)).status == 302
            assert await (await client.get('/test/group-evidence')).json() == {'groups': ['A']}
            # Mixed headers neither lend cookie claims to API auth nor destroy
            # a correctly authenticated browser session.
            for mixed in ({'KEY': 'unused'}, {'Authorization': 'Bearer unused'}):
                assert await (await client.get('/test/group-evidence', headers=mixed)).json() == {'groups': []}
                assert await (await client.get('/test/group-evidence')).json() == {'groups': ['A']}
            old = auth.user_map[info['email']]
            svc._saml_config['user_provisioning']['update_on_login'] = False
            assert not await svc._apply_group_role({**info, 'groups': ['P']}, 'report')
            assert auth.user_map[info['email']] is old
            assert (await client.get('/api/v2/operations')).status == 403
            assert (await client.get('/test/group-evidence')).status == 403
            assert executed == [info['email']]
            peer_user = auth.user_map[peer]
            assert (await client.get('/login', params={'who': peer})).status == 200
            assert (await client.get('/api/v2/operations')).status == 401
            assert auth.user_map[peer] is peer_user
            assert await svc._apply_group_role(peer_info, 'blue')
            assert (await client.get('/saml/test-login', params={'who': peer}, allow_redirects=False)).status == 302
            assert (await client.get('/api/v2/operations')).status == 200
            assert await (await client.get('/test/group-evidence')).json() == {'groups': ['B']}
            client.session.cookie_jar.clear()
            assert (await client.get('/api/v2/operations')).status == 401
            assert await svc._apply_group_role(info, 'admin')
            assert (await client.get('/saml/test-login', allow_redirects=False)).status == 302
            assert (await client.get('/api/v2/operations')).status == 200
            restart_cookie = dict(client.session.cookie_jar.filter_cookies(client.make_url('/')))
            svc._group_role_identities.clear()
            svc._group_role_session_markers.clear()
            # A new serving process cannot restore grants from its predecessor.
            expired = await client.get('/api/v2/operations')
            assert expired.status == 401
            assert (await expired.json())['login_url'] == '/saml/login'
            client.session.cookie_jar.clear()
            client.session.cookie_jar.update_cookies({k: v.value for k, v in restart_cookie.items()})
            redirected = await client.get('/api/v2/operations', headers={'Accept': 'text/html'}, allow_redirects=False)
            assert redirected.status == 302 and redirected.headers['Location'] == '/saml/login'
            assert await svc._apply_group_role(info, 'admin')
            assert (await client.get('/saml/test-login', allow_redirects=False)).status == 302
            assert (await client.get('/api/v2/operations')).status == 200
            assert await (await client.get('/test/group-evidence')).json() == {'groups': ['A']}

            # Cookie-free machines still reach their independent route auth.
            client.session.cookie_jar.clear()
            machine = await client.get('/api/v2/operations', headers={'KEY': 'test-machine-key'})
            assert machine.status == 200 and await machine.text() == 'machine'
            assert (await client.get('/api/v2/operations', headers={'KEY': 'wrong'})).status == 401

    asyncio.run(exercise())
