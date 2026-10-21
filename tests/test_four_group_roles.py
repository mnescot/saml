"""The group-only policy must not inherit legacy role/domain/default grants."""
import asyncio
import itertools
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest

from test_role_picker import _service, _AuthSvc

POLICY = {'enabled': True, 'groups': {'admin': ['A'], 'red': ['R'], 'blue': ['B'], 'report': ['P']}}


def service(auth=None):
    auth = auth or _AuthSvc()
    svc = _service(auth_svc=auth)
    svc._pending_auth = {}
    svc._saml_config = {'group_role_policy': POLICY, 'user_provisioning': {
        'enabled': True, 'create_missing_users': True, 'update_on_login': True,
        'default_role': 'admin', 'admin_roles': ['admin']}}
    svc._user_mapping_config = {'email_domain_mappings': {'example.org': 'red'},
                                'role_mappings': {'red': ['pentester']}}
    return svc, auth


def test_all_sixteen_membership_combinations_are_order_independent_and_group_only():
    svc, _ = service()
    names = ('admin', 'red', 'blue', 'report')
    for bits in itertools.product((False, True), repeat=4):
        groups = [POLICY['groups'][role][0] for role, bit in zip(names, bits) if bit]
        info = {'email': 'a@example.org', 'roles': ['admin', 'pentester'], 'groups': groups[::-1]}
        expected = [role for role, bit in zip(names, bits) if bit]
        assert svc._group_roles(info) == expected
        assert svc._entitled_roles(info) == set(expected)
        assert svc._matched_caldera_role(info) == next(iter(expected), None)


def test_none_and_unknown_groups_show_no_access_without_provisioning():
    svc, auth = service()
    svc._peek_pending_auth = lambda token: {'email': 'a@example.org', 'groups': ['other']}
    request = SimpleNamespace(method='GET', rel_url=SimpleNamespace(query={'token': 'one'}))
    result = asyncio.run(svc.saml_role_select_handler(request))
    assert result.status == 403 and 'No access' in result.text
    assert not auth.user_map


def test_picker_offers_exact_roles_and_displays_highest_permission_rule():
    svc, _ = service()
    svc._peek_pending_auth = lambda token: {'email': 'a@example.org', 'groups': ['P', 'B']}
    request = SimpleNamespace(method='GET', rel_url=SimpleNamespace(query={'token': '<test>'}))
    result = asyncio.run(svc.saml_role_select_handler(request))
    assert 'value="blue"' in result.text and 'value="report"' in result.text
    assert 'value="red"' not in result.text and 'value="admin"' not in result.text
    assert '&lt;test&gt;' in result.text and 'highest role' in result.text


def test_report_core_permission_is_app_only_and_downgrades_old_red_account():
    svc, auth = service()
    auth.user_map['a@example.org'] = auth.User('a@example.org', 'preserved', ('red', 'app'))
    info = {'email': 'a@example.org', 'groups': ['P']}
    assert asyncio.run(svc._apply_group_role(info, 'report'))
    assert auth.user_map['a@example.org'].permissions == ('app',)
    assert auth.user_map['a@example.org'].password == 'preserved'
    assert not asyncio.run(svc._apply_group_role(info, 'admin'))


def test_lower_picker_choice_cannot_override_highest_group_role():
    svc, auth = service()
    info = {'email': 'a@example.org', 'groups': ['P', 'A']}
    assert not asyncio.run(svc._apply_group_role(info, 'report'))
    assert asyncio.run(svc._apply_group_role(info, 'admin'))
    assert auth.user_map['a@example.org'].permissions == ('red', 'blue', 'app')


def test_provisioning_opt_out_still_prevents_creating_accounts():
    svc, auth = service()
    svc._saml_config['user_provisioning']['enabled'] = False
    assert not asyncio.run(svc._apply_group_role({'email': 'a@example.org', 'groups': ['A']}, 'admin'))
    assert not auth.user_map


def test_posting_lower_owned_role_still_applies_highest_permissions_and_consumes_pending_auth():
    svc, auth = service()
    info = {'email': 'a@example.org', 'groups': ['P', 'A']}
    popped = []
    svc._pop_pending_auth = lambda token: (popped.append(token) or info)
    seen = []
    async def authenticate(request, role, user_info):
        seen.append(role)
        return 'signed-in'
    svc._authenticate_user = authenticate
    async def post():
        return {'token': 'one-use', 'role': 'report'}
    request = SimpleNamespace(method='POST', post=post)
    assert asyncio.run(svc.saml_role_select_handler(request)) == 'signed-in'
    assert seen == ['admin'] and popped == ['one-use']
    assert auth.user_map['a@example.org'].permissions == ('red', 'blue', 'app')


def test_forged_admin_post_is_denied_before_any_account_mutation():
    svc, auth = service()
    svc._pop_pending_auth = lambda token: {'email': 'a@example.org', 'groups': ['P']}
    async def post():
        return {'token': 'one-use', 'role': 'admin'}
    result = asyncio.run(svc.saml_role_select_handler(SimpleNamespace(method='POST', post=post)))
    assert result.status == 403 and 'No access' in result.text
    assert not auth.user_map


def test_deployment_environment_policy_prevents_fallback_on_missing_or_malformed_settings():
    import json
    from unittest.mock import patch
    svc, _ = service()
    svc._saml_config = {}
    with patch.dict('os.environ', {'CALDERA_SAML_RBAC_POLICY': json.dumps(POLICY)}):
        assert svc._group_roles({'groups': ['B']}) == ['blue']
        assert svc._entitled_roles({'groups': [], 'roles': ['admin']}) == set()
    for raw in ('broken', '[]', '{"enabled":false}'):
        with patch.dict('os.environ', {'CALDERA_SAML_RBAC_POLICY': raw}):
            assert svc._entitled_roles({'groups': ['A'], 'roles': ['admin']}) == set()


def test_no_membership_get_does_not_remove_an_existing_core_account():
    svc, auth = service()
    auth.user_map['a@example.org'] = auth.User('a@example.org', 'old', ('red', 'app'))
    svc._peek_pending_auth = lambda token: {'email': 'a@example.org', 'groups': []}
    request = SimpleNamespace(method='GET', rel_url=SimpleNamespace(query={'token': 'signed'}))
    result = asyncio.run(svc.saml_role_select_handler(request))
    assert result.status == 403
    assert 'a@example.org' in auth.user_map


def owned_account():
    svc, auth = service()
    info = {'email': 'a@example.org', 'name_id': 'stable-subject', 'groups': ['A']}
    assert asyncio.run(svc._apply_group_role(info, 'admin'))
    return svc, auth, info


def deny_post(svc, info):
    token = svc._store_pending_auth(info)
    request = SimpleNamespace(method='POST', post=AsyncMock(return_value={'token': token}))
    result = asyncio.run(svc.saml_role_select_handler(request))
    assert result.status == 403
    assert svc._pop_pending_auth(token) is None
    return result


def test_revocation_post_removes_only_an_account_bound_to_the_verified_subject():
    svc, auth, info = owned_account()
    # Email can change; the binding is the verified subject, not a new mail value.
    auth.user_map['other@example.org'] = auth.User('other@example.org', 'local', ('red', 'app'))
    deny_post(svc, {**info, 'groups': [], 'email': 'other@example.org'})
    assert 'a@example.org' not in auth.user_map
    assert auth.user_map['other@example.org'].password == 'local'


@pytest.mark.parametrize('option', ['enabled', 'update_on_login'])
def test_revocation_respects_each_provisioning_opt_out(option):
    svc, auth, info = owned_account()
    svc._saml_config['user_provisioning'][option] = False
    deny_post(svc, {**info, 'groups': []})
    assert 'a@example.org' in auth.user_map
    assert guarded_response(svc, 'a@example.org').status == 403


def test_revocation_cannot_target_an_unrelated_or_replaced_account():
    svc, auth, info = owned_account()
    deny_post(svc, {**info, 'groups': [], 'name_id': 'different-subject'})
    assert 'a@example.org' in auth.user_map
    replacement = auth.User('a@example.org', 'new-local-account', ('blue', 'app'))
    auth.user_map['a@example.org'] = replacement
    deny_post(svc, {**info, 'groups': []})
    assert auth.user_map['a@example.org'] is replacement
    assert not svc._group_role_accounts


def test_denied_get_consumes_token_without_mutating_even_an_owned_account():
    svc, auth, info = owned_account()
    token = svc._store_pending_auth({**info, 'groups': []})
    request = SimpleNamespace(method='GET', rel_url=SimpleNamespace(query={'token': token}))
    assert asyncio.run(svc.saml_role_select_handler(request)).status == 403
    assert svc._pop_pending_auth(token) is None
    assert 'a@example.org' in auth.user_map


def test_role_changes_retain_subject_binding_but_a_different_subject_is_denied():
    svc, auth, info = owned_account()
    assert asyncio.run(svc._apply_group_role({**info, 'groups': ['B']}, 'blue'))
    assert not asyncio.run(svc._apply_group_role({**info, 'name_id': 'other'}, 'admin'))
    deny_post(svc, {**info, 'groups': []})
    assert 'a@example.org' not in auth.user_map


@pytest.mark.parametrize('updates', [True, False])
def test_renamed_subject_retires_old_username_before_lower_role_login(updates):
    svc, auth, info = owned_account()
    svc._saml_config['user_provisioning']['update_on_login'] = updates
    renamed = {**info, 'email': 'new@example.org', 'groups': ['P']}
    assert asyncio.run(svc._apply_group_role(renamed, 'report'))
    assert auth.user_map['new@example.org'].permissions == ('app',)
    if updates:
        assert info['email'] not in auth.user_map
    else:
        assert info['email'] in auth.user_map
        assert guarded_response(svc, info['email']).status == 403
    assert guarded_response(svc, renamed['email']).status == 200


def test_verified_no_access_acs_post_revokes_owned_session_before_a_picker_exists():
    svc, auth, info = owned_account()
    response = SimpleNamespace(get_identity=lambda: {'email': [info['email']]},
                               get_subject=lambda: SimpleNamespace(text=info['name_id']))
    svc._get_saml2_client = lambda: SimpleNamespace(parse_authn_request_response=lambda *args: response)
    consumed = []
    svc._claim_assertion = lambda assertion: (consumed.append(assertion) or True)
    request = SimpleNamespace(method='POST', path='/saml',
                              post=AsyncMock(return_value={'SAMLResponse': 'verified'}))
    assert asyncio.run(svc._saml_login(request)).status == 403
    assert consumed == [response]
    assert 'a@example.org' not in auth.user_map
    assert not svc._pending_auth


@pytest.mark.parametrize('updates', [True, False])
def test_fresh_downgrade_reconciles_before_any_picker_submission(updates):
    from aiohttp import web
    svc, auth, info = owned_account()
    svc._saml_config['user_provisioning']['update_on_login'] = updates
    response = SimpleNamespace(
        get_identity=lambda: {'email': [info['email']], 'groups': ['P']},
        get_subject=lambda: SimpleNamespace(text=info['name_id']))
    svc._get_saml2_client = lambda: SimpleNamespace(parse_authn_request_response=lambda *args: response)
    svc._claim_assertion = lambda assertion: True
    request = SimpleNamespace(method='POST', path='/saml/acs',
                              post=AsyncMock(return_value={'SAMLResponse': 'verified'}))
    if updates:
        with pytest.raises(web.HTTPFound) as redirect:
            asyncio.run(svc.saml_acs_handler(request))
        assert redirect.value.location.startswith('/saml/role-select?token=')
        assert auth.user_map[info['email']].permissions == ('app',)
        # An invalid choice cannot undo the already-applied downgrade.
        token = next(iter(svc._pending_auth))
        invalid = SimpleNamespace(method='POST', post=AsyncMock(return_value={'token': token, 'role': 'admin'}))
        assert asyncio.run(svc.saml_role_select_handler(invalid)).status == 403
        assert auth.user_map[info['email']].permissions == ('app',)
    else:
        assert asyncio.run(svc.saml_acs_handler(request)).status == 403
        assert not svc._pending_auth
        assert guarded_response(svc, info['email']).status == 403


def guarded_response(svc, username, path='/api/v2/operations'):
    import sys
    import types
    from unittest.mock import patch
    from aiohttp import web
    security = types.ModuleType('aiohttp_security')
    security.authorized_userid = AsyncMock(return_value=username)
    handler = AsyncMock(return_value=web.Response(text='allowed'))
    with patch.dict(sys.modules, {'aiohttp_security': security}):
        result = asyncio.run(svc.guard_group_session(SimpleNamespace(path=path), handler))
    assert handler.await_count == (0 if result.status == 403 else 1)
    return result


def test_failed_downgrade_blocks_old_sessions_without_changing_a_protected_account():
    svc, auth, info = owned_account()
    old = auth.user_map[info['email']]
    svc._saml_config['user_provisioning']['update_on_login'] = False
    assert not asyncio.run(svc._apply_group_role({**info, 'groups': ['P']}, 'report'))
    assert auth.user_map[info['email']] is old
    assert guarded_response(svc, info['email']).status == 403
    assert guarded_response(svc, 'someone-else').status == 200
    assert guarded_response(svc, info['email'], '/saml/login').status == 200
    # Restored membership can recover without an account update.
    assert asyncio.run(svc._apply_group_role(info, 'admin'))
    assert auth.user_map[info['email']] is old
    assert guarded_response(svc, info['email']).status == 200


def test_preconfigured_account_can_have_saml_sessions_revoked_without_deletion():
    svc, auth = service()
    old = auth.User('a@example.org', 'manual', ('red', 'app'))
    auth.user_map[old.username] = old
    info = {'email': old.username, 'name_id': 'stable', 'groups': ['R']}
    assert asyncio.run(svc._apply_group_role(info, 'red'))
    svc._saml_config['user_provisioning']['update_on_login'] = False
    assert not asyncio.run(svc._apply_group_role({**info, 'groups': ['P']}, 'report'))
    assert auth.user_map[old.username] is old
    assert guarded_response(svc, old.username).status == 403
    deny_post(svc, {**info, 'groups': []})
    assert auth.user_map[old.username] is old
    assert guarded_response(svc, old.username).status == 403
    # A new unrelated local entry is never subject to a stale denial.
    auth.user_map[old.username] = auth.User(old.username, 'replacement', old.permissions)
    assert guarded_response(svc, old.username).status == 200


def test_unmapped_subject_cannot_revoke_an_unbound_local_account():
    svc, auth = service()
    old = auth.User('admin', 'break-glass', ('red', 'app'))
    auth.user_map['admin'] = old
    deny_post(svc, {'email': 'admin', 'name_id': 'foreign', 'groups': []})
    assert auth.user_map['admin'] is old
    assert guarded_response(svc, 'admin').status == 200


def test_plugin_enable_registers_the_session_guard():
    import ast
    from pathlib import Path
    from aiohttp import web
    svc, _ = service()
    svc.set_saml_login_handler = AsyncMock()
    source = ast.parse((Path(__file__).parents[1] / 'hook.py').read_text())
    enable = next(n for n in source.body if isinstance(n, ast.AsyncFunctionDef) and n.name == 'enable')
    namespace = {'web': web, 'SamlService': lambda: svc}
    exec(compile(ast.Module(body=[enable], type_ignores=[]), 'saml-hook', 'exec'), namespace)
    async def check():
        app = web.Application()
        await namespace['enable']({'app_svc': SimpleNamespace(application=app)})
        assert len(app.middlewares) == 0
        app.on_startup.freeze()
        await app.startup()
        assert len(app.middlewares) == 1
        handler = AsyncMock(return_value=web.Response(text='allowed'))
        assert (await app.middlewares[0](SimpleNamespace(path='/api/v2/operations'), handler)).status == 200
        svc.set_saml_login_handler.assert_awaited_once()
    asyncio.run(check())


def test_entra_group_claim_uri_works_without_an_attribute_override():
    svc, _ = service()
    info = svc._extract_user_info_from_identity({
        'email': ['a@example.org'],
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups': ['A', 'P'],
    }, SimpleNamespace(text='subject'))
    assert info['groups'] == ['A', 'P']
    assert svc._group_roles(info) == ['admin', 'report']


def test_configured_group_attribute_retains_precedence_over_entra_fallback():
    svc, _ = service()
    svc._saml_config['user_provisioning']['group_attribute'] = 'custom-groups'
    info = svc._extract_user_info_from_identity({
        'email': ['a@example.org'], 'custom-groups': ['P'],
        'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups': ['A'],
    }, SimpleNamespace(text='subject'))
    assert svc._group_roles(info) == ['report']


def login_handler(services):
    import importlib.util
    import pathlib
    import sys
    import types
    # Model only the core interface; the handler implementation executes intact.
    class Interface:
        def __init__(self, *args):
            pass
    module = types.ModuleType('app.service.interfaces.i_login_handler')
    module.LoginHandlerInterface = Interface
    sys.modules.setdefault(module.__name__, module)
    spec = importlib.util.spec_from_file_location('group_login_handler',
        pathlib.Path(__file__).parents[1] / 'app/saml_login_handler.py')
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded.SamlLoginHandler(services)


def test_password_submission_cannot_bypass_saml_group_authorization():
    from unittest.mock import AsyncMock, Mock, patch
    from aiohttp import web
    auth = SimpleNamespace(default_login_handler=SimpleNamespace(handle_login=AsyncMock()))
    saml = SimpleNamespace(saml_login_handler=AsyncMock(side_effect=web.HTTPFound('/idp')))
    handler = login_handler({'auth_svc': auth, 'saml_svc': saml})
    request = SimpleNamespace(post=AsyncMock(return_value={'username': 'red', 'password': 'old'}))
    with patch.dict('os.environ', {'CALDERA_SAML_RBAC_POLICY': '{"enabled":true}'}):
        try:
            asyncio.run(handler.handle_login(request))
        except web.HTTPFound as response:
            assert response.location == '/idp'
        else:
            raise AssertionError('SAML redirect required')
    auth.default_login_handler.handle_login.assert_not_called()
    saml.saml_login_handler.assert_awaited_once_with(request)


def test_saml_failure_raises_forbidden_so_core_never_uses_password_fallback():
    from unittest.mock import AsyncMock, patch
    from aiohttp import web
    for saml in (None, SimpleNamespace(saml_login_handler=AsyncMock(side_effect=RuntimeError('unavailable')))):
        handler = login_handler({'saml_svc': saml})
        with patch.dict('os.environ', {'CALDERA_SAML_RBAC_POLICY': '{"enabled":true}'}):
            try:
                asyncio.run(handler.handle_login_redirect(SimpleNamespace()))
            except web.HTTPForbidden:
                pass
            else:
                raise AssertionError('fail closed with an exception core explicitly propagates')


def test_missing_saml_service_cannot_fall_back_to_passwords_without_environment_policy(monkeypatch):
    from aiohttp import web
    monkeypatch.delenv('CALDERA_SAML_RBAC_POLICY', raising=False)
    auth = SimpleNamespace(default_login_handler=SimpleNamespace(handle_login=AsyncMock()))
    handler = login_handler({'auth_svc': auth})
    request = SimpleNamespace(post=AsyncMock(return_value={'username': 'red', 'password': 'old'}))
    with pytest.raises(web.HTTPForbidden):
        asyncio.run(handler.handle_login(request))
    auth.default_login_handler.handle_login.assert_not_called()


def test_group_login_error_redirect_is_denied_instead_of_looping():
    from unittest.mock import patch
    from aiohttp import web
    saml = SimpleNamespace(saml_login_handler=AsyncMock(side_effect=web.HTTPFound('/login')))
    handler = login_handler({'saml_svc': saml})
    with patch.dict('os.environ', {'CALDERA_SAML_RBAC_POLICY': '{"enabled":true}'}):
        with pytest.raises(web.HTTPForbidden):
            asyncio.run(handler.handle_login_redirect(SimpleNamespace()))


@pytest.mark.parametrize('failure', ['parse', 'missing_identity', 'replay', 'client_init'])
@pytest.mark.parametrize('path', ['/saml/acs', '/auth/saml/acs', '/saml'])
def test_direct_acs_failure_is_denied_without_a_login_redirect(failure, path):
    from aiohttp import web
    svc, _ = service()
    svc.log = SimpleNamespace(debug=lambda *args: None, error=lambda *args: None,
                              exception=lambda *args: None)
    def parse(*args):
        if failure == 'parse':
            raise ValueError('bad assertion')
        return SimpleNamespace(get_identity=lambda: {}, get_subject=lambda: SimpleNamespace(text='id'))
    def client():
        if failure == 'client_init':
            raise ValueError('IdP unavailable')
        return SimpleNamespace(parse_authn_request_response=parse)
    svc._get_saml2_client = client
    svc._claim_assertion = lambda response: failure != 'replay'
    request = SimpleNamespace(method='POST', path=path,
                              post=AsyncMock(return_value={'SAMLResponse': 'bad'}))
    with pytest.raises(web.HTTPForbidden):
        asyncio.run(svc.saml(request) if path == '/saml' else svc.saml_acs_handler(request))
