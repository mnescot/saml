"""The group-only policy must not inherit legacy role/domain/default grants."""
import asyncio
import itertools
from types import SimpleNamespace
from collections import namedtuple

from test_role_picker import _service, _AuthSvc

POLICY = {'enabled': True, 'groups': {'admin': ['A'], 'red': ['R'], 'blue': ['B'], 'report': ['P']}}


def service(auth=None):
    auth = auth or _AuthSvc()
    auth.User = namedtuple('User', 'username password permissions')
    svc = _service(auth_svc=auth)
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
