"""The role picker must offer every entitlement, and apply what it promises.

Two defects found in review of #6, both of which make the picker lie:

* `_matched_caldera_role` returned on the FIRST match, so whether Red was even
  offered depended on the ORDER of keys in user_mapping.json and on the order
  groups arrived in the assertion. The picker exists for users with more than
  one entitlement, so that is the case it got wrong.
* the selected role never reached the session unless `_provision_user` happened
  to run and succeed, so selecting Blue on a red account produced a RED session
  while the UI said Blue had been applied.

Self-contained: `saml_svc` imports Caldera and pysaml2 at module scope, neither
of which is available to a plugin's own test run, so both are stubbed. The
methods under test touch neither.
"""

import asyncio
import importlib.util
import pathlib
import sys
import types
import unittest


def _stub(name: str, **attrs) -> None:
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules.setdefault(name, module)


def _load_saml_svc():
    class _BaseService:
        def add_service(self, *_a, **_kw):
            return None

        def get_service(self, _name):
            return None

    _stub('app')
    _stub('app.utility')
    _stub('app.utility.base_service', BaseService=_BaseService)
    _stub('saml2', BINDING_HTTP_POST='post', BINDING_HTTP_REDIRECT='redirect')
    _stub('saml2.client', Saml2Client=object)
    _stub('saml2.config', Config=object)
    _stub('saml2.metadata', create_metadata_string=lambda *a, **k: b'')
    _stub('saml2.response', AuthnResponse=object)

    path = pathlib.Path(__file__).resolve().parents[1] / 'app' / 'saml_svc.py'
    spec = importlib.util.spec_from_file_location('saml_svc_under_test', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SAML = _load_saml_svc()


class _User:
    """Stands in for Caldera's User namedtuple."""

    def __init__(self, username, password, permissions):
        self.username = username
        self.password = password
        self.permissions = permissions


class _AuthSvc:
    def __init__(self, user_map=None, fail=False):
        self.user_map = user_map or {}
        self.fail = fail
        self.created = []

    async def create_user(self, username, password, group):
        if self.fail:
            raise RuntimeError('simulated create_user failure')
        self.created.append((username, group))
        self.user_map[username] = _User(username, password, (group, 'app'))


def _service(mapping=None, auth_svc=None, log=None):
    """A SamlService without running __init__, which needs real config."""
    svc = object.__new__(SAML.SamlService)
    svc._user_mapping_config = mapping or {}
    svc._saml_config = {}
    svc.log = log or _Log()
    svc.get_service = lambda _name: auth_svc
    return svc


class _Log:
    def __init__(self):
        self.errors = []

    def _noop(self, *a, **k):
        pass

    info = debug = warning = _noop

    def error(self, *a, **k):
        self.errors.append(a)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class AssertedRolesTests(unittest.TestCase):
    """Order independence: two users with identical entitlements must get the
    same picker."""

    MAPPING = {
        # Blue deliberately listed FIRST -- the ordering that hid Red.
        'role_mappings': {'blue': ['soc-analyst'], 'red': ['pentester']},
        'group_mappings': {'blue-team': 'blue', 'red-team': 'red'},
    }

    def setUp(self):
        self.svc = _service(self.MAPPING)
        self.svc._admin_allowlists = lambda: (set(), set())
        self.svc._normalize_caldera_role = lambda r: str(r).lower()

    def test_a_user_matching_both_gets_both(self):
        info = {'roles': ['soc-analyst', 'pentester'], 'groups': [], 'email': 'a@x'}
        self.assertEqual({'blue', 'red'}, self.svc._asserted_caldera_roles(info))

    def test_group_matches_aggregate_too(self):
        info = {'roles': [], 'groups': ['blue-team', 'red-team'], 'email': 'a@x'}
        self.assertEqual({'blue', 'red'}, self.svc._asserted_caldera_roles(info))

    def test_the_result_does_not_depend_on_assertion_order(self):
        forward = {'roles': ['soc-analyst', 'pentester'], 'groups': [], 'email': 'a@x'}
        reverse = {'roles': ['pentester', 'soc-analyst'], 'groups': [], 'email': 'a@x'}
        self.assertEqual(self.svc._asserted_caldera_roles(forward),
                         self.svc._asserted_caldera_roles(reverse))

    def test_the_most_privileged_asserted_role_wins(self):
        info = {'roles': ['soc-analyst', 'pentester'], 'groups': [], 'email': 'a@x'}
        self.assertEqual('red', self.svc._matched_caldera_role(info))

    def test_no_match_is_still_none(self):
        """None must survive: _entitled_roles relies on it to withhold Red, and
        _matched_caldera_role never falls back to default_role."""
        info = {'roles': ['unmapped'], 'groups': [], 'email': 'a@x'}
        self.assertIsNone(self.svc._matched_caldera_role(info))

    def test_blue_only_stays_blue_only(self):
        info = {'roles': ['soc-analyst'], 'groups': [], 'email': 'a@x'}
        self.assertEqual({'blue'}, self.svc._asserted_caldera_roles(info))
        self.assertEqual('blue', self.svc._matched_caldera_role(info))


class ApplySelectedRoleTests(unittest.TestCase):
    """The picker has already told the user the role was applied."""

    def _svc(self, auth_svc, provisioning=None, entitled=('blue',)):
        svc = _service(auth_svc=auth_svc)
        svc._generate_temp_password = lambda: 'generated'
        # Provisioning ENABLED by default here so these tests stay about applying
        # the role. The gate itself is exercised in ProvisioningGateTests below.
        svc._saml_config = {'user_provisioning':
                            {'enabled': True} if provisioning is None else provisioning}
        svc._entitled_roles = lambda _info: set(entitled)
        return svc

    def test_an_existing_red_account_selecting_blue_gets_blue(self):
        """The reported case. Provisioning is not involved at all here."""
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('red', 'app'))})
        svc = self._svc(auth)
        self.assertTrue(_run(svc._apply_selected_role({'email': 'a@x'}, 'blue')))
        self.assertIn('blue', auth.user_map['a@x'].permissions)
        self.assertNotIn('red', auth.user_map['a@x'].permissions)

    def test_the_stored_password_is_reused_not_churned(self):
        auth = _AuthSvc({'a@x': _User('a@x', 'original', ('red', 'app'))})
        _run(self._svc(auth)._apply_selected_role({'email': 'a@x'}, 'blue'))
        self.assertEqual('original', auth.user_map['a@x'].password)

    def test_an_already_correct_entry_is_left_alone(self):
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('blue', 'app'))})
        self.assertTrue(_run(self._svc(auth)._apply_selected_role({'email': 'a@x'}, 'blue')))
        self.assertEqual([], auth.created, 'no need to rewrite a correct entry')

    def test_a_failure_to_apply_reports_false(self):
        """The caller refuses the login on False, rather than signing the user in
        with whatever role the account already had."""
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('red', 'app'))}, fail=True)
        self.assertFalse(_run(self._svc(auth)._apply_selected_role({'email': 'a@x'}, 'blue')))

    def test_a_missing_auth_service_reports_false(self):
        self.assertFalse(_run(self._svc(None)._apply_selected_role({'email': 'a@x'}, 'blue')))

    def test_a_silent_write_failure_reports_false(self):
        """create_user returning without error is not proof the role landed.

        Without this the post-write check is never exercised: every fake here
        writes correctly, so replacing the verification with `applied = True`
        passed the whole suite. A Caldera whose create_user changed shape, or an
        entry overwritten by something else between write and read, would then
        sign the user in with the wrong role while reporting success.
        """
        class _Silent(_AuthSvc):
            async def create_user(self, username, password, group):
                # Writes, but not the requested group.
                self.user_map[username] = _User(username, password, ('red', 'app'))

        auth = _Silent({'a@x': _User('a@x', 'pw', ('red', 'app'))})
        self.assertFalse(_run(self._svc(auth)._apply_selected_role({'email': 'a@x'}, 'blue')))

    def test_a_missing_email_reports_false(self):
        auth = _AuthSvc()
        self.assertFalse(_run(self._svc(auth)._apply_selected_role({}, 'blue')))


class ProvisioningGateTests(unittest.TestCase):
    """The picker must not become its own account-creation path.

    _apply_selected_role wrote to user_map unconditionally -- the docstring said
    "whatever provisioning says" -- so every identity the IdP accepted could
    obtain a Caldera account even where the operator had switched automatic
    provisioning off. `enabled` defaults to FALSE, so that was the out-of-the-box
    behaviour, not a misconfiguration (Codex P1 + AWS HIGH on
    caldera-deployalt#379).

    Refusing the login is the resolution: the picker still never lies about the
    role a session carries, and it no longer writes accounts nobody permitted.
    """

    def _svc(self, auth_svc, provisioning, entitled=('blue', 'red')):
        svc = _service(auth_svc=auth_svc)
        svc._generate_temp_password = lambda: 'generated'
        svc._saml_config = {'user_provisioning': provisioning}
        svc._entitled_roles = lambda _info: set(entitled)
        return svc

    def test_provisioning_off_does_not_create_a_missing_account(self):
        """The finding, stated directly."""
        auth = _AuthSvc()
        svc = self._svc(auth, {})  # `enabled` absent -> False, the DEFAULT
        self.assertFalse(_run(svc._apply_selected_role({'email': 'new@x'}, 'blue')))
        self.assertNotIn('new@x', auth.user_map,
                         'a disabled provisioner must not gain an account via the picker')
        self.assertEqual([], auth.created)

    def test_provisioning_off_does_not_rewrite_an_existing_account(self):
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('red', 'app'))})
        svc = self._svc(auth, {'enabled': False})
        self.assertFalse(_run(svc._apply_selected_role({'email': 'a@x'}, 'blue')))
        self.assertIn('red', auth.user_map['a@x'].permissions, 'left untouched')

    def test_provisioning_off_still_admits_an_already_correct_account(self):
        """The refusal must not lock out users the operator provisioned by hand:
        this path needs no write, so nothing is being gated."""
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('blue', 'app'))})
        svc = self._svc(auth, {'enabled': False})
        self.assertTrue(_run(svc._apply_selected_role({'email': 'a@x'}, 'blue')))

    def test_create_missing_users_false_blocks_only_creation(self):
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('red', 'app'))})
        svc = self._svc(auth, {'enabled': True, 'create_missing_users': False})
        self.assertFalse(_run(svc._apply_selected_role({'email': 'new@x'}, 'blue')))
        self.assertNotIn('new@x', auth.user_map)
        # ...while an existing account may still be updated (update_on_login
        # defaults True), which is what makes these two settings distinct.
        self.assertTrue(_run(svc._apply_selected_role({'email': 'a@x'}, 'blue')))

    def test_update_on_login_false_blocks_only_updates(self):
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('red', 'app'))})
        svc = self._svc(auth, {'enabled': True, 'update_on_login': False})
        self.assertFalse(_run(svc._apply_selected_role({'email': 'a@x'}, 'blue')))
        self.assertIn('red', auth.user_map['a@x'].permissions)
        self.assertTrue(_run(svc._apply_selected_role({'email': 'new@x'}, 'blue')))

    def test_both_writers_read_the_same_rules(self):
        """_provision_user spelled these rules out inline and _apply_selected_role
        did not read them at all. One helper now answers the question for both, so
        the two cannot drift back apart."""
        source = (pathlib.Path(__file__).resolve().parents[1] / 'app' / 'saml_svc.py').read_text()
        body = source[source.index('async def _provision_user'):]
        body = body[:body.index('\n    def ', 1)]
        self.assertNotIn("get('create_missing_users'", body,
                         '_provision_user must ask _may_write_user, not re-read the config')
        self.assertIn('_may_write_user', body)

    def test_the_role_is_rechecked_against_entitlement_before_writing(self):
        """Defence in depth: the handler checks entitlement, but a writer that
        trusts its caller is one refactor away from being reachable without it."""
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('blue', 'app'))})
        svc = self._svc(auth, {'enabled': True}, entitled=('blue',))
        self.assertFalse(_run(svc._apply_selected_role({'email': 'a@x'}, 'red')))
        self.assertNotIn('red', auth.user_map['a@x'].permissions)

    def test_a_failing_entitlement_check_fails_closed(self):
        auth = _AuthSvc({'a@x': _User('a@x', 'pw', ('blue', 'app'))})
        svc = self._svc(auth, {'enabled': True})
        def _boom(_info):
            raise RuntimeError('attribute source unavailable')
        svc._entitled_roles = _boom
        self.assertFalse(_run(svc._apply_selected_role({'email': 'a@x'}, 'red')))


class PickerRefusalTests(unittest.TestCase):
    """A picker that cannot apply the choice must not sign the user in."""

    SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'app' / 'saml_svc.py').read_text()

    def test_the_handler_refuses_when_the_role_cannot_be_applied(self):
        branch = self.SOURCE[self.SOURCE.index('via SAML role picker'):]
        branch = branch[:branch.index('raise web.HTTPMethodNotAllowed')]
        self.assertIn('if not await self._apply_selected_role(user_info, role):', branch)
        refuse = branch.index('_apply_selected_role')
        authenticate = branch.index('_authenticate_user')
        self.assertLess(refuse, authenticate,
                        'apply the role BEFORE authenticating, and refuse on failure')
        self.assertIn('status=403', branch)


if __name__ == '__main__':
    unittest.main()
