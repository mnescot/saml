"""Selected-role sessions end after inactivity, not an hour after sign-in.

Operators were signed out mid-task: the grant lived min(1 h, the assertion's
Conditions/NotOnOrAfter), and Entra issues assertions valid for about an hour,
so an active operator lost the session at the hour regardless. The session now
slides on activity (60 minutes by default) under a hard ceiling (12 hours, or
the IdP's SessionNotOnOrAfter) that still forces a fresh assertion, and with it
fresh group membership, at least that often.

"Activity" is user input, not traffic: the console reports how long its tab has
been idle on every request, so a background poll from an unattended tab does
not keep the session alive.
"""
import asyncio
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import web

from test_four_group_roles import owned_account

HEADER = 'X-Caldera-Input-Idle-Seconds'


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def signed_in(clock):
    """A completed SSO: account, grant and the browser cookie's marker."""
    with patch('time.time', clock):
        svc, _, info = owned_account()
        canonical = svc._group_role_identities[info['email']]
        cookie = {}
        sessions = types.ModuleType('aiohttp_session')
        sessions.get_session = AsyncMock(return_value=cookie)
        with patch.dict(sys.modules, {'aiohttp_session': sessions}):
            asyncio.run(svc._bind_group_session(SimpleNamespace(), info, canonical))
    return svc, info, cookie


def request(svc, info, cookie, clock, *, headers=None, path='/plugins/infosec_agent/api/status'):
    """One request through the real guard; returns the response status."""
    security = types.ModuleType('aiohttp_security')
    security.authorized_userid = AsyncMock(return_value=info['email'])
    sessions = types.ModuleType('aiohttp_session')
    sessions.get_session = AsyncMock(return_value=_Cookie(cookie))
    handler = AsyncMock(return_value=web.Response(text='ok'))
    req = SimpleNamespace(path=path, method='GET', headers=headers or {'Accept': 'application/json'})
    with patch('time.time', clock), \
            patch.dict(sys.modules, {'aiohttp_security': security, 'aiohttp_session': sessions}):
        response = asyncio.run(svc.guard_group_session(req, handler))
    return response.status


class _Cookie(dict):
    def __init__(self, backing):
        super().__init__(backing)
        self._backing = backing

    def invalidate(self):
        self._backing.clear()
        self.clear()


def test_activity_keeps_a_session_alive_well_past_an_hour():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    for _ in range(8):  # 8 x 50 minutes = 6 h 40 min of steady work
        clock.now += 50 * 60
        assert request(svc, info, cookie, clock) == 200


def test_sixty_minutes_without_activity_ends_the_session():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    clock.now += 59 * 60
    assert request(svc, info, cookie, clock) == 200
    clock.now += 60 * 60 + 1
    assert request(svc, info, cookie, clock) == 401
    # Ended for good: a later request does not revive it.
    clock.now += 1
    assert request(svc, info, cookie, clock) == 401


def test_background_polls_from_an_unattended_tab_do_not_extend_it():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    for minute in range(1, 61):  # a poll every minute, user away the whole time
        clock.now += 60
        assert request(svc, info, cookie, clock, headers={HEADER: str(minute * 60)}) == 200
    clock.now += 2
    assert request(svc, info, cookie, clock, headers={HEADER: str(3602)}) == 401


def test_a_poll_carrying_recent_input_extends_it():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    clock.now += 50 * 60
    assert request(svc, info, cookie, clock, headers={HEADER: '5'}) == 200
    clock.now += 50 * 60  # 100 minutes after sign-in, 50 after the input
    assert request(svc, info, cookie, clock, headers={HEADER: str(50 * 60)}) == 200


@pytest.mark.parametrize('value', ['-30', 'soon', '', '1e9'])
def test_a_malformed_idle_report_counts_as_activity_now_and_never_later(value):
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    clock.now += 30 * 60
    assert request(svc, info, cookie, clock, headers={HEADER: value}) == 200
    last = svc._session_activity(info['email'])[cookie['saml_assertion_marker']]
    assert last <= clock.now


def test_the_hard_ceiling_still_forces_a_fresh_sign_in():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    for _ in range(16):  # 16 x 50 minutes passes the 12-hour ceiling
        clock.now += 50 * 60
        status = request(svc, info, cookie, clock)
        if clock.now - 1_800_000_000.0 >= svc._GROUP_SESSION_MAX_LIFETIME:
            assert status == 401
            break
        assert status == 200
    else:
        pytest.fail('the session outlived its maximum lifetime')


def test_policy_can_tune_both_limits_within_bounds():
    svc, _, _ = owned_account()
    policy = dict(svc._saml_config['group_role_policy'])
    svc._saml_config['group_role_policy'] = {**policy, 'session_idle_timeout_seconds': 1800,
                                             'session_max_lifetime_seconds': 28800}
    assert svc._session_limits() == (1800, 28800)
    svc._saml_config['group_role_policy'] = {**policy, 'session_idle_timeout_seconds': 5,
                                             'session_max_lifetime_seconds': 10 ** 9}
    assert svc._session_limits() == (300, 86400)
    svc._saml_config['group_role_policy'] = {**policy, 'session_idle_timeout_seconds': True,
                                             'session_max_lifetime_seconds': '99'}
    assert svc._session_limits() == (svc._GROUP_SESSION_IDLE_TIMEOUT, svc._GROUP_SESSION_MAX_LIFETIME)


def test_a_grant_without_recorded_activity_fails_closed():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    svc._session_activity(info['email']).clear()
    assert request(svc, info, cookie, clock) == 401


def test_new_claims_reset_activity_with_the_markers():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    with patch('time.time', clock):
        assert asyncio.run(svc._apply_group_role({**info, 'groups': ['A', 'P']}, 'report'))
    assert svc._session_activity(info['email']) == {}


def status(svc, info, cookie, clock):
    security = types.ModuleType('aiohttp_security')
    security.authorized_userid = AsyncMock(return_value=info['email'])
    sessions = types.ModuleType('aiohttp_session')
    sessions.get_session = AsyncMock(return_value=cookie)
    with patch('time.time', clock), \
            patch.dict(sys.modules, {'aiohttp_security': security, 'aiohttp_session': sessions}):
        response = asyncio.run(svc.saml_session_status_handler(SimpleNamespace(headers={})))
    import json
    assert response.headers['Cache-Control'] == 'no-store'
    return json.loads(response.text)


def test_status_reports_the_deadlines_and_reading_it_never_extends_them():
    clock = Clock()
    svc, info, cookie = signed_in(clock)
    started = clock.now
    clock.now += 10 * 60
    body = status(svc, info, cookie, clock)
    assert body['authenticated'] is True and body['idle_timeout_seconds'] == 3600
    assert body['idle_expires_at'] == int(started + 3600)
    assert body['expires_at'] == int(started + svc._GROUP_SESSION_MAX_LIFETIME)
    clock.now += 50 * 60 + 1  # polled only the status endpoint meanwhile
    assert status(svc, info, cookie, clock) == {'managed': True, 'authenticated': False}


def test_status_without_a_group_policy_reports_unmanaged():
    svc, _, _ = owned_account()
    svc._saml_config['group_role_policy'] = None
    with patch.dict('os.environ', {}, clear=False):
        import os
        os.environ.pop('CALDERA_SAML_RBAC_POLICY', None)
        response = asyncio.run(svc.saml_session_status_handler(SimpleNamespace(headers={})))
    assert response.text == '{"managed": false}'


def test_hook_registers_the_status_route():
    from pathlib import Path
    hook = (Path(__file__).resolve().parents[1] / 'hook.py').read_text()
    assert "add_route('GET', '/saml/session', saml_svc.saml_session_status_handler)" in hook
