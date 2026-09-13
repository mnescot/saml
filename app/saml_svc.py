import calendar
import hashlib
import json
import os
import logging
import base64
import secrets
import time
import urllib.parse
from typing import Dict, Any, Optional

from aiohttp import web
from pathlib import Path
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.metadata import create_metadata_string
from saml2.response import AuthnResponse
from app.utility.base_service import BaseService


# HTML template for the role selection page (served inline — no template engine needed)
_ROLE_SELECT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CALDERA — Select Role</title>
<style>
  :root {{
    --bg: #0f1117;
    --surface: #1a1d27;
    --card: #20243a;
    --border: #2d3348;
    --accent: #3b82f6;
    --accent-dark: #2563eb;
    --danger: #ef4444;
    --success: #22c55e;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --sans: 'Inter', 'Segoe UI', system-ui, sans-serif;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{
    height: 100%; background: var(--bg); color: var(--text);
    font-family: var(--sans); font-size: 14px; line-height: 1.5;
    display: flex; align-items: center; justify-content: center;
  }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 36px 40px; width: 380px; max-width: 95vw;
    box-shadow: 0 8px 32px rgba(0,0,0,.5);
  }}
  .logo {{
    display: flex; align-items: center; gap: 10px; margin-bottom: 28px;
  }}
  .logo-icon {{
    width: 36px; height: 36px; background: var(--accent);
    border-radius: 8px; display: flex; align-items: center; justify-content: center;
    font-weight: 900; font-size: 18px; color: #fff; letter-spacing: -.02em;
  }}
  .logo-name {{
    font-size: 18px; font-weight: 800; letter-spacing: .06em;
    text-transform: uppercase; color: var(--text);
  }}
  h2 {{
    font-size: 16px; font-weight: 700; margin-bottom: 6px;
  }}
  .subtitle {{
    font-size: 13px; color: var(--text-dim); margin-bottom: 28px;
  }}
  .name-pill {{
    display: inline-block; background: rgba(59,130,246,.12);
    color: var(--accent); border: 1px solid rgba(59,130,246,.25);
    border-radius: 20px; padding: 2px 12px; font-size: 13px;
    font-weight: 600; margin-bottom: 28px;
  }}
  .role-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px;
  }}
  .role-btn {{
    display: flex; flex-direction: column; align-items: center; gap: 8px;
    padding: 20px 14px; border-radius: 8px; border: 2px solid transparent;
    cursor: pointer; font-family: inherit; font-size: 14px; font-weight: 700;
    transition: all .15s; background: var(--surface); color: var(--text);
    text-transform: uppercase; letter-spacing: .04em;
  }}
  .role-btn:hover {{ border-color: currentColor; }}
  .role-btn .icon {{ font-size: 28px; }}
  .role-btn.red {{ color: #f87171; }}
  .role-btn.red:hover {{ background: rgba(239,68,68,.1); }}
  .role-btn.blue {{ color: #60a5fa; }}
  .role-btn.blue:hover {{ background: rgba(59,130,246,.1); }}
  .role-desc {{ font-size: 11px; font-weight: 400; color: var(--text-dim);
    text-transform: none; letter-spacing: 0; }}
  .footer {{
    font-size: 11px; color: var(--text-dim); text-align: center; margin-top: 8px;
  }}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">C</div>
    <div class="logo-name">Caldera</div>
  </div>
  <h2>Choose Your Role</h2>
  <p class="subtitle">Select the perspective you want for this session.</p>
  {name_pill}
  <form method="POST" action="/saml/role-select">
    <input type="hidden" name="token" value="{token}">
    <div class="role-grid">
      {red_button}
      <button type="submit" name="role" value="blue" class="role-btn blue">
        <span class="icon">&#128737;</span>
        Blue Team
        <span class="role-desc">Defense, detection &amp; incident response</span>
      </button>
    </div>
  </form>
  <p class="footer">You can switch roles by logging out and back in.</p>
</div>
</body>
</html>"""

# The Red Team option is rendered ONLY for users the IdP entitles to it (see
# SamlService._entitled_roles). It is a separate constant so a user with no red
# entitlement never even sees the button; the POST handler enforces the same
# entitlement server-side regardless.
_RED_BUTTON_HTML = """<button type="submit" name="role" value="red" class="role-btn red">
        <span class="icon">&#9888;</span>
        Red Team
        <span class="role-desc">Offensive operations &amp; adversary simulation</span>
      </button>"""


class SamlService(BaseService):
    # TTL (seconds) for a pending role-selection auth token
    _PENDING_AUTH_TTL = 300  # 5 minutes

    # How long a consumed assertion is remembered when its own NotOnOrAfter
    # cannot be read. It must exceed any plausible assertion lifetime, because
    # forgetting early is what makes a replay possible; 24h is far beyond the
    # 5-60 minutes IdPs issue and costs a few hundred bytes per login.
    _ASSERTION_REPLAY_RETENTION = 86400  # 24 hours

    # Longest assertion validity window accepted. Bounds how long a record must
    # be kept, so retention can follow the assertion's own NotOnOrAfter instead
    # of being clamped to something shorter than it.
    _ASSERTION_MAX_LIFETIME = 86400  # 24 hours

    def __init__(self):
        self.config_dir_path = os.path.join(Path(__file__).parents[1], 'conf')
        self.settings_path = os.path.join(self.config_dir_path, 'settings.json')
        self.user_mapping_path = os.path.join(self.config_dir_path, 'user_mapping.json')

        # Initialize logger FIRST before any error handling that uses it
        self.log = self.add_service('saml_svc', self)

        # In-memory store for pending (post-SAML, pre-role-select) auth state.
        # Keys are random tokens; values are dicts with user_info + expiry.
        self._pending_auth: Dict[str, Dict[str, Any]] = {}

        # One-time-use record for consumed assertions, keyed by assertion ID and
        # held until that assertion's own NotOnOrAfter. See _claim_assertion.
        self._seen_assertions: Dict[str, float] = {}

        # Load SAML configuration with better error handling
        try:
            with open(self.settings_path, 'rb') as settings_file:
                self._saml_config = json.load(settings_file)
        except FileNotFoundError:
            self.log.error(f'SAML configuration file not found: {self.settings_path}')
            self._saml_config = {}
        except json.JSONDecodeError as e:
            self.log.error(f'Invalid JSON in SAML configuration: {e}')
            self._saml_config = {}

        # Load user mapping configuration
        try:
            with open(self.user_mapping_path, 'r') as mapping_file:
                self._user_mapping_config = json.load(mapping_file)
        except FileNotFoundError:
            # Fail CLOSED: the mapping is an authorization policy (it decides red
            # entitlement via _matched_caldera_role). A missing file must not fall
            # back to broader built-ins — use an empty (deny-all-red) mapping so
            # only explicit admin_roles/admin_groups from settings.json can grant red.
            self.log.error(f'User mapping file not found: {self.user_mapping_path}; '
                           'failing closed to an empty mapping (no mapping-derived red)')
            self._user_mapping_config = self._deny_user_mapping()
        except json.JSONDecodeError as e:
            self.log.error(f'Invalid JSON in user mapping configuration: {e}; '
                           'failing closed to an empty mapping (no mapping-derived red)')
            self._user_mapping_config = self._deny_user_mapping()

    def _convert_onelogin_config_to_pysaml2(self, onelogin_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert OneLogin python3-saml config format to pysaml2 config format.
        This maintains backward compatibility with existing settings.json files.
        """
        sp = onelogin_config.get('sp', {})
        idp = onelogin_config.get('idp', {})
        security = onelogin_config.get('security', {})

        # Extract SP entity ID and ACS URL
        sp_entity_id = sp.get('entityId', 'http://localhost:8888')
        acs_info = sp.get('assertionConsumerService', {})
        acs_url = acs_info.get('url', f'{sp_entity_id}/saml/acs')
        acs_binding = acs_info.get('binding', BINDING_HTTP_POST)

        # Extract IdP information
        idp_entity_id = idp.get('entityId', '')
        sso_info = idp.get('singleSignOnService', {})
        sso_url = sso_info.get('url', '')
        sso_binding = sso_info.get('binding', BINDING_HTTP_REDIRECT)

        # Extract certificate (remove whitespace and newlines)
        idp_cert = idp.get('x509cert', '').replace('\n', '').replace('\r', '').replace(' ', '')

        # Build pysaml2 config
        pysaml2_config = {
            'entityid': sp_entity_id,
            'service': {
                'sp': {
                    'name': 'Caldera SAML SP',
                    'endpoints': {
                        'assertion_consumer_service': [
                            (acs_url, acs_binding),
                        ],
                    },
                    'allow_unsolicited': True,
                    'authn_requests_signed': security.get('authnRequestsSigned', False),
                    'want_assertions_signed': security.get('wantAssertionsSigned', True),
                    'want_response_signed': security.get('wantMessagesSigned', True),
                },
            },
            'metadata': {
                'inline': [self._build_idp_metadata(idp_entity_id, sso_url, sso_binding, idp_cert)],
            },
            'debug': onelogin_config.get('debug', False),
            # WITHOUT THIS, ENTRA'S GROUP CLAIM IS SILENTLY DISCARDED.
            #
            # pysaml2 converts assertion attributes through its attribute maps.
            # An attribute whose Name it has no mapping for is DROPPED, and the
            # only trace is an INFO line from attribute_converter.py:
            #     Unknown attribute name: <ns0:Attribute ...
            #       Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups" ...
            # Captured from a real login on the running instance: the claim IS
            # present in the assertion, carrying the expected group GUID, and
            # pysaml2 discarded it before _extract_user_info ever looked. Every
            # Microsoft claim URI in the assertion was reported unknown --
            # groups, objectidentifier, displayname, tenantid, identityprovider,
            # authnmethodsreferences.
            #
            # That is why the symptom was so misleading: Entra was configured
            # correctly, settings.json held the right attribute URI and the right
            # group GUID, the user was a direct member, the group was assigned to
            # the enterprise application, and the assertion did contain the
            # claim. The loss happened inside the SAML library, between the
            # assertion and our code, and nothing above INFO reported it.
            #
            # With this enabled pysaml2 keeps unmapped attributes keyed by their
            # Name URI, which is exactly what _extract_user_info looks up via
            # user_provisioning.group_attribute. It widens nothing on the trust
            # boundary: the assertion is still signature-verified, issuer- and
            # audience-checked first, and an attacker who could add attributes to
            # a signed assertion could already assert anything.
            'allow_unknown_attributes': True,
        }

        return pysaml2_config

    def _build_idp_metadata(self, entity_id: str, sso_url: str, sso_binding: str, cert: str) -> str:
        """Build IdP metadata XML from OneLogin config parameters"""
        binding_map = {
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': BINDING_HTTP_REDIRECT,
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST': BINDING_HTTP_POST,
        }
        binding = binding_map.get(sso_binding, BINDING_HTTP_REDIRECT)

        # Format certificate with proper PEM structure if not already formatted
        if cert and not cert.startswith('-----BEGIN CERTIFICATE-----'):
            cert_formatted = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"
        else:
            cert_formatted = cert

        metadata = f'''<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{cert}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="{binding}" Location="{sso_url}"/>
  </IDPSSODescriptor>
</EntityDescriptor>'''

        return metadata

    def _get_saml2_client(self) -> Saml2Client:
        """Create and return a pysaml2 client instance"""
        pysaml2_config = self._convert_onelogin_config_to_pysaml2(self._saml_config)
        config = Saml2Config()
        config.load(pysaml2_config)
        client = Saml2Client(config=config)
        return client

    def _deny_user_mapping(self) -> Dict[str, Any]:
        """Fail-closed mapping used when the policy file is missing/invalid: no
        role/group/domain rules, so nothing here can confer red — only explicit
        admin_roles/admin_groups from settings.json remain in effect."""
        return {"role_mappings": {}, "group_mappings": {}, "email_domain_mappings": {}}

    def _get_default_user_mapping(self) -> Dict[str, Any]:
        """Default user mapping configuration. Deliberately conservative for the
        offensive tier: `red`/`admin` map only to explicit, unambiguous claim
        values — no `sysadmin`/`attacker`/`pentester` aliases that could grant red
        on a loosely-configured IdP."""
        return {
            "role_mappings": {
                "admin": ["admin", "administrator"],
                "blue": ["blue_team", "defender", "analyst"],
                "red": ["red_team"],
                "user": ["user", "viewer", "readonly"]
            },
            "group_mappings": {},
            "email_domain_mappings": {}
        }

    def _claim_assertion(self, authn_response) -> bool:
        """Consume a SAML assertion exactly once. False means reject the login.

        Signature and issuer validation prove an assertion was ISSUED by the
        IdP; they say nothing about whether it has already been used. This
        deployment needs IdP-initiated SSO (users arrive from MyApps), which
        means `allow_unsolicited` must stay True and pysaml2 performs no
        InResponseTo correlation -- so without a one-time-use record a captured
        SAMLResponse can be replayed to /saml/acs until its NotOnOrAfter and
        mint a fresh session each time.

        That matters more now than it used to: allow_unknown_attributes means a
        replayed assertion carries the Entra group claims that drive `red`
        entitlement, which the library previously discarded. The freshness gap
        is pre-existing, but this is what closes it.

        Fails CLOSED. An assertion whose ID cannot be read is refused rather
        than admitted un-tracked.
        """
        now = time.time()
        for seen_id, expires in list(self._seen_assertions.items()):
            if expires <= now:
                self._seen_assertions.pop(seen_id, None)

        assertion_id = ''
        # Default to the conservative retention, NOT a short TTL: every path
        # that fails to establish a real expiry must remember for longer, not
        # shorter. Forgetting early is precisely what re-enables a replay.
        expires_at = now + self._ASSERTION_REPLAY_RETENTION
        try:
            assertion = authn_response.assertion
            assertion_id = str(getattr(assertion, 'id', '') or '').strip()
            conditions = getattr(assertion, 'conditions', None)
            not_after = str(getattr(conditions, 'not_on_or_after', '') or '')
            if not_after:
                from saml2.time_util import str_to_time
                # calendar.timegm, NOT time.mktime. str_to_time returns a UTC
                # struct_time and mktime interprets its argument as LOCAL time,
                # so on any host east of UTC the epoch lands in the past, the
                # record is pruned on the next call, and the replay window
                # silently reopens. That made a security control depend on the
                # host's timezone -- invisible on a UTC box, broken elsewhere.
                parsed = calendar.timegm(str_to_time(not_after))
                # Only trust a parsed value that is actually in the future.
                if parsed > now:
                    # An assertion cannot outlive the record that makes it
                    # single-use. Rather than remember forever, refuse a window
                    # no legitimate IdP issues -- Entra's default is about an
                    # hour, so a day is already generous -- which keeps
                    # retention bounded without ever making it too short.
                    if parsed - now > self._ASSERTION_MAX_LIFETIME:
                        self.log.warning(
                            'SAML replay check: assertion %r claims a validity '
                            'window of %ds, beyond the %ds maximum; refusing',
                            assertion_id, int(parsed - now),
                            self._ASSERTION_MAX_LIFETIME)
                        return False
                    expires_at = parsed
                else:
                    self.log.warning(
                        'SAML replay check: NotOnOrAfter %r did not parse to a '
                        'future time; retaining conservatively', not_after)
        except Exception as exc:  # noqa: BLE001 - unreadable assertion is a reject
            self.log.warning('SAML replay check: could not read assertion id: %s', exc)
            return False

        if not assertion_id:
            self.log.warning('SAML replay check: assertion carries no ID; refusing')
            return False
        if assertion_id in self._seen_assertions:
            self.log.warning(
                'SAML replay REJECTED: assertion %r has already been consumed',
                assertion_id)
            return False

        # DURABLE record. The in-memory dict above is process-local and empty
        # after any restart, so on its own it leaves a replay window across
        # every redeploy -- and would not be shared if the fleet ever ran more
        # than one instance. The SAML conf directory is a symlink onto the EFS
        # data volume, so a marker written beside settings.json survives
        # restarts AND is visible to every instance.
        #
        # O_CREAT|O_EXCL makes "claim" a single atomic operation, so two
        # concurrent POSTs of the same assertion cannot both win; NFSv4 (which
        # EFS speaks) implements exclusive create correctly. The filename is a
        # hash, never the raw ID, so an attacker-chosen assertion ID cannot
        # traverse or collide with anything.
        if not self._claim_assertion_durably(assertion_id, expires_at, now):
            return False

        # Track the assertion's OWN expiry, never a shorter clamp. The record
        # has to outlive the thing it protects against; clamping it to a fixed
        # retention meant an assertion valid for longer than that became
        # replayable while still cryptographically valid.
        self._seen_assertions[assertion_id] = max(expires_at, now + 60)
        return True

    def _claim_assertion_durably(self, assertion_id: str, expires_at: float,
                                 now: float) -> bool:
        """Record the assertion on shared storage. False means DO NOT proceed.

        FAILS CLOSED on any storage error. An earlier version returned True when
        the store was unusable, reasoning that refusing logins on a filesystem
        fault was worse than the replay risk. That reasoning was wrong on its
        own terms: the fallback it left -- the in-process dict -- is empty after
        every restart and unshared between instances, i.e. precisely the gap
        this control exists to close, so the degraded mode was indistinguishable
        from having no durable layer at all. Exactly when the store breaks is
        when an attacker holding a captured assertion wins.

        It was also wrong about the cost. SAML is not the only way in: the
        installer provisions local red/blue accounts whose passwords live in SSM
        (/caldera/red_user_password, /caldera/blue_user_password) and SSO already
        falls through to the local login form when its config cannot load. A
        storage fault therefore degrades SSO to break-glass, it does not lock
        anyone out -- so refusing is affordable and is the correct choice.

        The marker's MTIME is the assertion's own expiry, so pruning cannot
        forget a record while the assertion it covers is still valid.
        """
        store = os.path.join(os.path.dirname(self.settings_path), 'consumed_assertions')
        marker = os.path.join(
            store, hashlib.sha256(assertion_id.encode('utf-8')).hexdigest())

        try:
            os.makedirs(store, mode=0o700, exist_ok=True)
        except OSError as exc:
            self.log.error(
                'SAML replay check: durable store unavailable (%s). REFUSING the '
                'login: the in-process record does not survive a restart and is '
                'not shared, so proceeding would silently drop replay protection. '
                'Local red/blue accounts remain available as break-glass.', exc)
            return False

        # Housekeeping only -- a prune failure must not decide an auth outcome.
        #
        # Expiry is read from the file BODY, never from mtime. Using mtime made
        # the prune racy and the upgrade unsafe:
        #
        #   * this pass runs BEFORE the marker is created, and a just-created
        #     marker's mtime is its creation time, so a concurrent replay could
        #     prune the first request's record and then win its own O_EXCL --
        #     admitting BOTH logins;
        #   * markers written by the previous version were never stamped, so
        #     every one of them would be deleted on the first prune after the
        #     upgrade, re-opening replay for anything consumed just before it.
        #
        # Reading the body removes both: a record with no readable expiry is
        # KEPT for mtime + retention rather than dropped, so an empty file mid
        # write, a legacy marker, and a corrupt one all fail safe.
        try:
            for name in os.listdir(store):
                path = os.path.join(store, name)
                try:
                    if name.startswith('.tmp-'):
                        # A staging file from a claim in flight. Only reap ones
                        # old enough that no request could still be using them.
                        if os.path.getmtime(path) + 300 <= now:
                            os.unlink(path)
                        continue
                    with open(path, 'rb') as handle:
                        raw = handle.read(32).strip()
                    # A body is trusted only when it is a COMPLETE, plausible
                    # epoch. A truncated read of "1718..." as "17" is still
                    # all-digits and parses to 1970, which would look expired
                    # and unlink a live record -- so length and range are
                    # checked, not just isdigit().
                    expiry = None
                    if raw.isdigit() and len(raw) >= 10:
                        value = float(raw)
                        if (now - self._ASSERTION_REPLAY_RETENTION <= value
                                <= now + self._ASSERTION_MAX_LIFETIME + 300):
                            expiry = value
                    if expiry is None:
                        expiry = (os.path.getmtime(path)
                                  + self._ASSERTION_REPLAY_RETENTION)
                    if expiry <= now:
                        os.unlink(path)
                except (OSError, ValueError):
                    # Undeterminable expiry: keep the record. Forgetting is what
                    # re-enables a replay; retaining one stale file costs bytes.
                    continue
        except OSError as exc:
            self.log.warning('SAML replay check: could not prune %s (%s)', store, exc)

        # Build the record COMPLETE, then publish it in one atomic step.
        #
        # Creating the marker and writing its body separately left a window in
        # which the file existed with a partial body. The prune reads that body
        # as the expiry, and a truncated read parses to 1970 -- so a concurrent
        # request could unlink a live record and then claim the assertion
        # itself. os.link is atomic and fails with EEXIST if the marker already
        # exists, so it serves as BOTH the claim and the publish: the file is
        # never observable in a half-written state.
        staging = os.path.join(
            store, '.tmp-%d-%s' % (os.getpid(), secrets.token_hex(8)))
        body = str(int(max(expires_at, now + 60))).encode('ascii')
        try:
            fd = os.open(staging, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, body)
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            self.log.error(
                'SAML replay check: could not stage the durable record (%s). '
                'REFUSING the login rather than proceeding without it.', exc)
            return False

        try:
            os.link(staging, marker)
        except FileExistsError:
            self.log.warning(
                'SAML replay REJECTED: assertion %r was already consumed '
                '(durable record)', assertion_id)
            return False
        except OSError as exc:
            self.log.error(
                'SAML replay check: could not publish the durable record (%s). '
                'REFUSING the login rather than proceeding without it.', exc)
            return False
        finally:
            try:
                os.unlink(staging)
            except OSError:
                pass
        return True

    # ── Pending auth (role-selection) helpers ─────────────────────────────────

    def _store_pending_auth(self, user_info: Dict[str, Any]) -> str:
        """
        Store user_info under a one-time token and return that token.
        The token is valid for _PENDING_AUTH_TTL seconds.
        """
        self._purge_expired_pending_auth()
        token = secrets.token_urlsafe(32)
        self._pending_auth[token] = {
            'user_info': user_info,
            'expires_at': time.monotonic() + self._PENDING_AUTH_TTL,
        }
        return token

    def _pop_pending_auth(self, token: str) -> Optional[Dict[str, Any]]:
        """Consume and return the user_info for a token, or None if invalid/expired."""
        entry = self._pending_auth.pop(token, None)
        if entry is None:
            return None
        if time.monotonic() > entry['expires_at']:
            return None
        return entry['user_info']

    def _peek_pending_auth(self, token: str) -> Optional[Dict[str, Any]]:
        """Return the user_info for a token WITHOUT consuming it (GET render),
        enforcing the same TTL as _pop_pending_auth. An expired entry is deleted
        and treated as invalid, so a stale token cannot remain a readable oracle
        past its TTL on an idle deployment."""
        if not token:
            return None
        entry = self._pending_auth.get(token)
        if entry is None:
            return None
        if time.monotonic() > entry['expires_at']:
            self._pending_auth.pop(token, None)
            return None
        return entry.get('user_info', {})

    def _purge_expired_pending_auth(self):
        """Remove expired entries to prevent unbounded memory growth."""
        now = time.monotonic()
        expired = [t for t, e in self._pending_auth.items() if now > e['expires_at']]
        for t in expired:
            del self._pending_auth[t]

    # ── Route handlers ────────────────────────────────────────────────────────

    async def saml(self, request):
        """Legacy handler - routes to appropriate specific handler based on path and method"""
        path = request.path
        method = request.method

        self.log.debug(f'SAML legacy handler called: {method} {path}')

        try:
            # Route to specific handlers based on path
            if path.endswith('/metadata'):
                return await self.saml_metadata_handler(request)
            elif path.endswith('/acs'):
                return await self.saml_acs_handler(request)
            elif path.endswith('/sls'):
                return await self.saml_sls_handler(request)
            elif path.endswith('/login') or path in ['/saml', '/auth/saml']:
                return await self.saml_login_handler(request)
            else:
                # Default behavior - check if it's a SAML response or login initiation
                if method == 'POST' and 'SAMLResponse' in (await request.post()):
                    return await self.saml_acs_handler(request)
                else:
                    return await self.saml_login_handler(request)

        except web.HTTPRedirection as http_redirect:
            raise http_redirect
        except Exception as e:
            self.log.exception('Exception when handling SAML request: %s', e)
            self.log.debug('Redirecting to main login page')
            raise web.HTTPFound('/login')

    async def _saml_login(self, request):
        """Core SAML login logic using pysaml2"""
        self.log.debug(f'Handling SAML login: {request.method} {request.path}')

        try:
            client = self._get_saml2_client()

            # Check if this is a SAML response (POST from IdP) or login initiation (GET)
            if request.method == 'POST':
                post_data = await request.post()
                if 'SAMLResponse' in post_data:
                    # Process SAML response from IdP
                    self.log.debug('Processing SAML response from IdP')

                    saml_response = post_data['SAMLResponse']

                    # Parse the SAML response
                    authn_response = client.parse_authn_request_response(
                        saml_response,
                        BINDING_HTTP_POST
                    )

                    # One-time use, before any identity is derived from it.
                    if not self._claim_assertion(authn_response):
                        raise web.HTTPFound('/login')

                    # Get user identity from response
                    identity = authn_response.get_identity()
                    subject = authn_response.get_subject()

                    if not identity or not subject:
                        self.log.error('SAML authentication failed: no identity or subject')
                        raise web.HTTPFound('/login')

                    # %r, not an f-string: subject.text is IdP-controlled and a
                    # CR/LF in it forges whole log lines. Every SAML-path log
                    # that carries an IdP value uses %r for that reason.
                    self.log.debug('SAML authentication successful for subject: %r',
                                   str(subject.text))

                    # Extract user info from SAML attributes
                    user_info = self._extract_user_info_from_identity(identity, subject)

                    # Store pending auth and redirect to role selection page
                    token = self._store_pending_auth(user_info)
                    self.log.info(
                        'SAML auth succeeded for %r - redirecting to role selection',
                        str(user_info.get('email') or subject.text or ''))
                    raise web.HTTPFound(f'/saml/role-select?token={token}')

            # GET request or no SAML response - initiate login
            self.log.debug('Initiating SAML login redirect to IdP')

            # Get IdP SSO URL from client
            session_id, info = client.prepare_for_authenticate()

            # Extract redirect URL (first tuple element is the redirect URL)
            redirect_url = None
            for key, value in info['headers']:
                if key == 'Location':
                    redirect_url = value
                    break

            if not redirect_url:
                self.log.error('Failed to get redirect URL from SAML client')
                raise web.HTTPFound('/login')

            self.log.debug(f'Redirecting to IdP: {redirect_url}')
            raise web.HTTPFound(redirect_url)

        except web.HTTPRedirection:
            raise
        except Exception as e:
            self.log.exception(f'SAML login error: {e}')
            raise web.HTTPFound('/login')

    async def saml_role_select_handler(self, request):
        """
        GET  /saml/role-select?token=<token>
          — Show role selection page

        POST /saml/role-select
          — Process role selection (form fields: token, role)
        """
        if request.method == 'GET':
            token = request.rel_url.query.get('token', '')
            user_info = self._peek_pending_auth(token)
            if user_info is None:
                self.log.warning('Role select GET: invalid or expired token')
                raise web.HTTPFound('/login')
            display_name = user_info.get('display_name') or user_info.get('email', 'User')

            name_pill = (
                f'<div class="name-pill">{self._html_escape(display_name)}</div>'
                if display_name else ''
            )
            entitled = self._entitled_roles(user_info)
            html = _ROLE_SELECT_HTML.format(
                token=self._html_escape(token),
                name_pill=name_pill,
                red_button=(_RED_BUTTON_HTML if 'red' in entitled else ''),
            )
            return web.Response(text=html, content_type='text/html')

        elif request.method == 'POST':
            post_data = await request.post()
            token = post_data.get('token', '')
            role = post_data.get('role', '').lower()

            if role not in ('red', 'blue'):
                self.log.warning(f'Role select POST: invalid role "{role}"')
                raise web.HTTPFound('/login')

            user_info = self._pop_pending_auth(token)
            if user_info is None:
                self.log.warning('Role select POST: invalid or expired token')
                raise web.HTTPFound('/login')

            # SECURITY: the selected role must be one the IdP actually entitles this
            # user to. Without this the picker accepts any POSTed role, so any SSO
            # user could self-assign 'red'. Entitlement is derived from IdP-asserted
            # attributes only (never from the POST body).
            entitled = self._entitled_roles(user_info)
            if role not in entitled:
                self.log.warning(
                    'Role select POST: user %r selected %r but is only entitled '
                    'to %s; refusing',
                    str(user_info.get('email') or ''), str(role), sorted(entitled))
                raise web.HTTPFound('/login')

            self.log.info(
                'User %r selected role %r via SAML role picker',
                str(user_info.get('email') or ''), str(role))

            # Provision user with the chosen role
            if self._is_user_provisioning_enabled():
                await self._provision_user(user_info, role)

            # ...and then make sure the choice actually reached the session,
            # because provisioning may be disabled, may skip an existing user, or
            # may have failed silently. Refuse rather than log the user in with
            # the role their account happened to already have.
            if not await self._apply_selected_role(user_info, role):
                self.log.error('Refusing SAML login: selected role %r could not be applied for %r',
                               str(role), str(user_info.get('email') or ''))
                return web.Response(
                    status=403,
                    content_type='text/html',
                    text=('<!DOCTYPE html><html><body style="font-family:system-ui;padding:2rem">'
                          '<h2>Sign-in could not complete</h2><p>The selected role could not be '
                          'applied to your session, so you have not been signed in. This is '
                          'deliberate: continuing would have given you a different role from the '
                          'one you chose.</p><p>Contact your Caldera administrator.</p>'
                          '</body></html>'))

            return await self._authenticate_user(request, role, user_info)

        raise web.HTTPMethodNotAllowed(request.method, ['GET', 'POST'])

    async def _apply_selected_role(self, user_info: Dict[str, Any], caldera_role: str) -> bool:
        """Make the picker's choice true for the SESSION, whatever provisioning says.

        _authenticate_user accepts caldera_role and only LOGS it; it then calls
        auth_svc.handle_successful_login(request, username), so the session's
        permissions come from the existing user_map entry. Only _provision_user
        writes that entry, and it is skipped entirely when
        user_provisioning.enabled is false, skipped for an existing user when
        update_on_login is false, and swallows every exception when it does run.

        So on any of those three paths the picker told the user a role had been
        applied while the session kept the account's previous one -- selecting
        Blue on a red account produced a RED session (Codex review on
        mnescot/saml#6). That is a privilege-relevant lie in the UI, not a no-op.

        Returns True only when the entry actually carries the role afterwards.
        The caller refuses the login on False rather than proceeding with
        whatever the account already had.

        The write is still bounded by the operator's provisioning settings. An
        earlier revision wrote unconditionally -- "make the choice true whatever
        provisioning says" -- which turned the picker into its own account
        creation path around user_provisioning.enabled (default FALSE),
        create_missing_users and update_on_login: every identity the IdP accepted
        could obtain a Caldera account on a deployment whose operator had
        switched automatic provisioning off (Codex P1 + AWS HIGH on
        caldera-deployalt#379).

        Refusing is the resolution, not writing anyway. Both properties then
        hold at once: the picker never lies about the role a session carries,
        AND it never creates or rewrites an account the operator did not permit.
        A user whose account already carries the chosen role still signs in with
        provisioning fully disabled, because that path needs no write at all.
        """
        auth_svc = self.get_service('auth_svc')
        if not auth_svc:
            self.log.error('Auth service unavailable; cannot apply the selected role')
            return False
        username = user_info.get('email')
        if not username:
            self.log.error('No email in SAML response; cannot apply the selected role')
            return False

        existing = auth_svc.user_map.get(username)
        if existing is not None and caldera_role in tuple(getattr(existing, 'permissions', ()) or ()):
            # Already correct, so there is nothing to write and nothing to gate.
            return True

        # Re-derive entitlement against the IdP attributes immediately before the
        # write. The handler checks this too, but a writer that trusts its caller
        # is one refactor away from being reachable without the check.
        try:
            entitled = self._entitled_roles(user_info)
        except Exception as exc:  # noqa: BLE001 - fail closed
            self.log.error('Entitlement re-check failed for %r: %s', username, exc)
            return False
        if caldera_role not in entitled:
            self.log.error('Refusing to apply %r for %r: not entitled (entitled=%s)',
                           caldera_role, username, sorted(entitled))
            return False

        if not self._may_write_user(user_exists=existing is not None):
            self.log.error(
                'Refusing to apply %r for %r: user provisioning does not permit '
                'writing this account (enabled=%s, exists=%s). The login is refused '
                'rather than proceeding with a different role than was chosen.',
                caldera_role, username, self._is_user_provisioning_enabled(),
                existing is not None)
            return False

        # Reuse the stored password: create_user REPLACES the entry, and minting
        # a new one on every login would churn a credential for no reason.
        password = getattr(existing, 'password', None) or self._generate_temp_password()
        try:
            await auth_svc.create_user(username, password, caldera_role)
        except Exception as exc:  # noqa: BLE001 - surfaced as a refusal below
            self.log.error('Applying selected role %r for %r failed: %s',
                           caldera_role, username, exc)
            return False

        updated = auth_svc.user_map.get(username)
        applied = caldera_role in tuple(getattr(updated, 'permissions', ()) or ())
        if not applied:
            self.log.error('user_map for %r does not carry %r after create_user',
                           username, caldera_role)
        return applied

    @staticmethod
    def _html_escape(text: str) -> str:
        """Minimal HTML escaping for safe inline rendering."""
        return (
            text.replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;')
        )

    # Entra signals ">150 groups, fetch them from Graph instead" by sending this
    # link INSTEAD of the groups claim. Membership is then simply absent from the
    # assertion, so a group-based entitlement silently cannot be satisfied. We
    # cannot resolve it (no Graph credentials here), but a login that quietly
    # drops to blue for this reason must say so rather than look like a plain
    # not-a-member.
    _GROUPS_OVERAGE_ATTRS = (
        'http://schemas.microsoft.com/claims/groups.link',
        'urn:mace:dir:attribute-def:isMemberOf.link',
    )

    def _identity_values(self, identity: Dict[str, Any], candidates) -> list:
        """First non-empty attribute among candidates, always as a list.

        Order matters: the CONFIGURED name is tried before the well-known short
        names, so an operator who sets user_provisioning.group_attribute gets
        exactly the claim they nominated rather than whichever fallback happens
        to also be present.
        """
        for attr in candidates:
            if not attr:
                continue
            value = identity.get(attr)
            if value in (None, '', [], ()):
                continue
            return list(value) if isinstance(value, (list, tuple)) else [value]
        return []

    def _extract_user_info_from_identity(self, identity: Dict[str, Any], subject) -> Dict[str, Any]:
        """Extract user information from SAML identity attributes.

        Reads the CONFIGURED claim names first (user_provisioning.*_attribute),
        falling back to the well-known short names.

        This function used to match on short names ONLY -- 'group', 'groups',
        'Group', 'Groups', 'memberOf' -- while the configured name was honoured
        just by _extract_user_info, which serves the unused python3-saml path.
        pysaml2 is the live path, and for a claim it has no converter for it
        keys the value by the attribute's FULL NAME (lcd_ava_from returns
        attribute.name verbatim), so Entra's

            http://schemas.microsoft.com/ws/2008/06/identity/claims/groups

        matched nothing and every group-based entitlement was unreachable. That
        is why setting allow_unknown_attributes was necessary but not
        sufficient: it stopped pysaml2 discarding the attribute, and then this
        function discarded it one layer further on. Both had to be fixed for a
        group to reach _entitled_roles, which is why the symptom -- SSO logins
        capped at blue -- survived the first repair unchanged.
        """
        up = self._saml_config.get('user_provisioning', {})
        user_info = {
            'name_id': subject.text,
            'email': None,
            'display_name': None,
            'roles': [],
            'groups': [],
        }

        emails = self._identity_values(identity, [
            up.get('email_attribute'),
            'email', 'emailAddress', 'mail',
            'urn:oid:0.9.2342.19200300.100.1.3',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        ])
        if emails:
            user_info['email'] = emails[0]

        names = self._identity_values(identity, [
            up.get('name_attribute'),
            'displayName', 'cn', 'commonName', 'name',
            'urn:oid:2.5.4.3',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        ])
        if names:
            user_info['display_name'] = names[0]

        user_info['roles'] = self._identity_values(identity, [
            up.get('role_attribute'),
            'role', 'roles', 'Role', 'Roles',
            'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
        ])
        user_info['groups'] = self._identity_values(identity, [
            up.get('group_attribute'),
            'group', 'groups', 'Group', 'Groups', 'memberOf',
            'http://schemas.xmlsoap.org/claims/Group',
        ])

        if not user_info['groups']:
            overage = self._identity_values(identity, list(self._GROUPS_OVERAGE_ATTRS))
            if overage:
                self.log.warning(
                    'SAML entitlement: the IdP returned a groups OVERAGE link '
                    'instead of the group values, so membership is absent from '
                    'the assertion and no group-based entitlement can be '
                    'satisfied. Restrict the application group claim (for '
                    'example to "Groups assigned to the application") so the '
                    'set stays under the assertion limit.')

            # NAMES the IdP actually delivered -- never their values. This is
            # the one fact that separates the two causes of an empty group set,
            # and not having it cost two deploy cycles of inference: an empty
            # list here means the IdP sent no attributes at all (configure the
            # claim in the enterprise application), whereas a populated list
            # that lacks group_attribute means the claim is arriving under a
            # DIFFERENT name and group_attribute should be set to one of these.
            #
            # Names are claim URIs and carry no membership information, so this
            # is not the disclosure risk that listing the values would be
            # (CWE-532).
            #
            # The names are IdP-controlled, so a CR/LF in one would forge whole
            # log records (CWE-117). They are passed as a LIST, and %s of a list
            # reprs each element, which is what escapes the newline -- so do not
            # "tidy" this into ', '.join(...), which would emit them raw. An
            # earlier version also wrapped each name in repr() by hand; that was
            # redundant double-quoting, and it hid which mechanism was actually
            # doing the escaping.
            self.log.info(
                'SAML entitlement: no group values resolved. Attribute names '
                'present in the assertion: %s (configured group_attribute=%r)',
                sorted(str(k) for k in identity), up.get('group_attribute'))

        return user_info

    async def _handle_enhanced_authentication(self, request, saml_auth):
        """Enhanced authentication handler with automatic user provisioning"""
        try:
            # Extract user information from SAML response
            user_info = self._extract_user_info(saml_auth)
            self.log.debug('Extracted user info: %r', user_info)

            # Determine Caldera role based on SAML attributes
            caldera_role = self._determine_caldera_role(user_info)
            self.log.debug(f'Determined Caldera role: {caldera_role}')

            # Provision or update user if enabled
            if self._is_user_provisioning_enabled():
                await self._provision_user(user_info, caldera_role)

            # Authenticate user (will raise HTTPFound redirect on success)
            await self._authenticate_user(request, caldera_role, user_info)

        except web.HTTPRedirection:
            # Re-raise redirects (this is expected for successful login)
            raise
        except Exception as e:
            self.log.error(f'Enhanced authentication failed: {e}')
            raise web.HTTPFound('/login')

    def _extract_user_info(self, saml_auth) -> Dict[str, Any]:
        """Extract user information from SAML response"""
        attributes = saml_auth.get_attributes()
        name_id = saml_auth.get_nameid()

        # Get configuration for attribute names
        user_provisioning = self._saml_config.get('user_provisioning', {})
        email_attr = user_provisioning.get('email_attribute', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')
        name_attr = user_provisioning.get('name_attribute', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name')
        role_attr = user_provisioning.get('role_attribute', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role')
        group_attr = user_provisioning.get('group_attribute', 'http://schemas.xmlsoap.org/claims/Group')

        # Extract values
        user_info = {
            'name_id': name_id,
            'email': self._get_attribute_value(attributes, email_attr),
            'display_name': self._get_attribute_value(attributes, name_attr),
            'roles': self._get_attribute_values(attributes, role_attr),
            'groups': self._get_attribute_values(attributes, group_attr),
            'all_attributes': attributes
        }

        # Use name_id as email if email not found
        if not user_info['email'] and name_id:
            user_info['email'] = name_id

        return user_info

    def _get_attribute_value(self, attributes: Dict, attr_name: str) -> Optional[str]:
        """Get single attribute value"""
        values = attributes.get(attr_name, [])
        return values[0] if values else None

    def _get_attribute_values(self, attributes: Dict, attr_name: str) -> list:
        """Get multiple attribute values"""
        return attributes.get(attr_name, [])

    def _normalize_caldera_role(self, role: str) -> str:
        """
        Normalize role names to match Caldera's valid role set.

        Caldera only accepts: 'red', 'blue', 'user' (case-sensitive)
        The Access enum in auth_svc.py only has RED, BLUE, USER members.

        This method transforms common role names to valid Caldera roles:
        - 'admin', 'administrator' → 'red' (highest privilege)
        - 'red', 'blue', 'user' → unchanged (already valid)
        """
        role_lower = role.lower()

        # Map admin role variants to Caldera's 'red' role
        if role_lower in ['admin', 'administrator']:
            return 'red'

        # Return valid Caldera roles as-is
        return role

    # The DEFAULT here is load-bearing: with no admin_roles configured, an
    # IdP-asserted "admin"/"administrator" still confers red. Both the decision
    # and the audit record MUST read the allowlists through this one helper.
    # They previously did not -- the decision defaulted to
    # ['admin', 'administrator'] while the audit line defaulted to [] -- so a
    # deployment relying on the default logged "matched=red" beside
    # "admin_roles_configured=0 matched_admin_roles=[]", contradicting the very
    # decision it exists to document. One reader, one default, no drift.
    def _admin_allowlists(self):
        """Return (admin_roles, admin_groups) normalised for comparison."""
        up = self._saml_config.get('user_provisioning', {})
        return (
            {str(r).lower() for r in up.get('admin_roles', ['admin', 'administrator'])},
            {str(g).lower() for g in up.get('admin_groups', [])},
        )

    #: Most privileged first. _normalize_caldera_role folds 'admin' into 'red',
    #: so these are the only values an assertion can produce.
    _ROLE_PRECEDENCE = ('red', 'blue', 'user')

    def _asserted_caldera_roles(self, user_info: Dict[str, Any]) -> set:
        """EVERY Caldera role the IdP explicitly asserts for this user.

        Collected rather than short-circuited on the first match. Returning the
        first one made the result depend on the ORDER of keys in
        user_mapping.json and on the order groups arrive in the assertion, so a
        user entitled to both blue and red was offered only whichever mapping
        happened to come first -- and the picker exists precisely for users with
        more than one entitlement. Two users with identical entitlements could
        get different pickers (AWS/Codex review on mnescot/saml#6).
        """
        matched = set()
        admin_roles, admin_groups = self._admin_allowlists()
        roles = [str(r).lower() for r in user_info.get('roles', [])]
        groups = [str(g).lower() for g in user_info.get('groups', [])]

        if any(r in admin_roles for r in roles) or any(g in admin_groups for g in groups):
            matched.add(self._normalize_caldera_role('red'))

        role_mappings = self._user_mapping_config.get('role_mappings', {}) or {}
        for caldera_role, saml_roles in role_mappings.items():
            if any(r in [str(s).lower() for s in saml_roles] for r in roles):
                matched.add(self._normalize_caldera_role(caldera_role))

        group_mappings = {str(k).lower(): v for k, v in
                          (self._user_mapping_config.get('group_mappings', {}) or {}).items()}
        for g in groups:
            if g in group_mappings:
                matched.add(self._normalize_caldera_role(group_mappings[g]))

        email = str(user_info.get('email') or '')
        if '@' in email:
            domain = email.rsplit('@', 1)[-1].lower()
            domain_mappings = {str(k).lower(): v for k, v in
                               (self._user_mapping_config.get('email_domain_mappings', {}) or {}).items()}
            if domain in domain_mappings:
                matched.add(self._normalize_caldera_role(domain_mappings[domain]))
        return matched

    def _matched_caldera_role(self, user_info: Dict[str, Any]):
        """The Caldera role EXPLICITLY asserted by the IdP for this user, or None
        if no role/group/domain rule matched.

        Unlike _determine_caldera_role this NEVER falls back to
        user_provisioning.default_role, so an operator default of 'admin'/'red'
        can never silently confer offensive (`red`) entitlement on an identity the
        IdP asserted nothing about. All comparisons are case-insensitive so an
        Entra casing/format difference does not fall through to a broader tier."""
        matched = self._asserted_caldera_roles(user_info)
        # Deterministic and order-independent: the most privileged asserted role
        # wins, rather than whichever mapping happened to be listed first.
        for role in self._ROLE_PRECEDENCE:
            if role in matched:
                return role
        return None

    def _entitled_roles(self, user_info: Dict[str, Any]) -> set:
        """Roles the IdP entitles this user to SELECT in the picker.

        Any authenticated SSO user may operate as blue; 'red' is offered ONLY when
        the IdP EXPLICITLY asserts a red/admin entitlement (via
        _matched_caldera_role, which ignores default_role), so neither an ordinary
        employee nor a privileged default_role can self-assign the offensive tier."""
        entitled = {'blue'}
        matched = None
        try:
            matched = self._matched_caldera_role(user_info)
            if matched == 'red':
                entitled.add('red')
        except Exception as e:  # noqa: BLE001 - fail closed to blue-only
            self.log.warning(f'Entitlement resolution failed, defaulting to blue: {e}')

        # Blue-only is the SILENT outcome: the picker simply omits the red
        # button and nothing else records why, which is how a library-level
        # attribute loss survived days of inference. This line exists so the
        # decision is never silent again.
        #
        # It is deliberately NOT a dump of the assertion. This is the audit
        # record for the control that gates the offensive red tier, so it has to
        # be tamper-evident and it must not become a disclosure channel:
        #
        #   * the subject is rendered with %r -- an IdP-influenced NameID or
        #     email containing CR/LF could otherwise forge whole log records,
        #     including a fabricated matched=red line for another subject
        #     (CWE-117), which would corrupt the very trail this provides;
        #   * received groups are counted, never listed. With "Security groups"
        #     or "All groups" configured, that list is the user's entire
        #     organisational membership; being in the IdP does not make it
        #     appropriate for every log reader (CWE-532);
        #   * only the INTERSECTION with the configured admin allowlist is named.
        #     Those values are already in settings.json, so they disclose
        #     nothing new, and they are the ones an operator actually needs;
        #   * the allowlists themselves are counted, not printed.
        #
        # It stays unconditional rather than behind a debug flag: a flag is off
        # exactly when the failure is being investigated, which is the situation
        # that made this necessary.
        up = self._saml_config.get('user_provisioning', {})
        groups = [str(g) for g in (user_info.get('groups') or [])]
        roles = [str(r) for r in (user_info.get('roles') or [])]
        admin_roles, admin_groups = self._admin_allowlists()
        matched_groups = sorted(admin_groups & {g.lower() for g in groups})
        matched_roles = sorted(admin_roles & {r.lower() for r in roles})
        self.log.info(
            'SAML entitlement: subject=%r matched=%s entitled=%s | '
            'group_attribute=%r groups_received=%d roles_received=%d | '
            'admin_groups_configured=%d admin_roles_configured=%d | '
            'matched_admin_groups=%s matched_admin_roles=%s',
            str(user_info.get('email') or user_info.get('name_id') or ''),
            matched, sorted(entitled),
            up.get('group_attribute'), len(groups), len(roles),
            len(admin_groups), len(admin_roles),
            matched_groups, matched_roles)
        if not groups:
            self.log.warning(
                'SAML entitlement: the IdP sent NO values for %r. Every '
                'group-based entitlement is unreachable until that claim '
                'reaches the application. Check that the SAML library is not '
                'discarding it (pysaml2 drops attributes it cannot map unless '
                'allow_unknown_attributes is set, logging only "Unknown '
                'attribute name" at INFO), that the group is ASSIGNED to the '
                'enterprise application, and that the assertion is not '
                'returning a groups overage link.',
                up.get('group_attribute'))
        return entitled

    def _determine_caldera_role(self, user_info: Dict[str, Any]) -> str:
        """Determine a Caldera role from SAML attributes and the mapping config.

        NOT on the live login path: the ACS handler stores pending auth and
        redirects to the role picker, which decides through _entitled_roles.
        Its only caller, _handle_enhanced_authentication, has none of its own.
        It is hardened rather than left as written because a dormant second
        decision function with weaker rules is a loaded gun -- anything that
        wires it up later inherits whatever it does today.

        Three divergences from _matched_caldera_role are corrected here:

          * it re-read the admin allowlists itself, so the two could drift
            apart exactly as the audit record did. It now reads
            _admin_allowlists(), the single owner of the values AND the default;
          * group comparisons were CASE-SENSITIVE while the helper lowercases,
            so an Entra casing difference silently changed the tier;
          * it ended with _normalize_caldera_role(default_role), which maps
            admin/administrator -> red. With user_provisioning.default_role set
            to "admin" or "red" -- and this deployment's settings.json does set
            "default_role": "red" -- that hands the offensive tier to a user the
            IdP asserted nothing about. default_role is an operator convenience,
            never an entitlement, so it is now clamped away from red.
        """
        user_provisioning = self._saml_config.get('user_provisioning', {})
        default_role = user_provisioning.get('default_role', 'blue')
        admin_roles, admin_groups = self._admin_allowlists()
        roles = [str(r).lower() for r in user_info.get('roles', [])]
        groups = [str(g).lower() for g in user_info.get('groups', [])]

        if any(role in admin_roles for role in roles):
            return self._normalize_caldera_role('red')

        if any(group in admin_groups for group in groups):
            return self._normalize_caldera_role('red')

        role_mappings = self._user_mapping_config.get('role_mappings', {}) or {}
        for caldera_role, saml_roles in role_mappings.items():
            if any(role in [str(s).lower() for s in saml_roles] for role in roles):
                return self._normalize_caldera_role(caldera_role)

        group_mappings = {str(k).lower(): v for k, v in
                          (self._user_mapping_config.get('group_mappings', {}) or {}).items()}
        for group in groups:
            if group in group_mappings:
                return self._normalize_caldera_role(group_mappings[group])

        email_domain_mappings = {str(k).lower(): v for k, v in
                                 (self._user_mapping_config.get('email_domain_mappings', {}) or {}).items()}
        email = str(user_info.get('email') or '')
        if '@' in email:
            domain = email.rsplit('@', 1)[-1].lower()
            if domain in email_domain_mappings:
                return self._normalize_caldera_role(email_domain_mappings[domain])

        # An UNASSERTED identity never receives the offensive tier, whatever the
        # operator set default_role to.
        fallback = self._normalize_caldera_role(default_role)
        if fallback == 'red':
            self.log.warning(
                'SAML: default_role=%r would confer the offensive red tier on an '
                'identity the IdP asserted nothing about; clamping to blue',
                default_role)
            return 'blue'
        return fallback

    def _is_user_provisioning_enabled(self) -> bool:
        """Check if user provisioning is enabled"""
        user_provisioning = self._saml_config.get('user_provisioning', {})
        return user_provisioning.get('enabled', False)

    def _may_write_user(self, user_exists: bool) -> bool:
        """Whether the operator's settings permit writing this entry to user_map.

        The single source of truth for that question. It used to be spelled out
        inline in _provision_user only, which is how _apply_selected_role came to
        write accounts the operator had switched off: two writers, one set of
        rules, and only one of them reading it. Note `enabled` defaults to FALSE,
        so "no automatic account management" is the OUT-OF-THE-BOX state, not just
        a hardening step someone opted into.
        """
        if not self._is_user_provisioning_enabled():
            return False
        user_provisioning = self._saml_config.get('user_provisioning', {})
        if user_exists:
            return bool(user_provisioning.get('update_on_login', True))
        return bool(user_provisioning.get('create_missing_users', True))

    async def _provision_user(self, user_info: Dict[str, Any], caldera_role: str):
        """Provision or update user in Caldera using proper User namedtuple structure"""
        try:
            auth_svc = self.get_service('auth_svc')
            if not auth_svc:
                raise Exception('Auth service not available')

            email = user_info.get('email')
            display_name = user_info.get('display_name', email)

            if not email:
                self.log.warning('No email found in SAML response, cannot provision user')
                return

            # Use email as username (key in user_map)
            username = email

            # Check if user exists by username (email), not role
            user_exists = username in auth_svc.user_map

            create_missing = self._may_write_user(user_exists=False)
            update_on_login = self._may_write_user(user_exists=True)

            if not user_exists and create_missing:
                self.log.info(f'Creating new user: {username} with role {caldera_role}')
                password = self._generate_temp_password()
                await auth_svc.create_user(username, password, caldera_role)
                self.log.info(f'User {username} created successfully with role {caldera_role}')

            elif user_exists and update_on_login:
                self.log.debug(f'Updating existing user: {username}')
                password = self._generate_temp_password()
                # Recreate user to update role and refresh password
                await auth_svc.create_user(username, password, caldera_role)
                self.log.debug(f'User {username} updated successfully')

        except Exception as e:
            self.log.error(f'User provisioning failed: {e}')
            # Don't fail authentication if provisioning fails
            pass

    def _get_role_privileges(self, role: str) -> list:
        """Get privileges for a Caldera role"""
        role_privileges = {
            'admin': ['red', 'blue'],
            'red': ['red'],
            'blue': ['blue'],
            'user': []
        }
        return role_privileges.get(role, [])

    def _generate_temp_password(self) -> str:
        """Generate a temporary password for SAML users"""
        import string
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(16))

    def _get_current_timestamp(self) -> str:
        """Get current timestamp as string"""
        from datetime import datetime
        return datetime.utcnow().isoformat()

    async def _authenticate_user(self, request, caldera_role: str, user_info: Dict[str, Any]):
        """Authenticate user with Caldera using email as username"""
        auth_svc = self.get_service('auth_svc')
        if not auth_svc:
            raise Exception('Auth service not available')

        email = user_info.get('email', 'unknown@unknown.com')
        display_name = user_info.get('display_name', email)

        # Use email as username (key in user_map), not role!
        username = email

        if username in auth_svc.user_map:
            self.log.info(f'User "{display_name}" ({username}) authenticated via SAML with role "{caldera_role}"')
            try:
                await auth_svc.handle_successful_login(request, username)
            except web.HTTPFound as landing:
                raise self._chain_agentcore_identity(landing)
        else:
            self.log.warning(f'User "{username}" not found in user_map. Role: "{caldera_role}", Display name: "{display_name}"')
            raise web.HTTPFound('/login')

    # The managed harness calls AgentCore as the USER, using a delegated token
    # minted by a separate Cognito authorization-code flow. Nothing used to
    # start that flow, so every chat turn failed with "delegated harness
    # identity unavailable" until the user found and visited a second login URL
    # -- on every browser session, and again after each restart.
    #
    # Chaining it onto the end of the SAML login makes it invisible: the user
    # has just proved the same identity to the same Entra tenant Cognito
    # federates to, so the hop completes as redirects with nothing displayed.
    #
    # A TOP-LEVEL redirect, deliberately, not a hidden iframe running
    # prompt=none. The Cognito hosted UI is on amazoncognito.com while the
    # application is not, so an iframe would be cross-site and its session
    # cookie a third-party one: Safari blocks those outright, Firefox blocks
    # them by default, and Chrome is restricting them. Silent auth would have
    # failed for most users, intermittently and by browser.
    AGENTCORE_IDENTITY_CHAIN = '/plugins/infosec_agent/api/identity/oauth/login'

    def _chain_agentcore_identity(self, landing):
        """Redirect the post-login landing through the delegated-identity flow.

        soft=1 so this can never break a login: if the identity plane is off,
        misconfigured, or mid-deploy, that endpoint sends the user straight on
        to `next` instead of erroring. The worst case is the behaviour that
        preceded this change, not a failed SSO.
        """
        try:
            destination = str(landing.location or '/')
            if not destination.startswith('/') or destination.startswith('//'):
                destination = '/'
            if destination.startswith(self.AGENTCORE_IDENTITY_CHAIN):
                return landing  # already chained; never loop
            return web.HTTPFound(
                '%s?soft=1&next=%s' % (self.AGENTCORE_IDENTITY_CHAIN,
                                       urllib.parse.quote(destination, safe='')))
        except Exception as e:  # noqa: BLE001 - a login must not fail on this
            self.log.warning('AgentCore identity chain skipped: %s', e)
            return landing

    # ── Specific handler methods for different SAML endpoints ─────────────────

    async def saml_login_handler(self, request):
        """Handle SAML login initiation (GET)"""
        self.log.debug('SAML login handler called')
        return await self._saml_login(request)

    async def saml_acs_handler(self, request):
        """Handle SAML assertion consumer service (POST)"""
        self.log.debug('SAML ACS handler called')
        return await self._saml_login(request)

    async def saml_metadata_handler(self, request):
        """Generate and return SAML SP metadata"""
        try:
            client = self._get_saml2_client()

            # Generate metadata
            metadata = create_metadata_string(
                configfile=None,
                config=client.config,
                valid_for=24  # hours
            )

            return web.Response(
                text=metadata.decode('utf-8') if isinstance(metadata, bytes) else metadata,
                content_type='application/xml'
            )
        except Exception as e:
            self.log.exception(f'Error generating SAML metadata: {e}')
            return web.Response(text='Error generating metadata', status=500)

    async def saml_sls_handler(self, request):
        """Handle SAML Single Logout Service (SLS)"""
        self.log.debug('SAML SLS (logout) not yet implemented')
        raise web.HTTPFound('/login')

    async def set_saml_login_handler(self):
        """Set self as the optional login handler for the auth service."""
        self.log.debug('SAML login handler initialization complete.')
        pass


# Legacy compatibility methods (to be removed in future versions)

    async def get_saml_auth(self, request):
        """
        DEPRECATED: Legacy method for OneLogin compatibility.
        Returns a wrapper object for backward compatibility.
        """
        self.log.warning('get_saml_auth() is deprecated - using pysaml2 client instead')

        class LegacySamlAuthWrapper:
            """Wrapper to provide OneLogin-like interface for legacy code"""
            def __init__(self, service, request):
                self.service = service
                self.request = request
                self.client = service._get_saml2_client()
                self._authenticated = False
                self._identity = None
                self._subject = None

            def login(self, return_to=None):
                """Initiate login - returns redirect URL"""
                session_id, info = self.client.prepare_for_authenticate()
                for key, value in info['headers']:
                    if key == 'Location':
                        return value
                return None

            def process_response(self):
                """Process SAML response"""
                # This is a no-op in the wrapper - actual processing happens elsewhere
                pass

            def is_authenticated(self):
                """Check if authenticated"""
                return self._authenticated

            def get_attributes(self):
                """Get user attributes"""
                return self._identity if self._identity else {}

            def get_nameid(self):
                """Get name ID"""
                return self._subject.text if self._subject else None

            def get_errors(self):
                """Get errors - returns empty list for compatibility"""
                return []

        return LegacySamlAuthWrapper(self, request)

    async def _prepare_auth_parameter(self, request):
        """
        DEPRECATED: Legacy method for OneLogin compatibility.
        Convert aiohttp request to auth parameter format.
        """
        self.log.warning('_prepare_auth_parameter() is deprecated')

        post_data = {}
        if request.method == 'POST':
            post_data = await request.post()
            post_data = {k: v for k, v in post_data.items()}

        get_data = {k: v for k, v in request.query.items()}

        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'server_port': request.url.port or (443 if request.scheme == 'https' else 80),
            'script_name': request.path,
            'get_data': get_data,
            'post_data': post_data,
            'query_string': request.query_string,
        }

    def _handle_saml_auth_errors(self, saml_auth):
        """
        DEPRECATED: Legacy method for OneLogin compatibility.
        Check for and handle SAML authentication errors.
        """
        self.log.warning('_handle_saml_auth_errors() is deprecated')
        # No-op for compatibility
        pass

    @staticmethod
    def _get_saml_login_username(saml_auth):
        """Get username from SAML NameID"""
        name_id = saml_auth.get_nameid()
        if name_id:
            return name_id
        return SamlService._get_saml_username_attribute(saml_auth)

    @staticmethod
    def _get_saml_username_attribute(saml_auth):
        """Get username from SAML attributes"""
        attributes = saml_auth.get_attributes()
        username_attr_list = attributes.get('username', [])
        return username_attr_list[0] if len(username_attr_list) > 0 else None
