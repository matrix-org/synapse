# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2019 - 2020 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
import time
import unicodedata
import urllib.parse
from binascii import crc32
from http import HTTPStatus
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    Union,
    cast,
)

import attr
import bcrypt
import unpaddedbase64

from twisted.internet.defer import CancelledError
from twisted.web.server import Request

from synapse.api.constants import LoginType
from synapse.api.errors import (
    AuthError,
    Codes,
    InteractiveAuthIncompleteError,
    LoginError,
    StoreError,
    SynapseError,
    UserDeactivatedError,
)
from synapse.api.ratelimiting import Ratelimiter
from synapse.handlers.ui_auth import (
    INTERACTIVE_AUTH_CHECKERS,
    UIAuthSessionDataConstants,
)
from synapse.handlers.ui_auth.checkers import UserInteractiveAuthChecker
from synapse.http import get_request_user_agent
from synapse.http.server import finish_request, respond_with_html
from synapse.http.site import SynapseRequest
from synapse.logging.context import defer_to_thread
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import JsonDict, Requester, UserID
from synapse.util import stringutils as stringutils
from synapse.util.async_helpers import delay_cancellation, maybe_awaitable
from synapse.util.macaroons import LoginTokenAttributes
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.stringutils import base62_encode
from synapse.util.threepids import canonicalise_email

if TYPE_CHECKING:
    from synapse.module_api import ModuleApi
    from synapse.rest.client.login import LoginResponse
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

INVALID_USERNAME_OR_PASSWORD = "Invalid username or password"


def convert_client_dict_legacy_fields_to_identifier(
    submission: JsonDict,
) -> Dict[str, str]:
    """
    Convert a legacy-formatted login submission to an identifier dict.

    Legacy login submissions (used in both login and user-interactive authentication)
    provide user-identifying information at the top-level instead.

    These are now deprecated and replaced with identifiers:
    https://matrix.org/docs/spec/client_server/r0.6.1#identifier-types

    Args:
        submission: The client dict to convert

    Returns:
        The matching identifier dict

    Raises:
        SynapseError: If the format of the client dict is invalid
    """
    identifier = submission.get("identifier", {})

    # Generate an m.id.user identifier if "user" parameter is present
    user = submission.get("user")
    if user:
        identifier = {"type": "m.id.user", "user": user}

    # Generate an m.id.thirdparty identifier if "medium" and "address" parameters are present
    medium = submission.get("medium")
    address = submission.get("address")
    if medium and address:
        identifier = {
            "type": "m.id.thirdparty",
            "medium": medium,
            "address": address,
        }

    # We've converted valid, legacy login submissions to an identifier. If the
    # submission still doesn't have an identifier, it's invalid
    if not identifier:
        raise SynapseError(400, "Invalid login submission", Codes.INVALID_PARAM)

    # Ensure the identifier has a type
    if "type" not in identifier:
        raise SynapseError(
            400,
            "'identifier' dict has no key 'type'",
            errcode=Codes.MISSING_PARAM,
        )

    return identifier


def login_id_phone_to_thirdparty(identifier: JsonDict) -> Dict[str, str]:
    """
    Convert a phone login identifier type to a generic threepid identifier.

    Args:
        identifier: Login identifier dict of type 'm.id.phone'

    Returns:
        An equivalent m.id.thirdparty identifier dict
    """
    if "country" not in identifier or (
        # The specification requires a "phone" field, while Synapse used to require a "number"
        # field. Accept both for backwards compatibility.
        "phone" not in identifier
        and "number" not in identifier
    ):
        raise SynapseError(
            400, "Invalid phone-type identifier", errcode=Codes.INVALID_PARAM
        )

    # Accept both "phone" and "number" as valid keys in m.id.phone
    phone_number = identifier.get("phone", identifier["number"])

    # Convert user-provided phone number to a consistent representation
    msisdn = phone_number_to_msisdn(identifier["country"], phone_number)

    return {
        "type": "m.id.thirdparty",
        "medium": "msisdn",
        "address": msisdn,
    }


@attr.s(slots=True, auto_attribs=True)
class SsoLoginExtraAttributes:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time: int
    extra_attributes: JsonDict


class AuthHandler:
    SESSION_EXPIRE_MS = 48 * 60 * 60 * 1000

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.auth_blocking = hs.get_auth_blocking()
        self.clock = hs.get_clock()
        self.checkers: Dict[str, UserInteractiveAuthChecker] = {}
        for auth_checker_class in INTERACTIVE_AUTH_CHECKERS:
            inst = auth_checker_class(hs)
            if inst.is_enabled():
                self.checkers[inst.AUTH_TYPE] = inst  # type: ignore

        self.bcrypt_rounds = hs.config.registration.bcrypt_rounds

        self.password_auth_provider = hs.get_password_auth_provider()

        self.hs = hs  # FIXME better possibility to access registrationHandler later?
        self.macaroon_gen = hs.get_macaroon_generator()
        self._password_enabled_for_login = hs.config.auth.password_enabled_for_login
        self._password_enabled_for_reauth = hs.config.auth.password_enabled_for_reauth
        self._password_localdb_enabled = hs.config.auth.password_localdb_enabled
        self._third_party_rules = hs.get_third_party_event_rules()

        # Ratelimiter for failed auth during UIA. Uses same ratelimit config
        # as per `rc_login.failed_attempts`.
        self._failed_uia_attempts_ratelimiter = Ratelimiter(
            store=self.store,
            clock=self.clock,
            rate_hz=self.hs.config.ratelimiting.rc_login_failed_attempts.per_second,
            burst_count=self.hs.config.ratelimiting.rc_login_failed_attempts.burst_count,
        )

        # The number of seconds to keep a UI auth session active.
        self._ui_auth_session_timeout = hs.config.auth.ui_auth_session_timeout

        # Ratelimitier for failed /login attempts
        self._failed_login_attempts_ratelimiter = Ratelimiter(
            store=self.store,
            clock=hs.get_clock(),
            rate_hz=self.hs.config.ratelimiting.rc_login_failed_attempts.per_second,
            burst_count=self.hs.config.ratelimiting.rc_login_failed_attempts.burst_count,
        )

        self._clock = self.hs.get_clock()

        # Expire old UI auth sessions after a period of time.
        if hs.config.worker.run_background_tasks:
            self._clock.looping_call(
                run_as_background_process,
                5 * 60 * 1000,
                "expire_old_sessions",
                self._expire_old_sessions,
            )

        # Load the SSO HTML templates.

        # The following template is shown to the user during a client login via SSO,
        # after the SSO completes and before redirecting them back to their client.
        # It notifies the user they are about to give access to their matrix account
        # to the client.
        self._sso_redirect_confirm_template = (
            hs.config.sso.sso_redirect_confirm_template
        )

        # The following template is shown during user interactive authentication
        # in the fallback auth scenario. It notifies the user that they are
        # authenticating for an operation to occur on their account.
        self._sso_auth_confirm_template = hs.config.sso.sso_auth_confirm_template

        # The following template is shown during the SSO authentication process if
        # the account is deactivated.
        self._sso_account_deactivated_template = (
            hs.config.sso.sso_account_deactivated_template
        )

        self._server_name = hs.config.server.server_name

        # cast to tuple for use with str.startswith
        self._whitelisted_sso_clients = tuple(hs.config.sso.sso_client_whitelist)

        # A mapping of user ID to extra attributes to include in the login
        # response.
        self._extra_attributes: Dict[str, SsoLoginExtraAttributes] = {}

    async def validate_user_via_ui_auth(
        self,
        requester: Requester,
        request: SynapseRequest,
        request_body: Dict[str, Any],
        description: str,
        can_skip_ui_auth: bool = False,
    ) -> Tuple[dict, Optional[str]]:
        """
        Checks that the user is who they claim to be, via a UI auth.

        This is used for things like device deletion and password reset where
        the user already has a valid access token, but we want to double-check
        that it isn't stolen by re-authenticating them.

        Args:
            requester: The user making the request, according to the access token.

            request: The request sent by the client.

            request_body: The body of the request sent by the client

            description: A human readable string to be displayed to the user that
                         describes the operation happening on their account.

            can_skip_ui_auth: True if the UI auth session timeout applies this
                              action. Should be set to False for any "dangerous"
                              actions (e.g. deactivating an account).

        Returns:
            A tuple of (params, session_id).

                'params' contains the parameters for this request (which may
                have been given only in a previous call).

                'session_id' is the ID of this session, either passed in by the
                client or assigned by this call. This is None if UI auth was
                skipped (by re-using a previous validation).

        Raises:
            InteractiveAuthIncompleteError if the client has not yet completed
                any of the permitted login flows

            AuthError if the client has completed a login flow, and it gives
                a different user to `requester`

            LimitExceededError if the ratelimiter's failed request count for this
                user is too high to proceed

        """
        if not requester.access_token_id:
            raise ValueError("Cannot validate a user without an access token")
        if can_skip_ui_auth and self._ui_auth_session_timeout:
            last_validated = await self.store.get_access_token_last_validated(
                requester.access_token_id
            )
            if self.clock.time_msec() - last_validated < self._ui_auth_session_timeout:
                # Return the input parameters, minus the auth key, which matches
                # the logic in check_ui_auth.
                request_body.pop("auth", None)
                return request_body, None

        requester_user_id = requester.user.to_string()

        # Check if we should be ratelimited due to too many previous failed attempts
        await self._failed_uia_attempts_ratelimiter.ratelimit(requester, update=False)

        # build a list of supported flows
        supported_ui_auth_types = await self._get_available_ui_auth_types(
            requester.user
        )
        flows = [[login_type] for login_type in supported_ui_auth_types]

        def get_new_session_data() -> JsonDict:
            return {UIAuthSessionDataConstants.REQUEST_USER_ID: requester_user_id}

        try:
            result, params, session_id = await self.check_ui_auth(
                flows,
                request,
                request_body,
                description,
                get_new_session_data,
            )
        except LoginError:
            # Update the ratelimiter to say we failed (`can_do_action` doesn't raise).
            await self._failed_uia_attempts_ratelimiter.can_do_action(
                requester,
            )
            raise

        # find the completed login type
        for login_type in supported_ui_auth_types:
            if login_type not in result:
                continue

            validated_user_id = result[login_type]
            break
        else:
            # this can't happen
            raise Exception("check_auth returned True but no successful login type")

        # check that the UI auth matched the access token
        if validated_user_id != requester_user_id:
            raise AuthError(403, "Invalid auth")

        # Note that the access token has been validated.
        await self.store.update_access_token_last_validated(requester.access_token_id)

        return params, session_id

    async def _get_available_ui_auth_types(self, user: UserID) -> Iterable[str]:
        """Get a list of the user-interactive authentication types this user can use."""

        ui_auth_types = set()

        # if the HS supports password auth, and the user has a non-null password, we
        # support password auth
        if self._password_localdb_enabled and self._password_enabled_for_reauth:
            lookupres = await self._find_user_id_and_pwd_hash(user.to_string())
            if lookupres:
                _, password_hash = lookupres
                if password_hash:
                    ui_auth_types.add(LoginType.PASSWORD)

        # also allow auth from password providers
        for t in self.password_auth_provider.get_supported_login_types().keys():
            if t == LoginType.PASSWORD and not self._password_enabled_for_reauth:
                continue
            ui_auth_types.add(t)

        # if sso is enabled, allow the user to log in via SSO iff they have a mapping
        # from sso to mxid.
        if await self.hs.get_sso_handler().get_identity_providers_for_user(
            user.to_string()
        ):
            ui_auth_types.add(LoginType.SSO)

        return ui_auth_types

    def get_enabled_auth_types(self) -> Iterable[str]:
        """Return the enabled user-interactive authentication types

        Returns the UI-Auth types which are supported by the homeserver's current
        config.
        """
        return self.checkers.keys()

    async def check_ui_auth(
        self,
        flows: List[List[str]],
        request: SynapseRequest,
        clientdict: Dict[str, Any],
        description: str,
        get_new_session_data: Optional[Callable[[], JsonDict]] = None,
    ) -> Tuple[dict, dict, str]:
        """
        Takes a dictionary sent by the client in the login / registration
        protocol and handles the User-Interactive Auth flow.

        If no auth flows have been completed successfully, raises an
        InteractiveAuthIncompleteError. To handle this, you can use
        synapse.rest.client._base.interactive_auth_handler as a
        decorator.

        Args:
            flows: A list of login flows. Each flow is an ordered list of
                   strings representing auth-types. At least one full
                   flow must be completed in order for auth to be successful.

            request: The request sent by the client.

            clientdict: The dictionary from the client root level, not the
                        'auth' key: this method prompts for auth if none is sent.

            description: A human readable string to be displayed to the user that
                         describes the operation happening on their account.

            get_new_session_data:
                an optional callback which will be called when starting a new session.
                it should return data to be stored as part of the session.

                The keys of the returned data should be entries in
                UIAuthSessionDataConstants.

        Returns:
            A tuple of (creds, params, session_id).

                'creds' contains the authenticated credentials of each stage.

                'params' contains the parameters for this request (which may
                have been given only in a previous call).

                'session_id' is the ID of this session, either passed in by the
                client or assigned by this call

        Raises:
            InteractiveAuthIncompleteError if the client has not yet completed
                all the stages in any of the permitted flows.
        """

        sid: Optional[str] = None
        authdict = clientdict.pop("auth", {})
        if "session" in authdict:
            sid = authdict["session"]

        # Convert the URI and method to strings.
        uri = request.uri.decode("utf-8")
        method = request.method.decode("utf-8")

        # If there's no session ID, create a new session.
        if not sid:
            new_session_data = get_new_session_data() if get_new_session_data else {}

            session = await self.store.create_ui_auth_session(
                clientdict, uri, method, description
            )

            for k, v in new_session_data.items():
                await self.set_session_data(session.session_id, k, v)

        else:
            try:
                session = await self.store.get_ui_auth_session(sid)
            except StoreError:
                raise SynapseError(400, "Unknown session ID: %s" % (sid,))

            # If the client provides parameters, update what is persisted,
            # otherwise use whatever was last provided.
            #
            # This was designed to allow the client to omit the parameters
            # and just supply the session in subsequent calls so it split
            # auth between devices by just sharing the session, (eg. so you
            # could continue registration from your phone having clicked the
            # email auth link on there). It's probably too open to abuse
            # because it lets unauthenticated clients store arbitrary objects
            # on a homeserver.
            #
            # Revisit: Assuming the REST APIs do sensible validation, the data
            # isn't arbitrary.
            #
            # Note that the registration endpoint explicitly removes the
            # "initial_device_display_name" parameter if it is provided
            # without a "password" parameter. See the changes to
            # synapse.rest.client.register.RegisterRestServlet.on_POST
            # in commit 544722bad23fc31056b9240189c3cbbbf0ffd3f9.
            if not clientdict:
                clientdict = session.clientdict

            # Ensure that the queried operation does not vary between stages of
            # the UI authentication session. This is done by generating a stable
            # comparator and storing it during the initial query. Subsequent
            # queries ensure that this comparator has not changed.
            #
            # The comparator is based on the requested URI and HTTP method. The
            # client dict (minus the auth dict) should also be checked, but some
            # clients are not spec compliant, just warn for now if the client
            # dict changes.
            if (session.uri, session.method) != (uri, method):
                raise SynapseError(
                    403,
                    "Requested operation has changed during the UI authentication session.",
                )

            if session.clientdict != clientdict:
                logger.warning(
                    "Requested operation has changed during the UI "
                    "authentication session. A future version of Synapse "
                    "will remove this capability."
                )

            # For backwards compatibility, changes to the client dict are
            # persisted as clients modify them throughout their user interactive
            # authentication flow.
            await self.store.set_ui_auth_clientdict(sid, clientdict)

        user_agent = get_request_user_agent(request)
        clientip = request.getClientAddress().host

        await self.store.add_user_agent_ip_to_ui_auth_session(
            session.session_id, user_agent, clientip
        )

        if not authdict:
            raise InteractiveAuthIncompleteError(
                session.session_id, self._auth_dict_for_flows(flows, session.session_id)
            )

        # check auth type currently being presented
        errordict: Dict[str, Any] = {}
        if "type" in authdict:
            login_type: str = authdict["type"]
            try:
                result = await self._check_auth_dict(authdict, clientip)
                if result:
                    await self.store.mark_ui_auth_stage_complete(
                        session.session_id, login_type, result
                    )
            except LoginError as e:
                # this step failed. Merge the error dict into the response
                # so that the client can have another go.
                errordict = e.error_dict(self.hs.config)

        creds = await self.store.get_completed_ui_auth_stages(session.session_id)
        for f in flows:
            # If all the required credentials have been supplied, the user has
            # successfully completed the UI auth process!
            if len(set(f) - set(creds)) == 0:
                # it's very useful to know what args are stored, but this can
                # include the password in the case of registering, so only log
                # the keys (confusingly, clientdict may contain a password
                # param, creds is just what the user authed as for UI auth
                # and is not sensitive).
                logger.info(
                    "Auth completed with creds: %r. Client dict has keys: %r",
                    creds,
                    list(clientdict),
                )

                return creds, clientdict, session.session_id

        ret = self._auth_dict_for_flows(flows, session.session_id)
        ret["completed"] = list(creds)
        ret.update(errordict)
        raise InteractiveAuthIncompleteError(session.session_id, ret)

    async def add_oob_auth(
        self, stagetype: str, authdict: Dict[str, Any], clientip: str
    ) -> None:
        """
        Adds the result of out-of-band authentication into an existing auth
        session. Currently used for adding the result of fallback auth.

        Raises:
            LoginError if the stagetype is unknown or the session is missing.
            LoginError is raised by check_auth if authentication fails.
        """
        if stagetype not in self.checkers:
            raise LoginError(
                400, f"Unknown UIA stage type: {stagetype}", Codes.INVALID_PARAM
            )
        if "session" not in authdict:
            raise LoginError(400, "Missing session ID", Codes.MISSING_PARAM)

        # If authentication fails a LoginError is raised. Otherwise, store
        # the successful result.
        result = await self.checkers[stagetype].check_auth(authdict, clientip)
        await self.store.mark_ui_auth_stage_complete(
            authdict["session"], stagetype, result
        )

    def get_session_id(self, clientdict: Dict[str, Any]) -> Optional[str]:
        """
        Gets the session ID for a client given the client dictionary

        Args:
            clientdict: The dictionary sent by the client in the request

        Returns:
            The string session ID the client sent. If the client did
                not send a session ID, returns None.
        """
        sid = None
        if clientdict and "auth" in clientdict:
            authdict = clientdict["auth"]
            if "session" in authdict:
                sid = authdict["session"]
        return sid

    async def set_session_data(self, session_id: str, key: str, value: Any) -> None:
        """
        Store a key-value pair into the sessions data associated with this
        request. This data is stored server-side and cannot be modified by
        the client.

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key to store the data under. An entry from
                UIAuthSessionDataConstants.
            value: The data to store
        """
        try:
            await self.store.set_ui_auth_session_data(session_id, key, value)
        except StoreError:
            raise SynapseError(400, "Unknown session ID: %s" % (session_id,))

    async def get_session_data(
        self, session_id: str, key: str, default: Optional[Any] = None
    ) -> Any:
        """
        Retrieve data stored with set_session_data

        Args:
            session_id: The ID of this session as returned from check_auth
            key: The key the data was stored under. An entry from
                UIAuthSessionDataConstants.
            default: Value to return if the key has not been set
        """
        try:
            return await self.store.get_ui_auth_session_data(session_id, key, default)
        except StoreError:
            raise SynapseError(400, "Unknown session ID: %s" % (session_id,))

    async def _expire_old_sessions(self) -> None:
        """
        Invalidate any user interactive authentication sessions that have expired.
        """
        now = self._clock.time_msec()
        expiration_time = now - self.SESSION_EXPIRE_MS
        await self.store.delete_old_ui_auth_sessions(expiration_time)

    async def _check_auth_dict(
        self, authdict: Dict[str, Any], clientip: str
    ) -> Union[Dict[str, Any], str]:
        """Attempt to validate the auth dict provided by a client

        Args:
            authdict: auth dict provided by the client
            clientip: IP address of the client

        Returns:
            Result of the stage verification.

        Raises:
            StoreError if there was a problem accessing the database
            SynapseError if there was a problem with the request
            LoginError if there was an authentication problem.
        """
        login_type = authdict["type"]
        checker = self.checkers.get(login_type)
        if checker is not None:
            res = await checker.check_auth(authdict, clientip=clientip)
            return res

        # fall back to the v1 login flow
        canonical_id, _ = await self.validate_login(authdict, is_reauth=True)
        return canonical_id

    def _get_params_recaptcha(self) -> dict:
        return {"public_key": self.hs.config.captcha.recaptcha_public_key}

    def _get_params_terms(self) -> dict:
        return {
            "policies": {
                "privacy_policy": {
                    "version": self.hs.config.consent.user_consent_version,
                    "en": {
                        "name": self.hs.config.consent.user_consent_policy_name,
                        "url": "%s_matrix/consent?v=%s"
                        % (
                            self.hs.config.server.public_baseurl,
                            self.hs.config.consent.user_consent_version,
                        ),
                    },
                }
            }
        }

    def _auth_dict_for_flows(
        self,
        flows: List[List[str]],
        session_id: str,
    ) -> Dict[str, Any]:
        public_flows = []
        for f in flows:
            public_flows.append(f)

        get_params = {
            LoginType.RECAPTCHA: self._get_params_recaptcha,
            LoginType.TERMS: self._get_params_terms,
        }

        params: Dict[str, Any] = {}

        for f in public_flows:
            for stage in f:
                if stage in get_params and stage not in params:
                    params[stage] = get_params[stage]()

        return {
            "session": session_id,
            "flows": [{"stages": f} for f in public_flows],
            "params": params,
        }

    async def refresh_token(
        self,
        refresh_token: str,
        access_token_valid_until_ms: Optional[int],
        refresh_token_valid_until_ms: Optional[int],
    ) -> Tuple[str, str, Optional[int]]:
        """
        Consumes a refresh token and generate both a new access token and a new refresh token from it.

        The consumed refresh token is considered invalid after the first use of the new access token or the new refresh token.

        The lifetime of both the access token and refresh token will be capped so that they
        do not exceed the session's ultimate expiry time, if applicable.

        Args:
            refresh_token: The token to consume.
            access_token_valid_until_ms: The expiration timestamp of the new access token.
                None if the access token does not expire.
            refresh_token_valid_until_ms: The expiration timestamp of the new refresh token.
                None if the refresh token does not expire.
        Returns:
            A tuple containing:
              - the new access token
              - the new refresh token
              - the actual expiry time of the access token, which may be earlier than
                `access_token_valid_until_ms`.
        """

        # Verify the token signature first before looking up the token
        if not self._verify_refresh_token(refresh_token):
            raise SynapseError(
                HTTPStatus.UNAUTHORIZED, "invalid refresh token", Codes.UNKNOWN_TOKEN
            )

        existing_token = await self.store.lookup_refresh_token(refresh_token)
        if existing_token is None:
            raise SynapseError(
                HTTPStatus.UNAUTHORIZED,
                "refresh token does not exist",
                Codes.UNKNOWN_TOKEN,
            )

        if (
            existing_token.has_next_access_token_been_used
            or existing_token.has_next_refresh_token_been_refreshed
        ):
            raise SynapseError(
                HTTPStatus.FORBIDDEN,
                "refresh token isn't valid anymore",
                Codes.FORBIDDEN,
            )

        now_ms = self._clock.time_msec()

        if existing_token.expiry_ts is not None and existing_token.expiry_ts < now_ms:

            raise SynapseError(
                HTTPStatus.FORBIDDEN,
                "The supplied refresh token has expired",
                Codes.FORBIDDEN,
            )

        if existing_token.ultimate_session_expiry_ts is not None:
            # This session has a bounded lifetime, even across refreshes.

            if access_token_valid_until_ms is not None:
                access_token_valid_until_ms = min(
                    access_token_valid_until_ms,
                    existing_token.ultimate_session_expiry_ts,
                )
            else:
                access_token_valid_until_ms = existing_token.ultimate_session_expiry_ts

            if refresh_token_valid_until_ms is not None:
                refresh_token_valid_until_ms = min(
                    refresh_token_valid_until_ms,
                    existing_token.ultimate_session_expiry_ts,
                )
            else:
                refresh_token_valid_until_ms = existing_token.ultimate_session_expiry_ts
            if existing_token.ultimate_session_expiry_ts < now_ms:
                raise SynapseError(
                    HTTPStatus.FORBIDDEN,
                    "The session has expired and can no longer be refreshed",
                    Codes.FORBIDDEN,
                )

        (
            new_refresh_token,
            new_refresh_token_id,
        ) = await self.create_refresh_token_for_user_id(
            user_id=existing_token.user_id,
            device_id=existing_token.device_id,
            expiry_ts=refresh_token_valid_until_ms,
            ultimate_session_expiry_ts=existing_token.ultimate_session_expiry_ts,
        )
        access_token = await self.create_access_token_for_user_id(
            user_id=existing_token.user_id,
            device_id=existing_token.device_id,
            valid_until_ms=access_token_valid_until_ms,
            refresh_token_id=new_refresh_token_id,
        )
        await self.store.replace_refresh_token(
            existing_token.token_id, new_refresh_token_id
        )
        return access_token, new_refresh_token, access_token_valid_until_ms

    def _verify_refresh_token(self, token: str) -> bool:
        """
        Verifies the shape of a refresh token.

        Args:
            token: The refresh token to verify

        Returns:
            Whether the token has the right shape
        """
        parts = token.split("_", maxsplit=4)
        if len(parts) != 4:
            return False

        type, localpart, rand, crc = parts

        # Refresh tokens are prefixed by "syr_", let's check that
        if type != "syr":
            return False

        # Check the CRC
        base = f"{type}_{localpart}_{rand}"
        expected_crc = base62_encode(crc32(base.encode("ascii")), minwidth=6)
        if crc != expected_crc:
            return False

        return True

    async def create_refresh_token_for_user_id(
        self,
        user_id: str,
        device_id: str,
        expiry_ts: Optional[int],
        ultimate_session_expiry_ts: Optional[int],
    ) -> Tuple[str, int]:
        """
        Creates a new refresh token for the user with the given user ID.

        Args:
            user_id: canonical user ID
            device_id: the device ID to associate with the token.
            expiry_ts (milliseconds since the epoch): Time after which the
                refresh token cannot be used.
                If None, the refresh token never expires until it has been used.
            ultimate_session_expiry_ts (milliseconds since the epoch):
                Time at which the session will end and can not be extended any
                further.
                If None, the session can be refreshed indefinitely.

        Returns:
            The newly created refresh token and its ID in the database
        """
        refresh_token = self.generate_refresh_token(UserID.from_string(user_id))
        refresh_token_id = await self.store.add_refresh_token_to_user(
            user_id=user_id,
            token=refresh_token,
            device_id=device_id,
            expiry_ts=expiry_ts,
            ultimate_session_expiry_ts=ultimate_session_expiry_ts,
        )
        return refresh_token, refresh_token_id

    async def create_access_token_for_user_id(
        self,
        user_id: str,
        device_id: Optional[str],
        valid_until_ms: Optional[int],
        puppets_user_id: Optional[str] = None,
        is_appservice_ghost: bool = False,
        refresh_token_id: Optional[int] = None,
    ) -> str:
        """
        Creates a new access token for the user with the given user ID.

        The user is assumed to have been authenticated by some other
        mechanism (e.g. CAS), and the user_id converted to the canonical case.

        The device will be recorded in the table if it is not there already.

        Args:
            user_id: canonical User ID
            device_id: the device ID to associate with the tokens.
               None to leave the tokens unassociated with a device (deprecated:
               we should always have a device ID)
            valid_until_ms: when the token is valid until. None for
                no expiry.
            is_appservice_ghost: Whether the user is an application ghost user
            refresh_token_id: the refresh token ID that will be associated with
                this access token.
        Returns:
              The access token for the user's session.
        Raises:
            StoreError if there was a problem storing the token.
        """
        fmt_expiry = ""
        if valid_until_ms is not None:
            fmt_expiry = time.strftime(
                " until %Y-%m-%d %H:%M:%S", time.localtime(valid_until_ms / 1000.0)
            )

        if puppets_user_id:
            logger.info(
                "Logging in user %s as %s%s", user_id, puppets_user_id, fmt_expiry
            )
            target_user_id_obj = UserID.from_string(puppets_user_id)
        else:
            logger.info(
                "Logging in user %s on device %s%s", user_id, device_id, fmt_expiry
            )
            target_user_id_obj = UserID.from_string(user_id)

        if (
            not is_appservice_ghost
            or self.hs.config.appservice.track_appservice_user_ips
        ):
            await self.auth_blocking.check_auth_blocking(user_id)

        access_token = self.generate_access_token(target_user_id_obj)
        await self.store.add_access_token_to_user(
            user_id=user_id,
            token=access_token,
            device_id=device_id,
            valid_until_ms=valid_until_ms,
            puppets_user_id=puppets_user_id,
            refresh_token_id=refresh_token_id,
        )

        # the device *should* have been registered before we got here; however,
        # it's possible we raced against a DELETE operation. The thing we
        # really don't want is active access_tokens without a record of the
        # device, so we double-check it here.
        if device_id is not None:
            if await self.store.get_device(user_id, device_id) is None:
                await self.store.delete_access_token(access_token)
                raise StoreError(400, "Login raced against device deletion")

        return access_token

    async def check_user_exists(self, user_id: str) -> Optional[str]:
        """
        Checks to see if a user with the given id exists. Will check case
        insensitively, but return None if there are multiple inexact matches.

        Args:
            user_id: complete @user:id

        Returns:
            The canonical_user_id, or None if zero or multiple matches
        """
        res = await self._find_user_id_and_pwd_hash(user_id)
        if res is not None:
            return res[0]
        return None

    async def is_user_approved(self, user_id: str) -> bool:
        """Checks if a user is approved and therefore can be allowed to log in.

        Args:
            user_id: the user to check the approval status of.

        Returns:
            A boolean that is True if the user is approved, False otherwise.
        """
        return await self.store.is_user_approved(user_id)

    async def _find_user_id_and_pwd_hash(
        self, user_id: str
    ) -> Optional[Tuple[str, str]]:
        """Checks to see if a user with the given id exists. Will check case
        insensitively, but will return None if there are multiple inexact
        matches.

        Returns:
            A 2-tuple of `(canonical_user_id, password_hash)` or `None`
            if there is not exactly one match
        """
        user_infos = await self.store.get_users_by_id_case_insensitive(user_id)

        result = None
        if not user_infos:
            logger.warning("Attempted to login as %s but they do not exist", user_id)
        elif len(user_infos) == 1:
            # a single match (possibly not exact)
            result = user_infos.popitem()
        elif user_id in user_infos:
            # multiple matches, but one is exact
            result = (user_id, user_infos[user_id])
        else:
            # multiple matches, none of them exact
            logger.warning(
                "Attempted to login as %s but it matches more than one user "
                "inexactly: %r",
                user_id,
                user_infos.keys(),
            )
        return result

    def can_change_password(self) -> bool:
        """Get whether users on this server are allowed to change or set a password.

        Both `config.auth.password_enabled` and `config.auth.password_localdb_enabled` must be true.

        Note that any account (even SSO accounts) are allowed to add passwords if the above
        is true.

        Returns:
            Whether users on this server are allowed to change or set a password
        """
        return self._password_enabled_for_login and self._password_localdb_enabled

    def get_supported_login_types(self) -> Iterable[str]:
        """Get a the login types supported for the /login API

        By default this is just 'm.login.password' (unless password_enabled is
        False in the config file), but password auth providers can provide
        other login types.

        Returns:
            login types
        """
        # Load any login types registered by modules
        # This is stored in the password_auth_provider so this doesn't trigger
        # any callbacks
        types = list(self.password_auth_provider.get_supported_login_types().keys())

        # This list should include PASSWORD if (either _password_localdb_enabled is
        # true or if one of the modules registered it) AND _password_enabled is true
        # Also:
        # Some clients just pick the first type in the list. In this case, we want
        # them to use PASSWORD (rather than token or whatever), so we want to make sure
        # that comes first, where it's present.
        if LoginType.PASSWORD in types:
            types.remove(LoginType.PASSWORD)
            if self._password_enabled_for_login:
                types.insert(0, LoginType.PASSWORD)
        elif self._password_localdb_enabled and self._password_enabled_for_login:
            types.insert(0, LoginType.PASSWORD)

        return types

    async def validate_login(
        self,
        login_submission: Dict[str, Any],
        ratelimit: bool = False,
        is_reauth: bool = False,
    ) -> Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]:
        """Authenticates the user for the /login API

        Also used by the user-interactive auth flow to validate auth types which don't
        have an explicit UIA handler, including m.password.auth.

        Args:
            login_submission: the whole of the login submission
                (including 'type' and other relevant fields)
            ratelimit: whether to apply the failed_login_attempt ratelimiter
            is_reauth: whether this is part of a User-Interactive Authorisation
                flow to reauthenticate for a privileged action (rather than a
                new login)
        Returns:
            A tuple of the canonical user id, and optional callback
                to be called once the access token and device id are issued
        Raises:
            StoreError if there was a problem accessing the database
            SynapseError if there was a problem with the request
            LoginError if there was an authentication problem.
        """
        login_type = login_submission.get("type")
        if not isinstance(login_type, str):
            raise SynapseError(400, "Bad parameter: type", Codes.INVALID_PARAM)

        # ideally, we wouldn't be checking the identifier unless we know we have a login
        # method which uses it (https://github.com/matrix-org/synapse/issues/8836)
        #
        # But the auth providers' check_auth interface requires a username, so in
        # practice we can only support login methods which we can map to a username
        # anyway.

        # special case to check for "password" for the check_password interface
        # for the auth providers
        password = login_submission.get("password")

        if login_type == LoginType.PASSWORD:
            if is_reauth:
                passwords_allowed_here = self._password_enabled_for_reauth
            else:
                passwords_allowed_here = self._password_enabled_for_login

            if not passwords_allowed_here:
                raise SynapseError(400, "Password login has been disabled.")
            if not isinstance(password, str):
                raise SynapseError(400, "Bad parameter: password", Codes.INVALID_PARAM)

        # map old-school login fields into new-school "identifier" fields.
        identifier_dict = convert_client_dict_legacy_fields_to_identifier(
            login_submission
        )

        # convert phone type identifiers to generic threepids
        if identifier_dict["type"] == "m.id.phone":
            identifier_dict = login_id_phone_to_thirdparty(identifier_dict)

        # convert threepid identifiers to user IDs
        if identifier_dict["type"] == "m.id.thirdparty":
            address = identifier_dict.get("address")
            medium = identifier_dict.get("medium")

            if medium is None or address is None:
                raise SynapseError(400, "Invalid thirdparty identifier")

            # For emails, canonicalise the address.
            # We store all email addresses canonicalised in the DB.
            # (See add_threepid in synapse/handlers/auth.py)
            if medium == "email":
                try:
                    address = canonicalise_email(address)
                except ValueError as e:
                    raise SynapseError(400, str(e))

            # We also apply account rate limiting using the 3PID as a key, as
            # otherwise using 3PID bypasses the ratelimiting based on user ID.
            if ratelimit:
                await self._failed_login_attempts_ratelimiter.ratelimit(
                    None, (medium, address), update=False
                )

            # Check for login providers that support 3pid login types
            if login_type == LoginType.PASSWORD:
                # we've already checked that there is a (valid) password field
                assert isinstance(password, str)
                (
                    canonical_user_id,
                    callback_3pid,
                ) = await self.check_password_provider_3pid(medium, address, password)
                if canonical_user_id:
                    # Authentication through password provider and 3pid succeeded
                    return canonical_user_id, callback_3pid

            # No password providers were able to handle this 3pid
            # Check local store
            user_id = await self.hs.get_datastores().main.get_user_id_by_threepid(
                medium, address
            )
            if not user_id:
                logger.warning(
                    "unknown 3pid identifier medium %s, address %r", medium, address
                )
                # We mark that we've failed to log in here, as
                # `check_password_provider_3pid` might have returned `None` due
                # to an incorrect password, rather than the account not
                # existing.
                #
                # If it returned None but the 3PID was bound then we won't hit
                # this code path, which is fine as then the per-user ratelimit
                # will kick in below.
                if ratelimit:
                    await self._failed_login_attempts_ratelimiter.can_do_action(
                        None, (medium, address)
                    )
                raise LoginError(
                    403, msg=INVALID_USERNAME_OR_PASSWORD, errcode=Codes.FORBIDDEN
                )

            identifier_dict = {"type": "m.id.user", "user": user_id}

        # by this point, the identifier should be an m.id.user: if it's anything
        # else, we haven't understood it.
        if identifier_dict["type"] != "m.id.user":
            raise SynapseError(400, "Unknown login identifier type")

        username = identifier_dict.get("user")
        if not username:
            raise SynapseError(400, "User identifier is missing 'user' key")

        if username.startswith("@"):
            qualified_user_id = username
        else:
            qualified_user_id = UserID(username, self.hs.hostname).to_string()

        # Check if we've hit the failed ratelimit (but don't update it)
        if ratelimit:
            await self._failed_login_attempts_ratelimiter.ratelimit(
                None, qualified_user_id.lower(), update=False
            )

        try:
            return await self._validate_userid_login(username, login_submission)
        except LoginError:
            # The user has failed to log in, so we need to update the rate
            # limiter. Using `can_do_action` avoids us raising a ratelimit
            # exception and masking the LoginError. The actual ratelimiting
            # should have happened above.
            if ratelimit:
                await self._failed_login_attempts_ratelimiter.can_do_action(
                    None, qualified_user_id.lower()
                )
            raise

    async def _validate_userid_login(
        self,
        username: str,
        login_submission: Dict[str, Any],
    ) -> Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]:
        """Helper for validate_login

        Handles login, once we've mapped 3pids onto userids

        Args:
            username: the username, from the identifier dict
            login_submission: the whole of the login submission
                (including 'type' and other relevant fields)
        Returns:
            A tuple of the canonical user id, and optional callback
                to be called once the access token and device id are issued
        Raises:
            StoreError if there was a problem accessing the database
            SynapseError if there was a problem with the request
            LoginError if there was an authentication problem.
        """
        if username.startswith("@"):
            qualified_user_id = username
        else:
            qualified_user_id = UserID(username, self.hs.hostname).to_string()

        login_type = login_submission.get("type")
        # we already checked that we have a valid login type
        assert isinstance(login_type, str)

        known_login_type = False

        # Check if login_type matches a type registered by one of the modules
        # We don't need to remove LoginType.PASSWORD from the list if password login is
        # disabled, since if that were the case then by this point we know that the
        # login_type is not LoginType.PASSWORD
        supported_login_types = self.password_auth_provider.get_supported_login_types()
        # check if the login type being used is supported by a module
        if login_type in supported_login_types:
            # Make a note that this login type is supported by the server
            known_login_type = True
            # Get all the fields expected for this login types
            login_fields = supported_login_types[login_type]

            # go through the login submission and keep track of which required fields are
            # provided/not provided
            missing_fields = []
            login_dict = {}
            for f in login_fields:
                if f not in login_submission:
                    missing_fields.append(f)
                else:
                    login_dict[f] = login_submission[f]
            # raise an error if any of the expected fields for that login type weren't provided
            if missing_fields:
                raise SynapseError(
                    400,
                    "Missing parameters for login type %s: %s"
                    % (login_type, missing_fields),
                )

            # call all of the check_auth hooks for that login_type
            # it will return a result once the first success is found (or None otherwise)
            result = await self.password_auth_provider.check_auth(
                username, login_type, login_dict
            )
            if result:
                return result

        # if no module managed to authenticate the user, then fallback to built in password based auth
        if login_type == LoginType.PASSWORD and self._password_localdb_enabled:
            known_login_type = True

            # we've already checked that there is a (valid) password field
            password = login_submission["password"]
            assert isinstance(password, str)

            canonical_user_id = await self._check_local_password(
                qualified_user_id, password
            )

            if canonical_user_id:
                return canonical_user_id, None

        if not known_login_type:
            raise SynapseError(400, "Unknown login type %s" % login_type)

        # We raise a 403 here, but note that if we're doing user-interactive
        # login, it turns all LoginErrors into a 401 anyway.
        raise LoginError(403, msg=INVALID_USERNAME_OR_PASSWORD, errcode=Codes.FORBIDDEN)

    async def check_password_provider_3pid(
        self, medium: str, address: str, password: str
    ) -> Tuple[Optional[str], Optional[Callable[["LoginResponse"], Awaitable[None]]]]:
        """Check if a password provider is able to validate a thirdparty login

        Args:
            medium: The medium of the 3pid (ex. email).
            address: The address of the 3pid (ex. jdoe@example.com).
            password: The password of the user.

        Returns:
            A tuple of `(user_id, callback)`. If authentication is successful,
            `user_id`is the authenticated, canonical user ID. `callback` is
            then either a function to be later run after the server has
            completed login/registration, or `None`. If authentication was
            unsuccessful, `user_id` and `callback` are both `None`.
        """
        # call all of the check_3pid_auth callbacks
        # Result will be from the first callback that returns something other than None
        # If all the callbacks return None, then result is also set to None
        result = await self.password_auth_provider.check_3pid_auth(
            medium, address, password
        )
        if result:
            return result

        # if result is None then return (None, None)
        return None, None

    async def _check_local_password(self, user_id: str, password: str) -> Optional[str]:
        """Authenticate a user against the local password database.

        user_id is checked case insensitively, but will return None if there are
        multiple inexact matches.

        Args:
            user_id: complete @user:id
            password: the provided password
        Returns:
            The canonical_user_id, or None if unknown user/bad password
        """
        lookupres = await self._find_user_id_and_pwd_hash(user_id)
        if not lookupres:
            return None
        (user_id, password_hash) = lookupres

        # If the password hash is None, the account has likely been deactivated
        if not password_hash:
            deactivated = await self.store.get_user_deactivated_status(user_id)
            if deactivated:
                raise UserDeactivatedError("This account has been deactivated")

        result = await self.validate_hash(password, password_hash)
        if not result:
            logger.warning("Failed password login for user %s", user_id)
            return None
        return user_id

    def generate_access_token(self, for_user: UserID) -> str:
        """Generates an opaque string, for use as an access token"""

        # we use the following format for access tokens:
        #    syt_<base64 local part>_<random string>_<base62 crc check>

        b64local = unpaddedbase64.encode_base64(for_user.localpart.encode("utf-8"))
        random_string = stringutils.random_string(20)
        base = f"syt_{b64local}_{random_string}"

        crc = base62_encode(crc32(base.encode("ascii")), minwidth=6)
        return f"{base}_{crc}"

    def generate_refresh_token(self, for_user: UserID) -> str:
        """Generates an opaque string, for use as a refresh token"""

        # we use the following format for refresh tokens:
        #    syr_<base64 local part>_<random string>_<base62 crc check>

        b64local = unpaddedbase64.encode_base64(for_user.localpart.encode("utf-8"))
        random_string = stringutils.random_string(20)
        base = f"syr_{b64local}_{random_string}"

        crc = base62_encode(crc32(base.encode("ascii")), minwidth=6)
        return f"{base}_{crc}"

    async def validate_short_term_login_token(
        self, login_token: str
    ) -> LoginTokenAttributes:
        try:
            res = self.macaroon_gen.verify_short_term_login_token(login_token)
        except Exception:
            raise AuthError(403, "Invalid login token", errcode=Codes.FORBIDDEN)

        await self.auth_blocking.check_auth_blocking(res.user_id)
        return res

    async def delete_access_token(self, access_token: str) -> None:
        """Invalidate a single access token

        Args:
            access_token: access token to be deleted

        """
        token = await self.store.get_user_by_access_token(access_token)
        if not token:
            # At this point, the token should already have been fetched once by
            # the caller, so this should not happen, unless of a race condition
            # between two delete requests
            raise SynapseError(HTTPStatus.UNAUTHORIZED, "Unrecognised access token")
        await self.store.delete_access_token(access_token)

        # see if any modules want to know about this
        await self.password_auth_provider.on_logged_out(
            user_id=token.user_id,
            device_id=token.device_id,
            access_token=access_token,
        )

        # delete pushers associated with this access token
        if token.token_id is not None:
            await self.hs.get_pusherpool().remove_pushers_by_access_token(
                token.user_id, (token.token_id,)
            )

    async def delete_access_tokens_for_user(
        self,
        user_id: str,
        except_token_id: Optional[int] = None,
        device_id: Optional[str] = None,
    ) -> None:
        """Invalidate access tokens belonging to a user

        Args:
            user_id:  ID of user the tokens belong to
            except_token_id: access_token ID which should *not* be deleted
            device_id:  ID of device the tokens are associated with.
                If None, tokens associated with any device (or no device) will
                be deleted
        """
        tokens_and_devices = await self.store.user_delete_access_tokens(
            user_id, except_token_id=except_token_id, device_id=device_id
        )

        # see if any modules want to know about this
        for token, _, device_id in tokens_and_devices:
            await self.password_auth_provider.on_logged_out(
                user_id=user_id, device_id=device_id, access_token=token
            )

        # delete pushers associated with the access tokens
        await self.hs.get_pusherpool().remove_pushers_by_access_token(
            user_id, (token_id for _, token_id, _ in tokens_and_devices)
        )

    async def add_threepid(
        self, user_id: str, medium: str, address: str, validated_at: int
    ) -> None:
        # check if medium has a valid value
        if medium not in ["email", "msisdn"]:
            raise SynapseError(
                code=400,
                msg=("'%s' is not a valid value for 'medium'" % (medium,)),
                errcode=Codes.INVALID_PARAM,
            )

        # 'Canonicalise' email addresses down to lower case.
        # We've now moving towards the homeserver being the entity that
        # is responsible for validating threepids used for resetting passwords
        # on accounts, so in future Synapse will gain knowledge of specific
        # types (mediums) of threepid. For now, we still use the existing
        # infrastructure, but this is the start of synapse gaining knowledge
        # of specific types of threepid (and fixes the fact that checking
        # for the presence of an email address during password reset was
        # case sensitive).
        if medium == "email":
            address = canonicalise_email(address)

        await self.store.user_add_threepid(
            user_id, medium, address, validated_at, self.hs.get_clock().time_msec()
        )

        await self._third_party_rules.on_threepid_bind(user_id, medium, address)

    async def delete_threepid(
        self, user_id: str, medium: str, address: str, id_server: Optional[str] = None
    ) -> bool:
        """Attempts to unbind the 3pid on the identity servers and deletes it
        from the local database.

        Args:
            user_id: ID of user to remove the 3pid from.
            medium: The medium of the 3pid being removed: "email" or "msisdn".
            address: The 3pid address to remove.
            id_server: Use the given identity server when unbinding
                any threepids. If None then will attempt to unbind using the
                identity server specified when binding (if known).

        Returns:
            Returns True if successfully unbound the 3pid on
            the identity server, False if identity server doesn't support the
            unbind API.
        """

        # 'Canonicalise' email addresses as per above
        if medium == "email":
            address = canonicalise_email(address)

        identity_handler = self.hs.get_identity_handler()
        result = await identity_handler.try_unbind_threepid(
            user_id, {"medium": medium, "address": address, "id_server": id_server}
        )

        await self.store.user_delete_threepid(user_id, medium, address)
        if medium == "email":
            await self.store.delete_pusher_by_app_id_pushkey_user_id(
                app_id="m.email", pushkey=address, user_id=user_id
            )
        return result

    async def hash(self, password: str) -> str:
        """Computes a secure hash of password.

        Args:
            password: Password to hash.

        Returns:
            Hashed password.
        """

        def _do_hash() -> str:
            # Normalise the Unicode in the password
            pw = unicodedata.normalize("NFKC", password)

            return bcrypt.hashpw(
                pw.encode("utf8") + self.hs.config.auth.password_pepper.encode("utf8"),
                bcrypt.gensalt(self.bcrypt_rounds),
            ).decode("ascii")

        return await defer_to_thread(self.hs.get_reactor(), _do_hash)

    async def validate_hash(
        self, password: str, stored_hash: Union[bytes, str]
    ) -> bool:
        """Validates that self.hash(password) == stored_hash.

        Args:
            password: Password to hash.
            stored_hash: Expected hash value.

        Returns:
            Whether self.hash(password) == stored_hash.
        """

        def _do_validate_hash(checked_hash: bytes) -> bool:
            # Normalise the Unicode in the password
            pw = unicodedata.normalize("NFKC", password)

            return bcrypt.checkpw(
                pw.encode("utf8") + self.hs.config.auth.password_pepper.encode("utf8"),
                checked_hash,
            )

        if stored_hash:
            if not isinstance(stored_hash, bytes):
                stored_hash = stored_hash.encode("ascii")

            return await defer_to_thread(
                self.hs.get_reactor(), _do_validate_hash, stored_hash
            )
        else:
            return False

    async def start_sso_ui_auth(self, request: SynapseRequest, session_id: str) -> str:
        """
        Get the HTML for the SSO redirect confirmation page.

        Args:
            request: The incoming HTTP request
            session_id: The user interactive authentication session ID.

        Returns:
            The HTML to render.
        """
        try:
            session = await self.store.get_ui_auth_session(session_id)
        except StoreError:
            raise SynapseError(400, "Unknown session ID: %s" % (session_id,))

        user_id_to_verify: str = await self.get_session_data(
            session_id, UIAuthSessionDataConstants.REQUEST_USER_ID
        )

        idps = await self.hs.get_sso_handler().get_identity_providers_for_user(
            user_id_to_verify
        )

        if not idps:
            # we checked that the user had some remote identities before offering an SSO
            # flow, so either it's been deleted or the client has requested SSO despite
            # it not being offered.
            raise SynapseError(400, "User has no SSO identities")

        # for now, just pick one
        idp_id, sso_auth_provider = next(iter(idps.items()))
        if len(idps) > 0:
            logger.warning(
                "User %r has previously logged in with multiple SSO IdPs; arbitrarily "
                "picking %r",
                user_id_to_verify,
                idp_id,
            )

        redirect_url = await sso_auth_provider.handle_redirect_request(
            request, None, session_id
        )

        return self._sso_auth_confirm_template.render(
            description=session.description,
            redirect_url=redirect_url,
            idp=sso_auth_provider,
        )

    async def complete_sso_login(
        self,
        registered_user_id: str,
        auth_provider_id: str,
        request: Request,
        client_redirect_url: str,
        extra_attributes: Optional[JsonDict] = None,
        new_user: bool = False,
        auth_provider_session_id: Optional[str] = None,
    ) -> None:
        """Having figured out a mxid for this user, complete the HTTP request

        Args:
            registered_user_id: The registered user ID to complete SSO login for.
            auth_provider_id: The id of the SSO Identity provider that was used for
                login. This will be stored in the login token for future tracking in
                prometheus metrics.
            request: The request to complete.
            client_redirect_url: The URL to which to redirect the user at the end of the
                process.
            extra_attributes: Extra attributes which will be passed to the client
                during successful login. Must be JSON serializable.
            new_user: True if we should use wording appropriate to a user who has just
                registered.
            auth_provider_session_id: The session ID from the SSO IdP received during login.
        """
        # If the account has been deactivated, do not proceed with the login
        # flow.
        deactivated = await self.store.get_user_deactivated_status(registered_user_id)
        if deactivated:
            respond_with_html(request, 403, self._sso_account_deactivated_template)
            return

        user_profile_data = await self.store.get_profileinfo(
            UserID.from_string(registered_user_id).localpart
        )

        # Store any extra attributes which will be passed in the login response.
        # Note that this is per-user so it may overwrite a previous value, this
        # is considered OK since the newest SSO attributes should be most valid.
        if extra_attributes:
            self._extra_attributes[registered_user_id] = SsoLoginExtraAttributes(
                self._clock.time_msec(),
                extra_attributes,
            )

        # Create a login token
        login_token = self.macaroon_gen.generate_short_term_login_token(
            registered_user_id,
            auth_provider_id=auth_provider_id,
            auth_provider_session_id=auth_provider_session_id,
        )

        # Append the login token to the original redirect URL (i.e. with its query
        # parameters kept intact) to build the URL to which the template needs to
        # redirect the users once they have clicked on the confirmation link.
        redirect_url = self.add_query_param_to_url(
            client_redirect_url, "loginToken", login_token
        )

        # if the client is whitelisted, we can redirect straight to it
        if client_redirect_url.startswith(self._whitelisted_sso_clients):
            request.redirect(redirect_url)
            finish_request(request)
            return

        # Otherwise, serve the redirect confirmation page.

        # Remove the query parameters from the redirect URL to get a shorter version of
        # it. This is only to display a human-readable URL in the template, but not the
        # URL we redirect users to.
        url_parts = urllib.parse.urlsplit(client_redirect_url)

        if url_parts.scheme == "https":
            # for an https uri, just show the netloc (ie, the hostname. Specifically,
            # the bit between "//" and "/"; this includes any potential
            # "username:password@" prefix.)
            display_url = url_parts.netloc
        else:
            # for other uris, strip the query-params (including the login token) and
            # fragment.
            display_url = urllib.parse.urlunsplit(
                (url_parts.scheme, url_parts.netloc, url_parts.path, "", "")
            )

        html = self._sso_redirect_confirm_template.render(
            display_url=display_url,
            redirect_url=redirect_url,
            server_name=self._server_name,
            new_user=new_user,
            user_id=registered_user_id,
            user_profile=user_profile_data,
        )
        respond_with_html(request, 200, html)

    async def _sso_login_callback(self, login_result: "LoginResponse") -> None:
        """
        A login callback which might add additional attributes to the login response.

        Args:
            login_result: The data to be sent to the client. Includes the user
                ID and access token.
        """
        # Expire attributes before processing. Note that there shouldn't be any
        # valid logins that still have extra attributes.
        self._expire_sso_extra_attributes()

        extra_attributes = self._extra_attributes.get(login_result["user_id"])
        if extra_attributes:
            login_result_dict = cast(Dict[str, Any], login_result)
            login_result_dict.update(extra_attributes.extra_attributes)

    def _expire_sso_extra_attributes(self) -> None:
        """
        Iterate through the mapping of user IDs to extra attributes and remove any that are no longer valid.
        """
        # TODO This should match the amount of time the macaroon is valid for.
        LOGIN_TOKEN_EXPIRATION_TIME = 2 * 60 * 1000
        expire_before = self._clock.time_msec() - LOGIN_TOKEN_EXPIRATION_TIME
        to_expire = set()
        for user_id, data in self._extra_attributes.items():
            if data.creation_time < expire_before:
                to_expire.add(user_id)
        for user_id in to_expire:
            logger.debug("Expiring extra attributes for user %s", user_id)
            del self._extra_attributes[user_id]

    @staticmethod
    def add_query_param_to_url(url: str, param_name: str, param: Any) -> str:
        url_parts = list(urllib.parse.urlparse(url))
        query = urllib.parse.parse_qsl(url_parts[4], keep_blank_values=True)
        query.append((param_name, param))
        url_parts[4] = urllib.parse.urlencode(query)
        return urllib.parse.urlunparse(url_parts)


def load_legacy_password_auth_providers(hs: "HomeServer") -> None:
    module_api = hs.get_module_api()
    for module, config in hs.config.authproviders.password_providers:
        load_single_legacy_password_auth_provider(
            module=module, config=config, api=module_api
        )


def load_single_legacy_password_auth_provider(
    module: Type,
    config: JsonDict,
    api: "ModuleApi",
) -> None:
    try:
        provider = module(config=config, account_handler=api)
    except Exception as e:
        logger.error("Error while initializing %r: %s", module, e)
        raise

    # All methods that the module provides should be async, but this wasn't enforced
    # in the old module system, so we wrap them if needed
    def async_wrapper(f: Optional[Callable]) -> Optional[Callable[..., Awaitable]]:
        # f might be None if the callback isn't implemented by the module. In this
        # case we don't want to register a callback at all so we return None.
        if f is None:
            return None

        # We need to wrap check_password because its old form would return a boolean
        # but we now want it to behave just like check_auth() and return the matrix id of
        # the user if authentication succeeded or None otherwise
        if f.__name__ == "check_password":

            async def wrapped_check_password(
                username: str, login_type: str, login_dict: JsonDict
            ) -> Optional[Tuple[str, Optional[Callable]]]:
                # We've already made sure f is not None above, but mypy doesn't do well
                # across function boundaries so we need to tell it f is definitely not
                # None.
                assert f is not None

                matrix_user_id = api.get_qualified_user_id(username)
                password = login_dict["password"]

                is_valid = await f(matrix_user_id, password)

                if is_valid:
                    return matrix_user_id, None

                return None

            return wrapped_check_password

        # We need to wrap check_auth as in the old form it could return
        # just a str, but now it must return Optional[Tuple[str, Optional[Callable]]
        if f.__name__ == "check_auth":

            async def wrapped_check_auth(
                username: str, login_type: str, login_dict: JsonDict
            ) -> Optional[Tuple[str, Optional[Callable]]]:
                # We've already made sure f is not None above, but mypy doesn't do well
                # across function boundaries so we need to tell it f is definitely not
                # None.
                assert f is not None

                result = await f(username, login_type, login_dict)

                if isinstance(result, str):
                    return result, None

                return result

            return wrapped_check_auth

        # We need to wrap check_3pid_auth as in the old form it could return
        # just a str, but now it must return Optional[Tuple[str, Optional[Callable]]
        if f.__name__ == "check_3pid_auth":

            async def wrapped_check_3pid_auth(
                medium: str, address: str, password: str
            ) -> Optional[Tuple[str, Optional[Callable]]]:
                # We've already made sure f is not None above, but mypy doesn't do well
                # across function boundaries so we need to tell it f is definitely not
                # None.
                assert f is not None

                result = await f(medium, address, password)

                if isinstance(result, str):
                    return result, None

                return result

            return wrapped_check_3pid_auth

        def run(*args: Tuple, **kwargs: Dict) -> Awaitable:
            # mypy doesn't do well across function boundaries so we need to tell it
            # f is definitely not None.
            assert f is not None

            return maybe_awaitable(f(*args, **kwargs))

        return run

    # If the module has these methods implemented, then we pull them out
    # and register them as hooks.
    check_3pid_auth_hook: Optional[CHECK_3PID_AUTH_CALLBACK] = async_wrapper(
        getattr(provider, "check_3pid_auth", None)
    )
    on_logged_out_hook: Optional[ON_LOGGED_OUT_CALLBACK] = async_wrapper(
        getattr(provider, "on_logged_out", None)
    )

    supported_login_types = {}
    # call get_supported_login_types and add that to the dict
    g = getattr(provider, "get_supported_login_types", None)
    if g is not None:
        # Note the old module style also called get_supported_login_types at loading time
        # and it is synchronous
        supported_login_types.update(g())

    auth_checkers = {}
    # Legacy modules have a check_auth method which expects to be called with one of
    # the keys returned by get_supported_login_types. New style modules register a
    # dictionary of login_type->check_auth_method mappings
    check_auth = async_wrapper(getattr(provider, "check_auth", None))
    if check_auth is not None:
        for login_type, fields in supported_login_types.items():
            # need tuple(fields) since fields can be any Iterable type (so may not be hashable)
            auth_checkers[(login_type, tuple(fields))] = check_auth

    # if it has a "check_password" method then it should handle all auth checks
    # with login type of LoginType.PASSWORD
    check_password = async_wrapper(getattr(provider, "check_password", None))
    if check_password is not None:
        # need to use a tuple here for ("password",) not a list since lists aren't hashable
        auth_checkers[(LoginType.PASSWORD, ("password",))] = check_password

    api.register_password_auth_provider_callbacks(
        check_3pid_auth=check_3pid_auth_hook,
        on_logged_out=on_logged_out_hook,
        auth_checkers=auth_checkers,
    )


CHECK_3PID_AUTH_CALLBACK = Callable[
    [str, str, str],
    Awaitable[
        Optional[Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]]
    ],
]
ON_LOGGED_OUT_CALLBACK = Callable[[str, Optional[str], str], Awaitable]
CHECK_AUTH_CALLBACK = Callable[
    [str, str, JsonDict],
    Awaitable[
        Optional[Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]]
    ],
]
GET_USERNAME_FOR_REGISTRATION_CALLBACK = Callable[
    [JsonDict, JsonDict],
    Awaitable[Optional[str]],
]
GET_DISPLAYNAME_FOR_REGISTRATION_CALLBACK = Callable[
    [JsonDict, JsonDict],
    Awaitable[Optional[str]],
]
IS_3PID_ALLOWED_CALLBACK = Callable[[str, str, bool], Awaitable[bool]]


class PasswordAuthProvider:
    """
    A class that the AuthHandler calls when authenticating users
    It allows modules to provide alternative methods for authentication
    """

    def __init__(self) -> None:
        # lists of callbacks
        self.check_3pid_auth_callbacks: List[CHECK_3PID_AUTH_CALLBACK] = []
        self.on_logged_out_callbacks: List[ON_LOGGED_OUT_CALLBACK] = []
        self.get_username_for_registration_callbacks: List[
            GET_USERNAME_FOR_REGISTRATION_CALLBACK
        ] = []
        self.get_displayname_for_registration_callbacks: List[
            GET_DISPLAYNAME_FOR_REGISTRATION_CALLBACK
        ] = []
        self.is_3pid_allowed_callbacks: List[IS_3PID_ALLOWED_CALLBACK] = []

        # Mapping from login type to login parameters
        self._supported_login_types: Dict[str, Iterable[str]] = {}

        # Mapping from login type to auth checker callbacks
        self.auth_checker_callbacks: Dict[str, List[CHECK_AUTH_CALLBACK]] = {}

    def register_password_auth_provider_callbacks(
        self,
        check_3pid_auth: Optional[CHECK_3PID_AUTH_CALLBACK] = None,
        on_logged_out: Optional[ON_LOGGED_OUT_CALLBACK] = None,
        is_3pid_allowed: Optional[IS_3PID_ALLOWED_CALLBACK] = None,
        auth_checkers: Optional[
            Dict[Tuple[str, Tuple[str, ...]], CHECK_AUTH_CALLBACK]
        ] = None,
        get_username_for_registration: Optional[
            GET_USERNAME_FOR_REGISTRATION_CALLBACK
        ] = None,
        get_displayname_for_registration: Optional[
            GET_DISPLAYNAME_FOR_REGISTRATION_CALLBACK
        ] = None,
    ) -> None:
        # Register check_3pid_auth callback
        if check_3pid_auth is not None:
            self.check_3pid_auth_callbacks.append(check_3pid_auth)

        # register on_logged_out callback
        if on_logged_out is not None:
            self.on_logged_out_callbacks.append(on_logged_out)

        if auth_checkers is not None:
            # register a new supported login_type
            # Iterate through all of the types being registered
            for (login_type, fields), callback in auth_checkers.items():
                # Note: fields may be empty here. This would allow a modules auth checker to
                # be called with just 'login_type' and no password or other secrets

                # Need to check that all the field names are strings or may get nasty errors later
                for f in fields:
                    if not isinstance(f, str):
                        raise RuntimeError(
                            "A module tried to register support for login type: %s with parameters %s"
                            " but all parameter names must be strings"
                            % (login_type, fields)
                        )

                # 2 modules supporting the same login type must expect the same fields
                # e.g. 1 can't expect "pass" if the other expects "password"
                # so throw an exception if that happens
                if login_type not in self._supported_login_types.get(login_type, []):
                    self._supported_login_types[login_type] = fields
                else:
                    fields_currently_supported = self._supported_login_types.get(
                        login_type
                    )
                    if fields_currently_supported != fields:
                        raise RuntimeError(
                            "A module tried to register support for login type: %s with parameters %s"
                            " but another module had already registered support for that type with parameters %s"
                            % (login_type, fields, fields_currently_supported)
                        )

                # Add the new method to the list of auth_checker_callbacks for this login type
                self.auth_checker_callbacks.setdefault(login_type, []).append(callback)

        if get_username_for_registration is not None:
            self.get_username_for_registration_callbacks.append(
                get_username_for_registration,
            )

        if get_displayname_for_registration is not None:
            self.get_displayname_for_registration_callbacks.append(
                get_displayname_for_registration,
            )

        if is_3pid_allowed is not None:
            self.is_3pid_allowed_callbacks.append(is_3pid_allowed)

    def get_supported_login_types(self) -> Mapping[str, Iterable[str]]:
        """Get the login types supported by this password provider

        Returns a map from a login type identifier (such as m.login.password) to an
        iterable giving the fields which must be provided by the user in the submission
        to the /login API.
        """

        return self._supported_login_types

    async def check_auth(
        self, username: str, login_type: str, login_dict: JsonDict
    ) -> Optional[Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]]:
        """Check if the user has presented valid login credentials

        Args:
            username: user id presented by the client. Either an MXID or an unqualified
                username.

            login_type: the login type being attempted - one of the types returned by
                get_supported_login_types()

            login_dict: the dictionary of login secrets passed by the client.

        Returns: (user_id, callback) where `user_id` is the fully-qualified mxid of the
            user, and `callback` is an optional callback which will be called with the
            result from the /login call (including access_token, device_id, etc.)
        """

        # Go through all callbacks for the login type until one returns with a value
        # other than None (i.e. until a callback returns a success)
        for callback in self.auth_checker_callbacks[login_type]:
            try:
                result = await delay_cancellation(
                    callback(username, login_type, login_dict)
                )
            except CancelledError:
                raise
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)
                continue

            if result is not None:
                # Check that the callback returned a Tuple[str, Optional[Callable]]
                # "type: ignore[unreachable]" is used after some isinstance checks because mypy thinks
                # result is always the right type, but as it is 3rd party code it might not be

                if not isinstance(result, tuple) or len(result) != 2:
                    logger.warning(
                        "Wrong type returned by module API callback %s: %s, expected"
                        " Optional[Tuple[str, Optional[Callable]]]",
                        callback,
                        result,
                    )
                    continue

                # pull out the two parts of the tuple so we can do type checking
                str_result, callback_result = result

                # the 1st item in the tuple should be a str
                if not isinstance(str_result, str):
                    logger.warning(  # type: ignore[unreachable]
                        "Wrong type returned by module API callback %s: %s, expected"
                        " Optional[Tuple[str, Optional[Callable]]]",
                        callback,
                        result,
                    )
                    continue

                # the second should be Optional[Callable]
                if callback_result is not None:
                    if not callable(callback_result):
                        logger.warning(  # type: ignore[unreachable]
                            "Wrong type returned by module API callback %s: %s, expected"
                            " Optional[Tuple[str, Optional[Callable]]]",
                            callback,
                            result,
                        )
                        continue

                # The result is a (str, Optional[callback]) tuple so return the successful result
                return result

        # If this point has been reached then none of the callbacks successfully authenticated
        # the user so return None
        return None

    async def check_3pid_auth(
        self, medium: str, address: str, password: str
    ) -> Optional[Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]]:
        # This function is able to return a deferred that either
        # resolves None, meaning authentication failure, or upon
        # success, to a str (which is the user_id) or a tuple of
        # (user_id, callback_func), where callback_func should be run
        # after we've finished everything else

        for callback in self.check_3pid_auth_callbacks:
            try:
                result = await delay_cancellation(callback(medium, address, password))
            except CancelledError:
                raise
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)
                continue

            if result is not None:
                # Check that the callback returned a Tuple[str, Optional[Callable]]
                # "type: ignore[unreachable]" is used after some isinstance checks because mypy thinks
                # result is always the right type, but as it is 3rd party code it might not be

                if not isinstance(result, tuple) or len(result) != 2:
                    logger.warning(
                        "Wrong type returned by module API callback %s: %s, expected"
                        " Optional[Tuple[str, Optional[Callable]]]",
                        callback,
                        result,
                    )
                    continue

                # pull out the two parts of the tuple so we can do type checking
                str_result, callback_result = result

                # the 1st item in the tuple should be a str
                if not isinstance(str_result, str):
                    logger.warning(  # type: ignore[unreachable]
                        "Wrong type returned by module API callback %s: %s, expected"
                        " Optional[Tuple[str, Optional[Callable]]]",
                        callback,
                        result,
                    )
                    continue

                # the second should be Optional[Callable]
                if callback_result is not None:
                    if not callable(callback_result):
                        logger.warning(  # type: ignore[unreachable]
                            "Wrong type returned by module API callback %s: %s, expected"
                            " Optional[Tuple[str, Optional[Callable]]]",
                            callback,
                            result,
                        )
                        continue

                # The result is a (str, Optional[callback]) tuple so return the successful result
                return result

        # If this point has been reached then none of the callbacks successfully authenticated
        # the user so return None
        return None

    async def on_logged_out(
        self, user_id: str, device_id: Optional[str], access_token: str
    ) -> None:

        # call all of the on_logged_out callbacks
        for callback in self.on_logged_out_callbacks:
            try:
                await callback(user_id, device_id, access_token)
            except Exception as e:
                logger.warning("Failed to run module API callback %s: %s", callback, e)
                continue

    async def get_username_for_registration(
        self,
        uia_results: JsonDict,
        params: JsonDict,
    ) -> Optional[str]:
        """Defines the username to use when registering the user, using the credentials
        and parameters provided during the UIA flow.

        Stops at the first callback that returns a string.

        Args:
            uia_results: The credentials provided during the UIA flow.
            params: The parameters provided by the registration request.

        Returns:
            The localpart to use when registering this user, or None if no module
            returned a localpart.
        """
        for callback in self.get_username_for_registration_callbacks:
            try:
                res = await delay_cancellation(callback(uia_results, params))

                if isinstance(res, str):
                    return res
                elif res is not None:
                    # mypy complains that this line is unreachable because it assumes the
                    # data returned by the module fits the expected type. We just want
                    # to make sure this is the case.
                    logger.warning(  # type: ignore[unreachable]
                        "Ignoring non-string value returned by"
                        " get_username_for_registration callback %s: %s",
                        callback,
                        res,
                    )
            except CancelledError:
                raise
            except Exception as e:
                logger.error(
                    "Module raised an exception in get_username_for_registration: %s",
                    e,
                )
                raise SynapseError(code=500, msg="Internal Server Error")

        return None

    async def get_displayname_for_registration(
        self,
        uia_results: JsonDict,
        params: JsonDict,
    ) -> Optional[str]:
        """Defines the display name to use when registering the user, using the
        credentials and parameters provided during the UIA flow.

        Stops at the first callback that returns a tuple containing at least one string.

        Args:
            uia_results: The credentials provided during the UIA flow.
            params: The parameters provided by the registration request.

        Returns:
            A tuple which first element is the display name, and the second is an MXC URL
            to the user's avatar.
        """
        for callback in self.get_displayname_for_registration_callbacks:
            try:
                res = await delay_cancellation(callback(uia_results, params))

                if isinstance(res, str):
                    return res
                elif res is not None:
                    # mypy complains that this line is unreachable because it assumes the
                    # data returned by the module fits the expected type. We just want
                    # to make sure this is the case.
                    logger.warning(  # type: ignore[unreachable]
                        "Ignoring non-string value returned by"
                        " get_displayname_for_registration callback %s: %s",
                        callback,
                        res,
                    )
            except CancelledError:
                raise
            except Exception as e:
                logger.error(
                    "Module raised an exception in get_displayname_for_registration: %s",
                    e,
                )
                raise SynapseError(code=500, msg="Internal Server Error")

        return None

    async def is_3pid_allowed(
        self,
        medium: str,
        address: str,
        registration: bool,
    ) -> bool:
        """Check if the user can be allowed to bind a 3PID on this homeserver.

        Args:
            medium: The medium of the 3PID.
            address: The address of the 3PID.
            registration: Whether the 3PID is being bound when registering a new user.

        Returns:
            Whether the 3PID is allowed to be bound on this homeserver
        """
        for callback in self.is_3pid_allowed_callbacks:
            try:
                res = await delay_cancellation(callback(medium, address, registration))

                if res is False:
                    return res
                elif not isinstance(res, bool):
                    # mypy complains that this line is unreachable because it assumes the
                    # data returned by the module fits the expected type. We just want
                    # to make sure this is the case.
                    logger.warning(  # type: ignore[unreachable]
                        "Ignoring non-string value returned by"
                        " is_3pid_allowed callback %s: %s",
                        callback,
                        res,
                    )
            except CancelledError:
                raise
            except Exception as e:
                logger.error("Module raised an exception in is_3pid_allowed: %s", e)
                raise SynapseError(code=500, msg="Internal Server Error")

        return True
