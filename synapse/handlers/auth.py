# -*- coding: utf-8 -*-
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
    Union,
)

import attr
import bcrypt
import pymacaroons

from twisted.web.http import Request

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
from synapse.handlers._base import BaseHandler
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
from synapse.module_api import ModuleApi
from synapse.storage.roommember import ProfileInfo
from synapse.types import JsonDict, Requester, UserID
from synapse.util import stringutils as stringutils
from synapse.util.async_helpers import maybe_awaitable
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.threepids import canonicalise_email

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


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
            400, "'identifier' dict has no key 'type'", errcode=Codes.MISSING_PARAM,
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


@attr.s(slots=True)
class SsoLoginExtraAttributes:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time = attr.ib(type=int)
    extra_attributes = attr.ib(type=JsonDict)


class AuthHandler(BaseHandler):
    SESSION_EXPIRE_MS = 48 * 60 * 60 * 1000

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.checkers = {}  # type: Dict[str, UserInteractiveAuthChecker]
        for auth_checker_class in INTERACTIVE_AUTH_CHECKERS:
            inst = auth_checker_class(hs)
            if inst.is_enabled():
                self.checkers[inst.AUTH_TYPE] = inst  # type: ignore

        self.bcrypt_rounds = hs.config.bcrypt_rounds

        # we can't use hs.get_module_api() here, because to do so will create an
        # import loop.
        #
        # TODO: refactor this class to separate the lower-level stuff that
        #   ModuleApi can use from the higher-level stuff that uses ModuleApi, as
        #   better way to break the loop
        account_handler = ModuleApi(hs, self)

        self.password_providers = [
            PasswordProvider.load(module, config, account_handler)
            for module, config in hs.config.password_providers
        ]

        logger.info("Extra password_providers: %s", self.password_providers)

        self.hs = hs  # FIXME better possibility to access registrationHandler later?
        self.macaroon_gen = hs.get_macaroon_generator()
        self._password_enabled = hs.config.password_enabled
        self._password_localdb_enabled = hs.config.password_localdb_enabled

        # start out by assuming PASSWORD is enabled; we will remove it later if not.
        login_types = set()
        if self._password_localdb_enabled:
            login_types.add(LoginType.PASSWORD)

        for provider in self.password_providers:
            login_types.update(provider.get_supported_login_types().keys())

        if not self._password_enabled:
            login_types.discard(LoginType.PASSWORD)

        # Some clients just pick the first type in the list. In this case, we want
        # them to use PASSWORD (rather than token or whatever), so we want to make sure
        # that comes first, where it's present.
        self._supported_login_types = []
        if LoginType.PASSWORD in login_types:
            self._supported_login_types.append(LoginType.PASSWORD)
            login_types.remove(LoginType.PASSWORD)
        self._supported_login_types.extend(login_types)

        # Ratelimiter for failed auth during UIA. Uses same ratelimit config
        # as per `rc_login.failed_attempts`.
        self._failed_uia_attempts_ratelimiter = Ratelimiter(
            clock=self.clock,
            rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
            burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
        )

        # The number of seconds to keep a UI auth session active.
        self._ui_auth_session_timeout = hs.config.ui_auth_session_timeout

        # Ratelimitier for failed /login attempts
        self._failed_login_attempts_ratelimiter = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
            burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
        )

        self._clock = self.hs.get_clock()

        # Expire old UI auth sessions after a period of time.
        if hs.config.run_background_tasks:
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
        self._sso_redirect_confirm_template = hs.config.sso_redirect_confirm_template

        # The following template is shown during user interactive authentication
        # in the fallback auth scenario. It notifies the user that they are
        # authenticating for an operation to occur on their account.
        self._sso_auth_confirm_template = hs.config.sso_auth_confirm_template

        # The following template is shown during the SSO authentication process if
        # the account is deactivated.
        self._sso_account_deactivated_template = (
            hs.config.sso_account_deactivated_template
        )

        self._server_name = hs.config.server_name

        # cast to tuple for use with str.startswith
        self._whitelisted_sso_clients = tuple(hs.config.sso_client_whitelist)

        # A mapping of user ID to extra attributes to include in the login
        # response.
        self._extra_attributes = {}  # type: Dict[str, SsoLoginExtraAttributes]

    async def validate_user_via_ui_auth(
        self,
        requester: Requester,
        request: SynapseRequest,
        request_body: Dict[str, Any],
        description: str,
    ) -> Tuple[dict, Optional[str]]:
        """
        Checks that the user is who they claim to be, via a UI auth.

        This is used for things like device deletion and password reset where
        the user already has a valid access token, but we want to double-check
        that it isn't stolen by re-authenticating them.

        Args:
            requester: The user, as given by the access token

            request: The request sent by the client.

            request_body: The body of the request sent by the client

            description: A human readable string to be displayed to the user that
                         describes the operation happening on their account.

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

        if self._ui_auth_session_timeout:
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
        self._failed_uia_attempts_ratelimiter.ratelimit(requester_user_id, update=False)

        # build a list of supported flows
        supported_ui_auth_types = await self._get_available_ui_auth_types(
            requester.user
        )
        flows = [[login_type] for login_type in supported_ui_auth_types]

        def get_new_session_data() -> JsonDict:
            return {UIAuthSessionDataConstants.REQUEST_USER_ID: requester_user_id}

        try:
            result, params, session_id = await self.check_ui_auth(
                flows, request, request_body, description, get_new_session_data,
            )
        except LoginError:
            # Update the ratelimiter to say we failed (`can_do_action` doesn't raise).
            self._failed_uia_attempts_ratelimiter.can_do_action(requester_user_id)
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
        """Get a list of the authentication types this user can use
        """

        ui_auth_types = set()

        # if the HS supports password auth, and the user has a non-null password, we
        # support password auth
        if self._password_localdb_enabled and self._password_enabled:
            lookupres = await self._find_user_id_and_pwd_hash(user.to_string())
            if lookupres:
                _, password_hash = lookupres
                if password_hash:
                    ui_auth_types.add(LoginType.PASSWORD)

        # also allow auth from password providers
        for provider in self.password_providers:
            for t in provider.get_supported_login_types().keys():
                if t == LoginType.PASSWORD and not self._password_enabled:
                    continue
                ui_auth_types.add(t)

        # if sso is enabled, allow the user to log in via SSO iff they have a mapping
        # from sso to mxid.
        if await self.hs.get_sso_handler().get_identity_providers_for_user(
            user.to_string()
        ):
            ui_auth_types.add(LoginType.SSO)

        return ui_auth_types

    def get_enabled_auth_types(self):
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
        synapse.rest.client.v2_alpha._base.interactive_auth_handler as a
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

        sid = None  # type: Optional[str]
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
            # synapse.rest.client.v2_alpha.register.RegisterRestServlet.on_POST
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
        clientip = request.getClientIP()

        await self.store.add_user_agent_ip_to_ui_auth_session(
            session.session_id, user_agent, clientip
        )

        if not authdict:
            raise InteractiveAuthIncompleteError(
                session.session_id, self._auth_dict_for_flows(flows, session.session_id)
            )

        # check auth type currently being presented
        errordict = {}  # type: Dict[str, Any]
        if "type" in authdict:
            login_type = authdict["type"]  # type: str
            try:
                result = await self._check_auth_dict(authdict, clientip)
                if result:
                    await self.store.mark_ui_auth_stage_complete(
                        session.session_id, login_type, result
                    )
            except LoginError as e:
                # this step failed. Merge the error dict into the response
                # so that the client can have another go.
                errordict = e.error_dict()

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
    ) -> bool:
        """
        Adds the result of out-of-band authentication into an existing auth
        session. Currently used for adding the result of fallback auth.
        """
        if stagetype not in self.checkers:
            raise LoginError(400, "", Codes.MISSING_PARAM)
        if "session" not in authdict:
            raise LoginError(400, "", Codes.MISSING_PARAM)

        result = await self.checkers[stagetype].check_auth(authdict, clientip)
        if result:
            await self.store.mark_ui_auth_stage_complete(
                authdict["session"], stagetype, result
            )
            return True
        return False

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

    async def _expire_old_sessions(self):
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
        canonical_id, _ = await self.validate_login(authdict)
        return canonical_id

    def _get_params_recaptcha(self) -> dict:
        return {"public_key": self.hs.config.recaptcha_public_key}

    def _get_params_terms(self) -> dict:
        return {
            "policies": {
                "privacy_policy": {
                    "version": self.hs.config.user_consent_version,
                    "en": {
                        "name": self.hs.config.user_consent_policy_name,
                        "url": "%s_matrix/consent?v=%s"
                        % (
                            self.hs.config.public_baseurl,
                            self.hs.config.user_consent_version,
                        ),
                    },
                }
            }
        }

    def _auth_dict_for_flows(
        self, flows: List[List[str]], session_id: str,
    ) -> Dict[str, Any]:
        public_flows = []
        for f in flows:
            public_flows.append(f)

        get_params = {
            LoginType.RECAPTCHA: self._get_params_recaptcha,
            LoginType.TERMS: self._get_params_terms,
        }

        params = {}  # type: Dict[str, Any]

        for f in public_flows:
            for stage in f:
                if stage in get_params and stage not in params:
                    params[stage] = get_params[stage]()

        return {
            "session": session_id,
            "flows": [{"stages": f} for f in public_flows],
            "params": params,
        }

    async def get_access_token_for_user_id(
        self,
        user_id: str,
        device_id: Optional[str],
        valid_until_ms: Optional[int],
        puppets_user_id: Optional[str] = None,
        is_appservice_ghost: bool = False,
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
        else:
            logger.info(
                "Logging in user %s on device %s%s", user_id, device_id, fmt_expiry
            )

        if (
            not is_appservice_ghost
            or self.hs.config.appservice.track_appservice_user_ips
        ):
            await self.auth.check_auth_blocking(user_id)

        access_token = self.macaroon_gen.generate_access_token(user_id)
        await self.store.add_access_token_to_user(
            user_id=user_id,
            token=access_token,
            device_id=device_id,
            valid_until_ms=valid_until_ms,
            puppets_user_id=puppets_user_id,
        )

        # the device *should* have been registered before we got here; however,
        # it's possible we raced against a DELETE operation. The thing we
        # really don't want is active access_tokens without a record of the
        # device, so we double-check it here.
        if device_id is not None:
            try:
                await self.store.get_device(user_id, device_id)
            except StoreError:
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

    def get_supported_login_types(self) -> Iterable[str]:
        """Get a the login types supported for the /login API

        By default this is just 'm.login.password' (unless password_enabled is
        False in the config file), but password auth providers can provide
        other login types.

        Returns:
            login types
        """
        return self._supported_login_types

    async def validate_login(
        self, login_submission: Dict[str, Any], ratelimit: bool = False,
    ) -> Tuple[str, Optional[Callable[[Dict[str, str]], Awaitable[None]]]]:
        """Authenticates the user for the /login API

        Also used by the user-interactive auth flow to validate auth types which don't
        have an explicit UIA handler, including m.password.auth.

        Args:
            login_submission: the whole of the login submission
                (including 'type' and other relevant fields)
            ratelimit: whether to apply the failed_login_attempt ratelimiter
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
            if not self._password_enabled:
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
                self._failed_login_attempts_ratelimiter.ratelimit(
                    (medium, address), update=False
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
            user_id = await self.hs.get_datastore().get_user_id_by_threepid(
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
                    self._failed_login_attempts_ratelimiter.can_do_action(
                        (medium, address)
                    )
                raise LoginError(403, "", errcode=Codes.FORBIDDEN)

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
            self._failed_login_attempts_ratelimiter.ratelimit(
                qualified_user_id.lower(), update=False
            )

        try:
            return await self._validate_userid_login(username, login_submission)
        except LoginError:
            # The user has failed to log in, so we need to update the rate
            # limiter. Using `can_do_action` avoids us raising a ratelimit
            # exception and masking the LoginError. The actual ratelimiting
            # should have happened above.
            if ratelimit:
                self._failed_login_attempts_ratelimiter.can_do_action(
                    qualified_user_id.lower()
                )
            raise

    async def _validate_userid_login(
        self, username: str, login_submission: Dict[str, Any],
    ) -> Tuple[str, Optional[Callable[[Dict[str, str]], Awaitable[None]]]]:
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

        for provider in self.password_providers:
            supported_login_types = provider.get_supported_login_types()
            if login_type not in supported_login_types:
                # this password provider doesn't understand this login type
                continue

            known_login_type = True
            login_fields = supported_login_types[login_type]

            missing_fields = []
            login_dict = {}
            for f in login_fields:
                if f not in login_submission:
                    missing_fields.append(f)
                else:
                    login_dict[f] = login_submission[f]
            if missing_fields:
                raise SynapseError(
                    400,
                    "Missing parameters for login type %s: %s"
                    % (login_type, missing_fields),
                )

            result = await provider.check_auth(username, login_type, login_dict)
            if result:
                return result

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
        raise LoginError(403, "Invalid password", errcode=Codes.FORBIDDEN)

    async def check_password_provider_3pid(
        self, medium: str, address: str, password: str
    ) -> Tuple[Optional[str], Optional[Callable[[Dict[str, str]], Awaitable[None]]]]:
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
        for provider in self.password_providers:
            result = await provider.check_3pid_auth(medium, address, password)
            if result:
                return result

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

    async def validate_short_term_login_token_and_get_user_id(self, login_token: str):
        auth_api = self.hs.get_auth()
        user_id = None
        try:
            macaroon = pymacaroons.Macaroon.deserialize(login_token)
            user_id = auth_api.get_user_id_from_macaroon(macaroon)
            auth_api.validate_macaroon(macaroon, "login", user_id)
        except Exception:
            raise AuthError(403, "Invalid token", errcode=Codes.FORBIDDEN)

        await self.auth.check_auth_blocking(user_id)
        return user_id

    async def delete_access_token(self, access_token: str):
        """Invalidate a single access token

        Args:
            access_token: access token to be deleted

        """
        user_info = await self.auth.get_user_by_access_token(access_token)
        await self.store.delete_access_token(access_token)

        # see if any of our auth providers want to know about this
        for provider in self.password_providers:
            await provider.on_logged_out(
                user_id=user_info.user_id,
                device_id=user_info.device_id,
                access_token=access_token,
            )

        # delete pushers associated with this access token
        if user_info.token_id is not None:
            await self.hs.get_pusherpool().remove_pushers_by_access_token(
                user_info.user_id, (user_info.token_id,)
            )

    async def delete_access_tokens_for_user(
        self,
        user_id: str,
        except_token_id: Optional[str] = None,
        device_id: Optional[str] = None,
    ):
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

        # see if any of our auth providers want to know about this
        for provider in self.password_providers:
            for token, token_id, device_id in tokens_and_devices:
                await provider.on_logged_out(
                    user_id=user_id, device_id=device_id, access_token=token
                )

        # delete pushers associated with the access tokens
        await self.hs.get_pusherpool().remove_pushers_by_access_token(
            user_id, (token_id for _, token_id, _ in tokens_and_devices)
        )

    async def add_threepid(
        self, user_id: str, medium: str, address: str, validated_at: int
    ):
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
        return result

    async def hash(self, password: str) -> str:
        """Computes a secure hash of password.

        Args:
            password: Password to hash.

        Returns:
            Hashed password.
        """

        def _do_hash():
            # Normalise the Unicode in the password
            pw = unicodedata.normalize("NFKC", password)

            return bcrypt.hashpw(
                pw.encode("utf8") + self.hs.config.password_pepper.encode("utf8"),
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

        def _do_validate_hash(checked_hash: bytes):
            # Normalise the Unicode in the password
            pw = unicodedata.normalize("NFKC", password)

            return bcrypt.checkpw(
                pw.encode("utf8") + self.hs.config.password_pepper.encode("utf8"),
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

        user_id_to_verify = await self.get_session_data(
            session_id, UIAuthSessionDataConstants.REQUEST_USER_ID
        )  # type: str

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
        request: Request,
        client_redirect_url: str,
        extra_attributes: Optional[JsonDict] = None,
        new_user: bool = False,
    ):
        """Having figured out a mxid for this user, complete the HTTP request

        Args:
            registered_user_id: The registered user ID to complete SSO login for.
            request: The request to complete.
            client_redirect_url: The URL to which to redirect the user at the end of the
                process.
            extra_attributes: Extra attributes which will be passed to the client
                during successful login. Must be JSON serializable.
            new_user: True if we should use wording appropriate to a user who has just
                registered.
        """
        # If the account has been deactivated, do not proceed with the login
        # flow.
        deactivated = await self.store.get_user_deactivated_status(registered_user_id)
        if deactivated:
            respond_with_html(request, 403, self._sso_account_deactivated_template)
            return

        profile = await self.store.get_profileinfo(
            UserID.from_string(registered_user_id).localpart
        )

        self._complete_sso_login(
            registered_user_id,
            request,
            client_redirect_url,
            extra_attributes,
            new_user=new_user,
            user_profile_data=profile,
        )

    def _complete_sso_login(
        self,
        registered_user_id: str,
        request: Request,
        client_redirect_url: str,
        extra_attributes: Optional[JsonDict] = None,
        new_user: bool = False,
        user_profile_data: Optional[ProfileInfo] = None,
    ):
        """
        The synchronous portion of complete_sso_login.

        This exists purely for backwards compatibility of synapse.module_api.ModuleApi.
        """

        if user_profile_data is None:
            user_profile_data = ProfileInfo(None, None)

        # Store any extra attributes which will be passed in the login response.
        # Note that this is per-user so it may overwrite a previous value, this
        # is considered OK since the newest SSO attributes should be most valid.
        if extra_attributes:
            self._extra_attributes[registered_user_id] = SsoLoginExtraAttributes(
                self._clock.time_msec(), extra_attributes,
            )

        # Create a login token
        login_token = self.macaroon_gen.generate_short_term_login_token(
            registered_user_id
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
        redirect_url_no_params = client_redirect_url.split("?")[0]

        html = self._sso_redirect_confirm_template.render(
            display_url=redirect_url_no_params,
            redirect_url=redirect_url,
            server_name=self._server_name,
            new_user=new_user,
            user_id=registered_user_id,
            user_profile=user_profile_data,
        )
        respond_with_html(request, 200, html)

    async def _sso_login_callback(self, login_result: JsonDict) -> None:
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
            login_result.update(extra_attributes.extra_attributes)

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
    def add_query_param_to_url(url: str, param_name: str, param: Any):
        url_parts = list(urllib.parse.urlparse(url))
        query = urllib.parse.parse_qsl(url_parts[4], keep_blank_values=True)
        query.append((param_name, param))
        url_parts[4] = urllib.parse.urlencode(query)
        return urllib.parse.urlunparse(url_parts)


@attr.s(slots=True)
class MacaroonGenerator:

    hs = attr.ib()

    def generate_access_token(
        self, user_id: str, extra_caveats: Optional[List[str]] = None
    ) -> str:
        extra_caveats = extra_caveats or []
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = access")
        # Include a nonce, to make sure that each login gets a different
        # access token.
        macaroon.add_first_party_caveat(
            "nonce = %s" % (stringutils.random_string_with_symbols(16),)
        )
        for caveat in extra_caveats:
            macaroon.add_first_party_caveat(caveat)
        return macaroon.serialize()

    def generate_short_term_login_token(
        self, user_id: str, duration_in_ms: int = (2 * 60 * 1000)
    ) -> str:
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = login")
        now = self.hs.get_clock().time_msec()
        expiry = now + duration_in_ms
        macaroon.add_first_party_caveat("time < %d" % (expiry,))
        return macaroon.serialize()

    def generate_delete_pusher_token(self, user_id: str) -> str:
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = delete_pusher")
        return macaroon.serialize()

    def _generate_base_macaroon(self, user_id: str) -> pymacaroons.Macaroon:
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        return macaroon


class PasswordProvider:
    """Wrapper for a password auth provider module

    This class abstracts out all of the backwards-compatibility hacks for
    password providers, to provide a consistent interface.
    """

    @classmethod
    def load(cls, module, config, module_api: ModuleApi) -> "PasswordProvider":
        try:
            pp = module(config=config, account_handler=module_api)
        except Exception as e:
            logger.error("Error while initializing %r: %s", module, e)
            raise
        return cls(pp, module_api)

    def __init__(self, pp, module_api: ModuleApi):
        self._pp = pp
        self._module_api = module_api

        self._supported_login_types = {}

        # grandfather in check_password support
        if hasattr(self._pp, "check_password"):
            self._supported_login_types[LoginType.PASSWORD] = ("password",)

        g = getattr(self._pp, "get_supported_login_types", None)
        if g:
            self._supported_login_types.update(g())

    def __str__(self):
        return str(self._pp)

    def get_supported_login_types(self) -> Mapping[str, Iterable[str]]:
        """Get the login types supported by this password provider

        Returns a map from a login type identifier (such as m.login.password) to an
        iterable giving the fields which must be provided by the user in the submission
        to the /login API.

        This wrapper adds m.login.password to the list if the underlying password
        provider supports the check_password() api.
        """
        return self._supported_login_types

    async def check_auth(
        self, username: str, login_type: str, login_dict: JsonDict
    ) -> Optional[Tuple[str, Optional[Callable]]]:
        """Check if the user has presented valid login credentials

        This wrapper also calls check_password() if the underlying password provider
        supports the check_password() api and the login type is m.login.password.

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
        # first grandfather in a call to check_password
        if login_type == LoginType.PASSWORD:
            g = getattr(self._pp, "check_password", None)
            if g:
                qualified_user_id = self._module_api.get_qualified_user_id(username)
                is_valid = await self._pp.check_password(
                    qualified_user_id, login_dict["password"]
                )
                if is_valid:
                    return qualified_user_id, None

        g = getattr(self._pp, "check_auth", None)
        if not g:
            return None
        result = await g(username, login_type, login_dict)

        # Check if the return value is a str or a tuple
        if isinstance(result, str):
            # If it's a str, set callback function to None
            return result, None

        return result

    async def check_3pid_auth(
        self, medium: str, address: str, password: str
    ) -> Optional[Tuple[str, Optional[Callable]]]:
        g = getattr(self._pp, "check_3pid_auth", None)
        if not g:
            return None

        # This function is able to return a deferred that either
        # resolves None, meaning authentication failure, or upon
        # success, to a str (which is the user_id) or a tuple of
        # (user_id, callback_func), where callback_func should be run
        # after we've finished everything else
        result = await g(medium, address, password)

        # Check if the return value is a str or a tuple
        if isinstance(result, str):
            # If it's a str, set callback function to None
            return result, None

        return result

    async def on_logged_out(
        self, user_id: str, device_id: Optional[str], access_token: str
    ) -> None:
        g = getattr(self._pp, "on_logged_out", None)
        if not g:
            return

        # This might return an awaitable, if it does block the log out
        # until it completes.
        await maybe_awaitable(
            g(user_id=user_id, device_id=device_id, access_token=access_token,)
        )
