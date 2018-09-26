# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
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
import unicodedata

import attr
import bcrypt
import pymacaroons
from canonicaljson import json

from twisted.internet import defer, threads
from twisted.web.client import PartialDownloadError

import synapse.util.stringutils as stringutils
from synapse.api.constants import LoginType
from synapse.api.errors import (
    AuthError,
    Codes,
    InteractiveAuthIncompleteError,
    LoginError,
    StoreError,
    SynapseError,
)
from synapse.module_api import ModuleApi
from synapse.types import UserID
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.logcontext import make_deferred_yieldable

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class AuthHandler(BaseHandler):
    SESSION_EXPIRE_MS = 48 * 60 * 60 * 1000

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """
        super(AuthHandler, self).__init__(hs)
        self.checkers = {
            LoginType.RECAPTCHA: self._check_recaptcha,
            LoginType.EMAIL_IDENTITY: self._check_email_identity,
            LoginType.MSISDN: self._check_msisdn,
            LoginType.DUMMY: self._check_dummy_auth,
        }
        self.bcrypt_rounds = hs.config.bcrypt_rounds

        # This is not a cache per se, but a store of all current sessions that
        # expire after N hours
        self.sessions = ExpiringCache(
            cache_name="register_sessions",
            clock=hs.get_clock(),
            expiry_ms=self.SESSION_EXPIRE_MS,
            reset_expiry_on_get=True,
        )

        account_handler = ModuleApi(hs, self)
        self.password_providers = [
            module(config=config, account_handler=account_handler)
            for module, config in hs.config.password_providers
        ]

        logger.info("Extra password_providers: %r", self.password_providers)

        self.hs = hs  # FIXME better possibility to access registrationHandler later?
        self.macaroon_gen = hs.get_macaroon_generator()
        self._password_enabled = hs.config.password_enabled

        # we keep this as a list despite the O(N^2) implication so that we can
        # keep PASSWORD first and avoid confusing clients which pick the first
        # type in the list. (NB that the spec doesn't require us to do so and
        # clients which favour types that they don't understand over those that
        # they do are technically broken)
        login_types = []
        if self._password_enabled:
            login_types.append(LoginType.PASSWORD)
        for provider in self.password_providers:
            if hasattr(provider, "get_supported_login_types"):
                for t in provider.get_supported_login_types().keys():
                    if t not in login_types:
                        login_types.append(t)
        self._supported_login_types = login_types

    @defer.inlineCallbacks
    def validate_user_via_ui_auth(self, requester, request_body, clientip):
        """
        Checks that the user is who they claim to be, via a UI auth.

        This is used for things like device deletion and password reset where
        the user already has a valid access token, but we want to double-check
        that it isn't stolen by re-authenticating them.

        Args:
            requester (Requester): The user, as given by the access token

            request_body (dict): The body of the request sent by the client

            clientip (str): The IP address of the client.

        Returns:
            defer.Deferred[dict]: the parameters for this request (which may
                have been given only in a previous call).

        Raises:
            InteractiveAuthIncompleteError if the client has not yet completed
                any of the permitted login flows

            AuthError if the client has completed a login flow, and it gives
                a different user to `requester`
        """

        # build a list of supported flows
        flows = [
            [login_type] for login_type in self._supported_login_types
        ]

        result, params, _ = yield self.check_auth(
            flows, request_body, clientip,
        )

        # find the completed login type
        for login_type in self._supported_login_types:
            if login_type not in result:
                continue

            user_id = result[login_type]
            break
        else:
            # this can't happen
            raise Exception(
                "check_auth returned True but no successful login type",
            )

        # check that the UI auth matched the access token
        if user_id != requester.user.to_string():
            raise AuthError(403, "Invalid auth")

        defer.returnValue(params)

    @defer.inlineCallbacks
    def check_auth(self, flows, clientdict, clientip):
        """
        Takes a dictionary sent by the client in the login / registration
        protocol and handles the User-Interactive Auth flow.

        As a side effect, this function fills in the 'creds' key on the user's
        session with a map, which maps each auth-type (str) to the relevant
        identity authenticated by that auth-type (mostly str, but for captcha, bool).

        If no auth flows have been completed successfully, raises an
        InteractiveAuthIncompleteError. To handle this, you can use
        synapse.rest.client.v2_alpha._base.interactive_auth_handler as a
        decorator.

        Args:
            flows (list): A list of login flows. Each flow is an ordered list of
                          strings representing auth-types. At least one full
                          flow must be completed in order for auth to be successful.

            clientdict: The dictionary from the client root level, not the
                        'auth' key: this method prompts for auth if none is sent.

            clientip (str): The IP address of the client.

        Returns:
            defer.Deferred[dict, dict, str]: a deferred tuple of
                (creds, params, session_id).

                'creds' contains the authenticated credentials of each stage.

                'params' contains the parameters for this request (which may
                have been given only in a previous call).

                'session_id' is the ID of this session, either passed in by the
                client or assigned by this call

        Raises:
            InteractiveAuthIncompleteError if the client has not yet completed
                all the stages in any of the permitted flows.
        """

        authdict = None
        sid = None
        if clientdict and 'auth' in clientdict:
            authdict = clientdict['auth']
            del clientdict['auth']
            if 'session' in authdict:
                sid = authdict['session']
        session = self._get_session_info(sid)

        if len(clientdict) > 0:
            # This was designed to allow the client to omit the parameters
            # and just supply the session in subsequent calls so it split
            # auth between devices by just sharing the session, (eg. so you
            # could continue registration from your phone having clicked the
            # email auth link on there). It's probably too open to abuse
            # because it lets unauthenticated clients store arbitrary objects
            # on a home server.
            # Revisit: Assumimg the REST APIs do sensible validation, the data
            # isn't arbintrary.
            session['clientdict'] = clientdict
            self._save_session(session)
        elif 'clientdict' in session:
            clientdict = session['clientdict']

        if not authdict:
            raise InteractiveAuthIncompleteError(
                self._auth_dict_for_flows(flows, session),
            )

        if 'creds' not in session:
            session['creds'] = {}
        creds = session['creds']

        # check auth type currently being presented
        errordict = {}
        if 'type' in authdict:
            login_type = authdict['type']
            try:
                result = yield self._check_auth_dict(authdict, clientip)
                if result:
                    creds[login_type] = result
                    self._save_session(session)
            except LoginError as e:
                if login_type == LoginType.EMAIL_IDENTITY:
                    # riot used to have a bug where it would request a new
                    # validation token (thus sending a new email) each time it
                    # got a 401 with a 'flows' field.
                    # (https://github.com/vector-im/vector-web/issues/2447).
                    #
                    # Grandfather in the old behaviour for now to avoid
                    # breaking old riot deployments.
                    raise

                # this step failed. Merge the error dict into the response
                # so that the client can have another go.
                errordict = e.error_dict()

        for f in flows:
            if len(set(f) - set(creds)) == 0:
                # it's very useful to know what args are stored, but this can
                # include the password in the case of registering, so only log
                # the keys (confusingly, clientdict may contain a password
                # param, creds is just what the user authed as for UI auth
                # and is not sensitive).
                logger.info(
                    "Auth completed with creds: %r. Client dict has keys: %r",
                    creds, list(clientdict)
                )
                defer.returnValue((creds, clientdict, session['id']))

        ret = self._auth_dict_for_flows(flows, session)
        ret['completed'] = list(creds)
        ret.update(errordict)
        raise InteractiveAuthIncompleteError(
            ret,
        )

    @defer.inlineCallbacks
    def add_oob_auth(self, stagetype, authdict, clientip):
        """
        Adds the result of out-of-band authentication into an existing auth
        session. Currently used for adding the result of fallback auth.
        """
        if stagetype not in self.checkers:
            raise LoginError(400, "", Codes.MISSING_PARAM)
        if 'session' not in authdict:
            raise LoginError(400, "", Codes.MISSING_PARAM)

        sess = self._get_session_info(
            authdict['session']
        )
        if 'creds' not in sess:
            sess['creds'] = {}
        creds = sess['creds']

        result = yield self.checkers[stagetype](authdict, clientip)
        if result:
            creds[stagetype] = result
            self._save_session(sess)
            defer.returnValue(True)
        defer.returnValue(False)

    def get_session_id(self, clientdict):
        """
        Gets the session ID for a client given the client dictionary

        Args:
            clientdict: The dictionary sent by the client in the request

        Returns:
            str|None: The string session ID the client sent. If the client did
                not send a session ID, returns None.
        """
        sid = None
        if clientdict and 'auth' in clientdict:
            authdict = clientdict['auth']
            if 'session' in authdict:
                sid = authdict['session']
        return sid

    def set_session_data(self, session_id, key, value):
        """
        Store a key-value pair into the sessions data associated with this
        request. This data is stored server-side and cannot be modified by
        the client.

        Args:
            session_id (string): The ID of this session as returned from check_auth
            key (string): The key to store the data under
            value (any): The data to store
        """
        sess = self._get_session_info(session_id)
        sess.setdefault('serverdict', {})[key] = value
        self._save_session(sess)

    def get_session_data(self, session_id, key, default=None):
        """
        Retrieve data stored with set_session_data

        Args:
            session_id (string): The ID of this session as returned from check_auth
            key (string): The key to store the data under
            default (any): Value to return if the key has not been set
        """
        sess = self._get_session_info(session_id)
        return sess.setdefault('serverdict', {}).get(key, default)

    @defer.inlineCallbacks
    def _check_auth_dict(self, authdict, clientip):
        """Attempt to validate the auth dict provided by a client

        Args:
            authdict (object): auth dict provided by the client
            clientip (str): IP address of the client

        Returns:
            Deferred: result of the stage verification.

        Raises:
            StoreError if there was a problem accessing the database
            SynapseError if there was a problem with the request
            LoginError if there was an authentication problem.
        """
        login_type = authdict['type']
        checker = self.checkers.get(login_type)
        if checker is not None:
            res = yield checker(authdict, clientip)
            defer.returnValue(res)

        # build a v1-login-style dict out of the authdict and fall back to the
        # v1 code
        user_id = authdict.get("user")

        if user_id is None:
            raise SynapseError(400, "", Codes.MISSING_PARAM)

        (canonical_id, callback) = yield self.validate_login(user_id, authdict)
        defer.returnValue(canonical_id)

    @defer.inlineCallbacks
    def _check_recaptcha(self, authdict, clientip):
        try:
            user_response = authdict["response"]
        except KeyError:
            # Client tried to provide captcha but didn't give the parameter:
            # bad request.
            raise LoginError(
                400, "Captcha response is required",
                errcode=Codes.CAPTCHA_NEEDED
            )

        logger.info(
            "Submitting recaptcha response %s with remoteip %s",
            user_response, clientip
        )

        # TODO: get this from the homeserver rather than creating a new one for
        # each request
        try:
            client = self.hs.get_simple_http_client()
            resp_body = yield client.post_urlencoded_get_json(
                self.hs.config.recaptcha_siteverify_api,
                args={
                    'secret': self.hs.config.recaptcha_private_key,
                    'response': user_response,
                    'remoteip': clientip,
                }
            )
        except PartialDownloadError as pde:
            # Twisted is silly
            data = pde.response
            resp_body = json.loads(data)

        if 'success' in resp_body:
            # Note that we do NOT check the hostname here: we explicitly
            # intend the CAPTCHA to be presented by whatever client the
            # user is using, we just care that they have completed a CAPTCHA.
            logger.info(
                "%s reCAPTCHA from hostname %s",
                "Successful" if resp_body['success'] else "Failed",
                resp_body.get('hostname')
            )
            if resp_body['success']:
                defer.returnValue(True)
        raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

    def _check_email_identity(self, authdict, _):
        return self._check_threepid('email', authdict)

    def _check_msisdn(self, authdict, _):
        return self._check_threepid('msisdn', authdict)

    def _check_dummy_auth(self, authdict, _):
        return defer.succeed(True)

    @defer.inlineCallbacks
    def _check_threepid(self, medium, authdict):
        if 'threepid_creds' not in authdict:
            raise LoginError(400, "Missing threepid_creds", Codes.MISSING_PARAM)

        threepid_creds = authdict['threepid_creds']

        identity_handler = self.hs.get_handlers().identity_handler

        logger.info("Getting validated threepid. threepidcreds: %r", (threepid_creds,))
        threepid = yield identity_handler.threepid_from_creds(threepid_creds)

        if not threepid:
            raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

        if threepid['medium'] != medium:
            raise LoginError(
                401,
                "Expecting threepid of type '%s', got '%s'" % (
                    medium, threepid['medium'],
                ),
                errcode=Codes.UNAUTHORIZED
            )

        threepid['threepid_creds'] = authdict['threepid_creds']

        defer.returnValue(threepid)

    def _get_params_recaptcha(self):
        return {"public_key": self.hs.config.recaptcha_public_key}

    def _auth_dict_for_flows(self, flows, session):
        public_flows = []
        for f in flows:
            public_flows.append(f)

        get_params = {
            LoginType.RECAPTCHA: self._get_params_recaptcha,
        }

        params = {}

        for f in public_flows:
            for stage in f:
                if stage in get_params and stage not in params:
                    params[stage] = get_params[stage]()

        return {
            "session": session['id'],
            "flows": [{"stages": f} for f in public_flows],
            "params": params
        }

    def _get_session_info(self, session_id):
        if session_id not in self.sessions:
            session_id = None

        if not session_id:
            # create a new session
            while session_id is None or session_id in self.sessions:
                session_id = stringutils.random_string(24)
            self.sessions[session_id] = {
                "id": session_id,
            }

        return self.sessions[session_id]

    @defer.inlineCallbacks
    def get_access_token_for_user_id(self, user_id, device_id=None):
        """
        Creates a new access token for the user with the given user ID.

        The user is assumed to have been authenticated by some other
        machanism (e.g. CAS), and the user_id converted to the canonical case.

        The device will be recorded in the table if it is not there already.

        Args:
            user_id (str): canonical User ID
            device_id (str|None): the device ID to associate with the tokens.
               None to leave the tokens unassociated with a device (deprecated:
               we should always have a device ID)
        Returns:
              The access token for the user's session.
        Raises:
            StoreError if there was a problem storing the token.
        """
        logger.info("Logging in user %s on device %s", user_id, device_id)
        access_token = yield self.issue_access_token(user_id, device_id)
        yield self.auth.check_auth_blocking(user_id)

        # the device *should* have been registered before we got here; however,
        # it's possible we raced against a DELETE operation. The thing we
        # really don't want is active access_tokens without a record of the
        # device, so we double-check it here.
        if device_id is not None:
            try:
                yield self.store.get_device(user_id, device_id)
            except StoreError:
                yield self.store.delete_access_token(access_token)
                raise StoreError(400, "Login raced against device deletion")

        defer.returnValue(access_token)

    @defer.inlineCallbacks
    def check_user_exists(self, user_id):
        """
        Checks to see if a user with the given id exists. Will check case
        insensitively, but return None if there are multiple inexact matches.

        Args:
            (str) user_id: complete @user:id

        Returns:
            defer.Deferred: (str) canonical_user_id, or None if zero or
            multiple matches
        """
        res = yield self._find_user_id_and_pwd_hash(user_id)
        if res is not None:
            defer.returnValue(res[0])
        defer.returnValue(None)

    @defer.inlineCallbacks
    def _find_user_id_and_pwd_hash(self, user_id):
        """Checks to see if a user with the given id exists. Will check case
        insensitively, but will return None if there are multiple inexact
        matches.

        Returns:
            tuple: A 2-tuple of `(canonical_user_id, password_hash)`
            None: if there is not exactly one match
        """
        user_infos = yield self.store.get_users_by_id_case_insensitive(user_id)

        result = None
        if not user_infos:
            logger.warn("Attempted to login as %s but they do not exist", user_id)
        elif len(user_infos) == 1:
            # a single match (possibly not exact)
            result = user_infos.popitem()
        elif user_id in user_infos:
            # multiple matches, but one is exact
            result = (user_id, user_infos[user_id])
        else:
            # multiple matches, none of them exact
            logger.warn(
                "Attempted to login as %s but it matches more than one user "
                "inexactly: %r",
                user_id, user_infos.keys()
            )
        defer.returnValue(result)

    def get_supported_login_types(self):
        """Get a the login types supported for the /login API

        By default this is just 'm.login.password' (unless password_enabled is
        False in the config file), but password auth providers can provide
        other login types.

        Returns:
            Iterable[str]: login types
        """
        return self._supported_login_types

    @defer.inlineCallbacks
    def validate_login(self, username, login_submission):
        """Authenticates the user for the /login API

        Also used by the user-interactive auth flow to validate
        m.login.password auth types.

        Args:
            username (str): username supplied by the user
            login_submission (dict): the whole of the login submission
                (including 'type' and other relevant fields)
        Returns:
            Deferred[str, func]: canonical user id, and optional callback
                to be called once the access token and device id are issued
        Raises:
            StoreError if there was a problem accessing the database
            SynapseError if there was a problem with the request
            LoginError if there was an authentication problem.
        """

        if username.startswith('@'):
            qualified_user_id = username
        else:
            qualified_user_id = UserID(
                username, self.hs.hostname
            ).to_string()

        login_type = login_submission.get("type")
        known_login_type = False

        # special case to check for "password" for the check_password interface
        # for the auth providers
        password = login_submission.get("password")

        if login_type == LoginType.PASSWORD:
            if not self._password_enabled:
                raise SynapseError(400, "Password login has been disabled.")
            if not password:
                raise SynapseError(400, "Missing parameter: password")

        for provider in self.password_providers:
            if (hasattr(provider, "check_password")
                    and login_type == LoginType.PASSWORD):
                known_login_type = True
                is_valid = yield provider.check_password(
                    qualified_user_id, password,
                )
                if is_valid:
                    defer.returnValue((qualified_user_id, None))

            if (not hasattr(provider, "get_supported_login_types")
                    or not hasattr(provider, "check_auth")):
                # this password provider doesn't understand custom login types
                continue

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
                    400, "Missing parameters for login type %s: %s" % (
                        login_type,
                        missing_fields,
                    ),
                )

            result = yield provider.check_auth(
                username, login_type, login_dict,
            )
            if result:
                if isinstance(result, str):
                    result = (result, None)
                defer.returnValue(result)

        if login_type == LoginType.PASSWORD:
            known_login_type = True

            canonical_user_id = yield self._check_local_password(
                qualified_user_id, password,
            )

            if canonical_user_id:
                defer.returnValue((canonical_user_id, None))

        if not known_login_type:
            raise SynapseError(400, "Unknown login type %s" % login_type)

        # unknown username or invalid password. We raise a 403 here, but note
        # that if we're doing user-interactive login, it turns all LoginErrors
        # into a 401 anyway.
        raise LoginError(
            403, "Invalid password",
            errcode=Codes.FORBIDDEN
        )

    @defer.inlineCallbacks
    def _check_local_password(self, user_id, password):
        """Authenticate a user against the local password database.

        user_id is checked case insensitively, but will return None if there are
        multiple inexact matches.

        Args:
            user_id (unicode): complete @user:id
            password (unicode): the provided password
        Returns:
            (unicode) the canonical_user_id, or None if unknown user / bad password
        """
        lookupres = yield self._find_user_id_and_pwd_hash(user_id)
        if not lookupres:
            defer.returnValue(None)
        (user_id, password_hash) = lookupres
        result = yield self.validate_hash(password, password_hash)
        if not result:
            logger.warn("Failed password login for user %s", user_id)
            defer.returnValue(None)
        defer.returnValue(user_id)

    @defer.inlineCallbacks
    def issue_access_token(self, user_id, device_id=None):
        access_token = self.macaroon_gen.generate_access_token(user_id)
        yield self.store.add_access_token_to_user(user_id, access_token,
                                                  device_id)
        defer.returnValue(access_token)

    @defer.inlineCallbacks
    def validate_short_term_login_token_and_get_user_id(self, login_token):
        auth_api = self.hs.get_auth()
        user_id = None
        try:
            macaroon = pymacaroons.Macaroon.deserialize(login_token)
            user_id = auth_api.get_user_id_from_macaroon(macaroon)
            auth_api.validate_macaroon(macaroon, "login", True, user_id)
        except Exception:
            raise AuthError(403, "Invalid token", errcode=Codes.FORBIDDEN)
        yield self.auth.check_auth_blocking(user_id)
        defer.returnValue(user_id)

    @defer.inlineCallbacks
    def delete_access_token(self, access_token):
        """Invalidate a single access token

        Args:
            access_token (str): access token to be deleted

        Returns:
            Deferred
        """
        user_info = yield self.auth.get_user_by_access_token(access_token)
        yield self.store.delete_access_token(access_token)

        # see if any of our auth providers want to know about this
        for provider in self.password_providers:
            if hasattr(provider, "on_logged_out"):
                yield provider.on_logged_out(
                    user_id=str(user_info["user"]),
                    device_id=user_info["device_id"],
                    access_token=access_token,
                )

        # delete pushers associated with this access token
        if user_info["token_id"] is not None:
            yield self.hs.get_pusherpool().remove_pushers_by_access_token(
                str(user_info["user"]), (user_info["token_id"], )
            )

    @defer.inlineCallbacks
    def delete_access_tokens_for_user(self, user_id, except_token_id=None,
                                      device_id=None):
        """Invalidate access tokens belonging to a user

        Args:
            user_id (str):  ID of user the tokens belong to
            except_token_id (str|None): access_token ID which should *not* be
                deleted
            device_id (str|None):  ID of device the tokens are associated with.
                If None, tokens associated with any device (or no device) will
                be deleted
        Returns:
            Deferred
        """
        tokens_and_devices = yield self.store.user_delete_access_tokens(
            user_id, except_token_id=except_token_id, device_id=device_id,
        )

        # see if any of our auth providers want to know about this
        for provider in self.password_providers:
            if hasattr(provider, "on_logged_out"):
                for token, token_id, device_id in tokens_and_devices:
                    yield provider.on_logged_out(
                        user_id=user_id,
                        device_id=device_id,
                        access_token=token,
                    )

        # delete pushers associated with the access tokens
        yield self.hs.get_pusherpool().remove_pushers_by_access_token(
            user_id, (token_id for _, token_id, _ in tokens_and_devices),
        )

    @defer.inlineCallbacks
    def add_threepid(self, user_id, medium, address, validated_at):
        # 'Canonicalise' email addresses down to lower case.
        # We've now moving towards the Home Server being the entity that
        # is responsible for validating threepids used for resetting passwords
        # on accounts, so in future Synapse will gain knowledge of specific
        # types (mediums) of threepid. For now, we still use the existing
        # infrastructure, but this is the start of synapse gaining knowledge
        # of specific types of threepid (and fixes the fact that checking
        # for the presence of an email address during password reset was
        # case sensitive).
        if medium == 'email':
            address = address.lower()

        yield self.store.user_add_threepid(
            user_id, medium, address, validated_at,
            self.hs.get_clock().time_msec()
        )

    @defer.inlineCallbacks
    def delete_threepid(self, user_id, medium, address):
        """Attempts to unbind the 3pid on the identity servers and deletes it
        from the local database.

        Args:
            user_id (str)
            medium (str)
            address (str)

        Returns:
            Deferred[bool]: Returns True if successfully unbound the 3pid on
            the identity server, False if identity server doesn't support the
            unbind API.
        """

        # 'Canonicalise' email addresses as per above
        if medium == 'email':
            address = address.lower()

        identity_handler = self.hs.get_handlers().identity_handler
        result = yield identity_handler.try_unbind_threepid(
            user_id,
            {
                'medium': medium,
                'address': address,
            },
        )

        yield self.store.user_delete_threepid(
            user_id, medium, address,
        )
        defer.returnValue(result)

    def _save_session(self, session):
        # TODO: Persistent storage
        logger.debug("Saving session %s", session)
        session["last_used"] = self.hs.get_clock().time_msec()
        self.sessions[session["id"]] = session

    def hash(self, password):
        """Computes a secure hash of password.

        Args:
            password (unicode): Password to hash.

        Returns:
            Deferred(unicode): Hashed password.
        """
        def _do_hash():
            # Normalise the Unicode in the password
            pw = unicodedata.normalize("NFKC", password)

            return bcrypt.hashpw(
                pw.encode('utf8') + self.hs.config.password_pepper.encode("utf8"),
                bcrypt.gensalt(self.bcrypt_rounds),
            ).decode('ascii')

        return make_deferred_yieldable(
            threads.deferToThreadPool(
                self.hs.get_reactor(), self.hs.get_reactor().getThreadPool(), _do_hash
            ),
        )

    def validate_hash(self, password, stored_hash):
        """Validates that self.hash(password) == stored_hash.

        Args:
            password (unicode): Password to hash.
            stored_hash (bytes): Expected hash value.

        Returns:
            Deferred(bool): Whether self.hash(password) == stored_hash.
        """
        def _do_validate_hash():
            # Normalise the Unicode in the password
            pw = unicodedata.normalize("NFKC", password)

            return bcrypt.checkpw(
                pw.encode('utf8') + self.hs.config.password_pepper.encode("utf8"),
                stored_hash
            )

        if stored_hash:
            if not isinstance(stored_hash, bytes):
                stored_hash = stored_hash.encode('ascii')

            return make_deferred_yieldable(
                threads.deferToThreadPool(
                    self.hs.get_reactor(),
                    self.hs.get_reactor().getThreadPool(),
                    _do_validate_hash,
                ),
            )
        else:
            return defer.succeed(False)


@attr.s
class MacaroonGenerator(object):

    hs = attr.ib()

    def generate_access_token(self, user_id, extra_caveats=None):
        extra_caveats = extra_caveats or []
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = access")
        # Include a nonce, to make sure that each login gets a different
        # access token.
        macaroon.add_first_party_caveat("nonce = %s" % (
            stringutils.random_string_with_symbols(16),
        ))
        for caveat in extra_caveats:
            macaroon.add_first_party_caveat(caveat)
        return macaroon.serialize()

    def generate_short_term_login_token(self, user_id, duration_in_ms=(2 * 60 * 1000)):
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = login")
        now = self.hs.get_clock().time_msec()
        expiry = now + duration_in_ms
        macaroon.add_first_party_caveat("time < %d" % (expiry,))
        return macaroon.serialize()

    def generate_delete_pusher_token(self, user_id):
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = delete_pusher")
        return macaroon.serialize()

    def _generate_base_macaroon(self, user_id):
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key)
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        return macaroon
