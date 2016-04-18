# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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

from twisted.internet import defer

from ._base import BaseHandler
from synapse.api.constants import LoginType
from synapse.types import UserID
from synapse.api.errors import AuthError, LoginError, Codes
from synapse.util.async import run_on_reactor

from twisted.web.client import PartialDownloadError

import logging
import bcrypt
import pymacaroons
import simplejson

import synapse.util.stringutils as stringutils


logger = logging.getLogger(__name__)


class AuthHandler(BaseHandler):
    SESSION_EXPIRE_MS = 48 * 60 * 60 * 1000

    def __init__(self, hs):
        super(AuthHandler, self).__init__(hs)
        self.checkers = {
            LoginType.PASSWORD: self._check_password_auth,
            LoginType.RECAPTCHA: self._check_recaptcha,
            LoginType.EMAIL_IDENTITY: self._check_email_identity,
            LoginType.DUMMY: self._check_dummy_auth,
        }
        self.bcrypt_rounds = hs.config.bcrypt_rounds
        self.sessions = {}
        self.INVALID_TOKEN_HTTP_STATUS = 401

        self.ldap_enabled = hs.config.ldap_enabled
        self.ldap_server = hs.config.ldap_server
        self.ldap_port = hs.config.ldap_port
        self.ldap_tls = hs.config.ldap_tls
        self.ldap_search_base = hs.config.ldap_search_base
        self.ldap_search_property = hs.config.ldap_search_property
        self.ldap_email_property = hs.config.ldap_email_property
        self.ldap_full_name_property = hs.config.ldap_full_name_property

        if self.ldap_enabled is True:
            import ldap
            logger.info("Import ldap version: %s", ldap.__version__)

        self.hs = hs  # FIXME better possibility to access registrationHandler later?

    @defer.inlineCallbacks
    def check_auth(self, flows, clientdict, clientip):
        """
        Takes a dictionary sent by the client in the login / registration
        protocol and handles the login flow.

        As a side effect, this function fills in the 'creds' key on the user's
        session with a map, which maps each auth-type (str) to the relevant
        identity authenticated by that auth-type (mostly str, but for captcha, bool).

        Args:
            flows (list): A list of login flows. Each flow is an ordered list of
                          strings representing auth-types. At least one full
                          flow must be completed in order for auth to be successful.
            clientdict: The dictionary from the client root level, not the
                        'auth' key: this method prompts for auth if none is sent.
            clientip (str): The IP address of the client.
        Returns:
            A tuple of (authed, dict, dict, session_id) where authed is true if
            the client has successfully completed an auth flow. If it is true
            the first dict contains the authenticated credentials of each stage.

            If authed is false, the first dictionary is the server response to
            the login request and should be passed back to the client.

            In either case, the second dict contains the parameters for this
            request (which may have been given only in a previous call).

            session_id is the ID of this session, either passed in by the client
            or assigned by the call to check_auth
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
            defer.returnValue(
                (
                    False, self._auth_dict_for_flows(flows, session),
                    clientdict, session['id']
                )
            )

        if 'creds' not in session:
            session['creds'] = {}
        creds = session['creds']

        # check auth type currently being presented
        if 'type' in authdict:
            if authdict['type'] not in self.checkers:
                raise LoginError(400, "", Codes.UNRECOGNIZED)
            result = yield self.checkers[authdict['type']](authdict, clientip)
            if result:
                creds[authdict['type']] = result
                self._save_session(session)

        for f in flows:
            if len(set(f) - set(creds.keys())) == 0:
                logger.info("Auth completed with creds: %r", creds)
                defer.returnValue((True, creds, clientdict, session['id']))

        ret = self._auth_dict_for_flows(flows, session)
        ret['completed'] = creds.keys()
        defer.returnValue((False, ret, clientdict, session['id']))

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
    def _check_password_auth(self, authdict, _):
        if "user" not in authdict or "password" not in authdict:
            raise LoginError(400, "", Codes.MISSING_PARAM)

        user_id = authdict["user"]
        password = authdict["password"]
        if not user_id.startswith('@'):
            user_id = UserID.create(user_id, self.hs.hostname).to_string()

        if not (yield self._check_password(user_id, password)):
            logger.warn("Failed password login for user %s", user_id)
            raise LoginError(403, "", errcode=Codes.FORBIDDEN)

        defer.returnValue(user_id)

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
            resp_body = simplejson.loads(data)

        if 'success' in resp_body and resp_body['success']:
            defer.returnValue(True)
        raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

    @defer.inlineCallbacks
    def _check_email_identity(self, authdict, _):
        yield run_on_reactor()

        if 'threepid_creds' not in authdict:
            raise LoginError(400, "Missing threepid_creds", Codes.MISSING_PARAM)

        threepid_creds = authdict['threepid_creds']
        identity_handler = self.hs.get_handlers().identity_handler

        logger.info("Getting validated threepid. threepidcreds: %r" % (threepid_creds,))
        threepid = yield identity_handler.threepid_from_creds(threepid_creds)

        if not threepid:
            raise LoginError(401, "", errcode=Codes.UNAUTHORIZED)

        threepid['threepid_creds'] = authdict['threepid_creds']

        defer.returnValue(threepid)

    @defer.inlineCallbacks
    def _check_dummy_auth(self, authdict, _):
        yield run_on_reactor()
        defer.returnValue(True)

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
    def login_with_password(self, user_id, password):
        """
        Authenticates the user with their username and password.

        Used only by the v1 login API.

        Args:
            user_id (str): User ID
            password (str): Password
        Returns:
            A tuple of:
              The user's ID.
              The access token for the user's session.
              The refresh token for the user's session.
        Raises:
            StoreError if there was a problem storing the token.
            LoginError if there was an authentication problem.
        """

        if not (yield self._check_password(user_id, password)):
            logger.warn("Failed password login for user %s", user_id)
            raise LoginError(403, "", errcode=Codes.FORBIDDEN)

        logger.info("Logging in user %s", user_id)
        access_token = yield self.issue_access_token(user_id)
        refresh_token = yield self.issue_refresh_token(user_id)
        defer.returnValue((user_id, access_token, refresh_token))

    @defer.inlineCallbacks
    def get_login_tuple_for_user_id(self, user_id):
        """
        Gets login tuple for the user with the given user ID.
        The user is assumed to have been authenticated by some other
        machanism (e.g. CAS)

        Args:
            user_id (str): User ID
        Returns:
            A tuple of:
              The user's ID.
              The access token for the user's session.
              The refresh token for the user's session.
        Raises:
            StoreError if there was a problem storing the token.
            LoginError if there was an authentication problem.
        """
        user_id, ignored = yield self._find_user_id_and_pwd_hash(user_id)

        logger.info("Logging in user %s", user_id)
        access_token = yield self.issue_access_token(user_id)
        refresh_token = yield self.issue_refresh_token(user_id)
        defer.returnValue((user_id, access_token, refresh_token))

    @defer.inlineCallbacks
    def does_user_exist(self, user_id):
        try:
            yield self._find_user_id_and_pwd_hash(user_id)
            defer.returnValue(True)
        except LoginError:
            defer.returnValue(False)

    @defer.inlineCallbacks
    def _find_user_id_and_pwd_hash(self, user_id):
        """Checks to see if a user with the given id exists. Will check case
        insensitively, but will throw if there are multiple inexact matches.

        Returns:
            tuple: A 2-tuple of `(canonical_user_id, password_hash)`
        """
        user_infos = yield self.store.get_users_by_id_case_insensitive(user_id)
        if not user_infos:
            logger.warn("Attempted to login as %s but they do not exist", user_id)
            raise LoginError(403, "", errcode=Codes.FORBIDDEN)

        if len(user_infos) > 1:
            if user_id not in user_infos:
                logger.warn(
                    "Attempted to login as %s but it matches more than one user "
                    "inexactly: %r",
                    user_id, user_infos.keys()
                )
                raise LoginError(403, "", errcode=Codes.FORBIDDEN)

            defer.returnValue((user_id, user_infos[user_id]))
        else:
            defer.returnValue(user_infos.popitem())

    @defer.inlineCallbacks
    def _check_password(self, user_id, password):
        """
        Returns:
            True if the user_id successfully authenticated
        """
        valid_ldap = yield self._check_ldap_password(user_id, password)
        if valid_ldap:
            defer.returnValue(True)

        valid_local_password = yield self._check_local_password(user_id, password)
        if valid_local_password:
            defer.returnValue(True)

        defer.returnValue(False)

    @defer.inlineCallbacks
    def _check_local_password(self, user_id, password):
        try:
            user_id, password_hash = yield self._find_user_id_and_pwd_hash(user_id)
            defer.returnValue(self.validate_hash(password, password_hash))
        except LoginError:
            defer.returnValue(False)

    @defer.inlineCallbacks
    def _check_ldap_password(self, user_id, password):
        if not self.ldap_enabled:
            logger.debug("LDAP not configured")
            defer.returnValue(False)

        import ldap

        logger.info("Authenticating %s with LDAP" % user_id)
        try:
            ldap_url = "%s:%s" % (self.ldap_server, self.ldap_port)
            logger.debug("Connecting LDAP server at %s" % ldap_url)
            l = ldap.initialize(ldap_url)
            if self.ldap_tls:
                logger.debug("Initiating TLS")
                self._connection.start_tls_s()

            local_name = UserID.from_string(user_id).localpart

            dn = "%s=%s, %s" % (
                self.ldap_search_property,
                local_name,
                self.ldap_search_base)
            logger.debug("DN for LDAP authentication: %s" % dn)

            l.simple_bind_s(dn.encode('utf-8'), password.encode('utf-8'))

            if not (yield self.does_user_exist(user_id)):
                handler = self.hs.get_handlers().registration_handler
                user_id, access_token = (
                    yield handler.register(localpart=local_name)
                )

            defer.returnValue(True)
        except ldap.LDAPError, e:
            logger.warn("LDAP error: %s", e)
            defer.returnValue(False)

    @defer.inlineCallbacks
    def issue_access_token(self, user_id):
        access_token = self.generate_access_token(user_id)
        yield self.store.add_access_token_to_user(user_id, access_token)
        defer.returnValue(access_token)

    @defer.inlineCallbacks
    def issue_refresh_token(self, user_id):
        refresh_token = self.generate_refresh_token(user_id)
        yield self.store.add_refresh_token_to_user(user_id, refresh_token)
        defer.returnValue(refresh_token)

    def generate_access_token(self, user_id, extra_caveats=None):
        extra_caveats = extra_caveats or []
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = access")
        now = self.hs.get_clock().time_msec()
        expiry = now + (60 * 60 * 1000)
        macaroon.add_first_party_caveat("time < %d" % (expiry,))
        for caveat in extra_caveats:
            macaroon.add_first_party_caveat(caveat)
        return macaroon.serialize()

    def generate_refresh_token(self, user_id):
        m = self._generate_base_macaroon(user_id)
        m.add_first_party_caveat("type = refresh")
        # Important to add a nonce, because otherwise every refresh token for a
        # user will be the same.
        m.add_first_party_caveat("nonce = %s" % (
            stringutils.random_string_with_symbols(16),
        ))
        return m.serialize()

    def generate_short_term_login_token(self, user_id):
        macaroon = self._generate_base_macaroon(user_id)
        macaroon.add_first_party_caveat("type = login")
        now = self.hs.get_clock().time_msec()
        expiry = now + (2 * 60 * 1000)
        macaroon.add_first_party_caveat("time < %d" % (expiry,))
        return macaroon.serialize()

    def validate_short_term_login_token_and_get_user_id(self, login_token):
        try:
            macaroon = pymacaroons.Macaroon.deserialize(login_token)
            auth_api = self.hs.get_auth()
            auth_api.validate_macaroon(macaroon, "login", True)
            return self.get_user_from_macaroon(macaroon)
        except (pymacaroons.exceptions.MacaroonException, TypeError, ValueError):
            raise AuthError(401, "Invalid token", errcode=Codes.UNKNOWN_TOKEN)

    def _generate_base_macaroon(self, user_id):
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key)
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        return macaroon

    def get_user_from_macaroon(self, macaroon):
        user_prefix = "user_id = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(user_prefix):
                return caveat.caveat_id[len(user_prefix):]
        raise AuthError(
            self.INVALID_TOKEN_HTTP_STATUS, "No user_id found in token",
            errcode=Codes.UNKNOWN_TOKEN
        )

    @defer.inlineCallbacks
    def set_password(self, user_id, newpassword, requester=None):
        password_hash = self.hash(newpassword)

        except_access_token_ids = [requester.access_token_id] if requester else []

        yield self.store.user_set_password_hash(user_id, password_hash)
        yield self.store.user_delete_access_tokens(
            user_id, except_access_token_ids
        )
        yield self.hs.get_pusherpool().remove_pushers_by_user(
            user_id, except_access_token_ids
        )

    @defer.inlineCallbacks
    def add_threepid(self, user_id, medium, address, validated_at):
        yield self.store.user_add_threepid(
            user_id, medium, address, validated_at,
            self.hs.get_clock().time_msec()
        )

    def _save_session(self, session):
        # TODO: Persistent storage
        logger.debug("Saving session %s", session)
        session["last_used"] = self.hs.get_clock().time_msec()
        self.sessions[session["id"]] = session
        self._prune_sessions()

    def _prune_sessions(self):
        for sid, sess in self.sessions.items():
            last_used = 0
            if 'last_used' in sess:
                last_used = sess['last_used']
            now = self.hs.get_clock().time_msec()
            if last_used < now - AuthHandler.SESSION_EXPIRE_MS:
                del self.sessions[sid]

    def hash(self, password):
        """Computes a secure hash of password.

        Args:
            password (str): Password to hash.

        Returns:
            Hashed password (str).
        """
        return bcrypt.hashpw(password, bcrypt.gensalt(self.bcrypt_rounds))

    def validate_hash(self, password, stored_hash):
        """Validates that self.hash(password) == stored_hash.

        Args:
            password (str): Password to hash.
            stored_hash (str): Expected hash value.

        Returns:
            Whether self.hash(password) == stored_hash (bool).
        """
        return bcrypt.hashpw(password, stored_hash) == stored_hash
