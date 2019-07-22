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

import logging

from six import itervalues

import pymacaroons
from netaddr import IPAddress

from twisted.internet import defer

import synapse.types
from synapse import event_auth
from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientTokenError,
    MissingClientTokenError,
    ResourceLimitError,
)
from synapse.config.server import is_threepid_reserved
from synapse.types import UserID
from synapse.util.caches import CACHE_SIZE_FACTOR, register_cache
from synapse.util.caches.lrucache import LruCache
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


AuthEventTypes = (
    EventTypes.Create,
    EventTypes.Member,
    EventTypes.PowerLevels,
    EventTypes.JoinRules,
    EventTypes.RoomHistoryVisibility,
    EventTypes.ThirdPartyInvite,
)

# guests always get this device id.
GUEST_DEVICE_ID = "guest_device"


class _InvalidMacaroonException(Exception):
    pass


class Auth(object):
    """
    FIXME: This class contains a mix of functions for authenticating users
    of our client-server API and authenticating events added to room graphs.
    """

    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()

        self.token_cache = LruCache(CACHE_SIZE_FACTOR * 10000)
        register_cache("cache", "token_cache", self.token_cache)

        self._account_validity = hs.config.account_validity

    @defer.inlineCallbacks
    def check_from_context(self, room_version, event, context, do_sig_check=True):
        prev_state_ids = yield context.get_prev_state_ids(self.store)
        auth_events_ids = yield self.compute_auth_events(
            event, prev_state_ids, for_verification=True
        )
        auth_events = yield self.store.get_events(auth_events_ids)
        auth_events = {(e.type, e.state_key): e for e in itervalues(auth_events)}
        self.check(
            room_version, event, auth_events=auth_events, do_sig_check=do_sig_check
        )

    def check(self, room_version, event, auth_events, do_sig_check=True):
        """ Checks if this event is correctly authed.

        Args:
            room_version (str): version of the room
            event: the event being checked.
            auth_events (dict: event-key -> event): the existing room state.


        Returns:
            True if the auth checks pass.
        """
        with Measure(self.clock, "auth.check"):
            event_auth.check(
                room_version, event, auth_events, do_sig_check=do_sig_check
            )

    @defer.inlineCallbacks
    def check_joined_room(self, room_id, user_id, current_state=None):
        """Check if the user is currently joined in the room
        Args:
            room_id(str): The room to check.
            user_id(str): The user to check.
            current_state(dict): Optional map of the current state of the room.
                If provided then that map is used to check whether they are a
                member of the room. Otherwise the current membership is
                loaded from the database.
        Raises:
            AuthError if the user is not in the room.
        Returns:
            A deferred membership event for the user if the user is in
            the room.
        """
        if current_state:
            member = current_state.get((EventTypes.Member, user_id), None)
        else:
            member = yield self.state.get_current_state(
                room_id=room_id, event_type=EventTypes.Member, state_key=user_id
            )

        self._check_joined_room(member, user_id, room_id)
        return member

    @defer.inlineCallbacks
    def check_user_was_in_room(self, room_id, user_id):
        """Check if the user was in the room at some point.
        Args:
            room_id(str): The room to check.
            user_id(str): The user to check.
        Raises:
            AuthError if the user was never in the room.
        Returns:
            A deferred membership event for the user if the user was in the
            room. This will be the join event if they are currently joined to
            the room. This will be the leave event if they have left the room.
        """
        member = yield self.state.get_current_state(
            room_id=room_id, event_type=EventTypes.Member, state_key=user_id
        )
        membership = member.membership if member else None

        if membership not in (Membership.JOIN, Membership.LEAVE):
            raise AuthError(403, "User %s not in room %s" % (user_id, room_id))

        if membership == Membership.LEAVE:
            forgot = yield self.store.did_forget(user_id, room_id)
            if forgot:
                raise AuthError(403, "User %s not in room %s" % (user_id, room_id))

        return member

    @defer.inlineCallbacks
    def check_host_in_room(self, room_id, host):
        with Measure(self.clock, "check_host_in_room"):
            latest_event_ids = yield self.store.is_host_joined(room_id, host)
            return latest_event_ids

    def _check_joined_room(self, member, user_id, room_id):
        if not member or member.membership != Membership.JOIN:
            raise AuthError(
                403, "User %s not in room %s (%s)" % (user_id, room_id, repr(member))
            )

    def can_federate(self, event, auth_events):
        creation_event = auth_events.get((EventTypes.Create, ""))

        return creation_event.content.get("m.federate", True) is True

    def get_public_keys(self, invite_event):
        return event_auth.get_public_keys(invite_event)

    @defer.inlineCallbacks
    def get_user_by_req(
        self, request, allow_guest=False, rights="access", allow_expired=False
    ):
        """ Get a registered user's ID.

        Args:
            request - An HTTP request with an access_token query parameter.
            allow_expired - Whether to allow the request through even if the account is
                expired. If true, Synapse will still require an access token to be
                provided but won't check if the account it belongs to has expired. This
                works thanks to /login delivering access tokens regardless of accounts'
                expiration.
        Returns:
            defer.Deferred: resolves to a ``synapse.types.Requester`` object
        Raises:
            InvalidClientCredentialsError if no user by that token exists or the token
                is invalid.
            AuthError if access is denied for the user in the access token
        """
        try:
            ip_addr = self.hs.get_ip_from_request(request)
            user_agent = request.requestHeaders.getRawHeaders(
                b"User-Agent", default=[b""]
            )[0].decode("ascii", "surrogateescape")

            access_token = self.get_access_token_from_request(request)

            user_id, app_service = yield self._get_appservice_user_id(request)
            if user_id:
                request.authenticated_entity = user_id

                if ip_addr and self.hs.config.track_appservice_user_ips:
                    yield self.store.insert_client_ip(
                        user_id=user_id,
                        access_token=access_token,
                        ip=ip_addr,
                        user_agent=user_agent,
                        device_id="dummy-device",  # stubbed
                    )

                defer.returnValue(
                    synapse.types.create_requester(user_id, app_service=app_service)
                )

            user_info = yield self.get_user_by_access_token(access_token, rights)
            user = user_info["user"]
            token_id = user_info["token_id"]
            is_guest = user_info["is_guest"]

            # Deny the request if the user account has expired.
            if self._account_validity.enabled and not allow_expired:
                user_id = user.to_string()
                expiration_ts = yield self.store.get_expiration_ts_for_user(user_id)
                if (
                    expiration_ts is not None
                    and self.clock.time_msec() >= expiration_ts
                ):
                    raise AuthError(
                        403, "User account has expired", errcode=Codes.EXPIRED_ACCOUNT
                    )

            # device_id may not be present if get_user_by_access_token has been
            # stubbed out.
            device_id = user_info.get("device_id")

            if user and access_token and ip_addr:
                yield self.store.insert_client_ip(
                    user_id=user.to_string(),
                    access_token=access_token,
                    ip=ip_addr,
                    user_agent=user_agent,
                    device_id=device_id,
                )

            if is_guest and not allow_guest:
                raise AuthError(
                    403,
                    "Guest access not allowed",
                    errcode=Codes.GUEST_ACCESS_FORBIDDEN,
                )

            request.authenticated_entity = user.to_string()

            defer.returnValue(
                synapse.types.create_requester(
                    user, token_id, is_guest, device_id, app_service=app_service
                )
            )
        except KeyError:
            raise MissingClientTokenError()

    @defer.inlineCallbacks
    def _get_appservice_user_id(self, request):
        app_service = self.store.get_app_service_by_token(
            self.get_access_token_from_request(request)
        )
        if app_service is None:
            return (None, None)

        if app_service.ip_range_whitelist:
            ip_address = IPAddress(self.hs.get_ip_from_request(request))
            if ip_address not in app_service.ip_range_whitelist:
                return (None, None)

        if b"user_id" not in request.args:
            return (app_service.sender, app_service)

        user_id = request.args[b"user_id"][0].decode("utf8")
        if app_service.sender == user_id:
            return (app_service.sender, app_service)

        if not app_service.is_interested_in_user(user_id):
            raise AuthError(403, "Application service cannot masquerade as this user.")
        if not (yield self.store.get_user_by_id(user_id)):
            raise AuthError(403, "Application service has not registered this user")
        return (user_id, app_service)

    @defer.inlineCallbacks
    def get_user_by_access_token(self, token, rights="access"):
        """ Validate access token and get user_id from it

        Args:
            token (str): The access token to get the user by.
            rights (str): The operation being performed; the access token must
                allow this.
        Returns:
            Deferred[dict]: dict that includes:
               `user` (UserID)
               `is_guest` (bool)
               `token_id` (int|None): access token id. May be None if guest
               `device_id` (str|None): device corresponding to access token
        Raises:
            InvalidClientCredentialsError if no user by that token exists or the token
                is invalid.
        """

        if rights == "access":
            # first look in the database
            r = yield self._look_up_user_by_access_token(token)
            if r:
                valid_until_ms = r["valid_until_ms"]
                if (
                    valid_until_ms is not None
                    and valid_until_ms < self.clock.time_msec()
                ):
                    # there was a valid access token, but it has expired.
                    # soft-logout the user.
                    raise InvalidClientTokenError(
                        msg="Access token has expired", soft_logout=True
                    )

                return r

        # otherwise it needs to be a valid macaroon
        try:
            user_id, guest = self._parse_and_validate_macaroon(token, rights)
            user = UserID.from_string(user_id)

            if rights == "access":
                if not guest:
                    # non-guest access tokens must be in the database
                    logger.warning("Unrecognised access token - not in store.")
                    raise InvalidClientTokenError()

                # Guest access tokens are not stored in the database (there can
                # only be one access token per guest, anyway).
                #
                # In order to prevent guest access tokens being used as regular
                # user access tokens (and hence getting around the invalidation
                # process), we look up the user id and check that it is indeed
                # a guest user.
                #
                # It would of course be much easier to store guest access
                # tokens in the database as well, but that would break existing
                # guest tokens.
                stored_user = yield self.store.get_user_by_id(user_id)
                if not stored_user:
                    raise InvalidClientTokenError("Unknown user_id %s" % user_id)
                if not stored_user["is_guest"]:
                    raise InvalidClientTokenError(
                        "Guest access token used for regular user"
                    )
                ret = {
                    "user": user,
                    "is_guest": True,
                    "token_id": None,
                    # all guests get the same device id
                    "device_id": GUEST_DEVICE_ID,
                }
            elif rights == "delete_pusher":
                # We don't store these tokens in the database
                ret = {
                    "user": user,
                    "is_guest": False,
                    "token_id": None,
                    "device_id": None,
                }
            else:
                raise RuntimeError("Unknown rights setting %s", rights)
            return ret
        except (
            _InvalidMacaroonException,
            pymacaroons.exceptions.MacaroonException,
            TypeError,
            ValueError,
        ) as e:
            logger.warning("Invalid macaroon in auth: %s %s", type(e), e)
            raise InvalidClientTokenError("Invalid macaroon passed.")

    def _parse_and_validate_macaroon(self, token, rights="access"):
        """Takes a macaroon and tries to parse and validate it. This is cached
        if and only if rights == access and there isn't an expiry.

        On invalid macaroon raises _InvalidMacaroonException

        Returns:
            (user_id, is_guest)
        """
        if rights == "access":
            cached = self.token_cache.get(token, None)
            if cached:
                return cached

        try:
            macaroon = pymacaroons.Macaroon.deserialize(token)
        except Exception:  # deserialize can throw more-or-less anything
            # doesn't look like a macaroon: treat it as an opaque token which
            # must be in the database.
            # TODO: it would be nice to get rid of this, but apparently some
            # people use access tokens which aren't macaroons
            raise _InvalidMacaroonException()

        try:
            user_id = self.get_user_id_from_macaroon(macaroon)

            has_expiry = False
            guest = False
            for caveat in macaroon.caveats:
                if caveat.caveat_id.startswith("time "):
                    has_expiry = True
                elif caveat.caveat_id == "guest = true":
                    guest = True

            self.validate_macaroon(
                macaroon, rights, self.hs.config.expire_access_token, user_id=user_id
            )
        except (pymacaroons.exceptions.MacaroonException, TypeError, ValueError):
            raise InvalidClientTokenError("Invalid macaroon passed.")

        if not has_expiry and rights == "access":
            self.token_cache[token] = (user_id, guest)

        return user_id, guest

    def get_user_id_from_macaroon(self, macaroon):
        """Retrieve the user_id given by the caveats on the macaroon.

        Does *not* validate the macaroon.

        Args:
            macaroon (pymacaroons.Macaroon): The macaroon to validate

        Returns:
            (str) user id

        Raises:
            InvalidClientCredentialsError if there is no user_id caveat in the
                macaroon
        """
        user_prefix = "user_id = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(user_prefix):
                return caveat.caveat_id[len(user_prefix) :]
        raise InvalidClientTokenError("No user caveat in macaroon")

    def validate_macaroon(self, macaroon, type_string, verify_expiry, user_id):
        """
        validate that a Macaroon is understood by and was signed by this server.

        Args:
            macaroon(pymacaroons.Macaroon): The macaroon to validate
            type_string(str): The kind of token required (e.g. "access",
                              "delete_pusher")
            verify_expiry(bool): Whether to verify whether the macaroon has expired.
            user_id (str): The user_id required
        """
        v = pymacaroons.Verifier()

        # the verifier runs a test for every caveat on the macaroon, to check
        # that it is met for the current request. Each caveat must match at
        # least one of the predicates specified by satisfy_exact or
        # specify_general.
        v.satisfy_exact("gen = 1")
        v.satisfy_exact("type = " + type_string)
        v.satisfy_exact("user_id = %s" % user_id)
        v.satisfy_exact("guest = true")

        # verify_expiry should really always be True, but there exist access
        # tokens in the wild which expire when they should not, so we can't
        # enforce expiry yet (so we have to allow any caveat starting with
        # 'time < ' in access tokens).
        #
        # On the other hand, short-term login tokens (as used by CAS login, for
        # example) have an expiry time which we do want to enforce.

        if verify_expiry:
            v.satisfy_general(self._verify_expiry)
        else:
            v.satisfy_general(lambda c: c.startswith("time < "))

        # access_tokens include a nonce for uniqueness: any value is acceptable
        v.satisfy_general(lambda c: c.startswith("nonce = "))

        v.verify(macaroon, self.hs.config.macaroon_secret_key)

    def _verify_expiry(self, caveat):
        prefix = "time < "
        if not caveat.startswith(prefix):
            return False
        expiry = int(caveat[len(prefix) :])
        now = self.hs.get_clock().time_msec()
        return now < expiry

    @defer.inlineCallbacks
    def _look_up_user_by_access_token(self, token):
        ret = yield self.store.get_user_by_access_token(token)
        if not ret:
            return None

        # we use ret.get() below because *lots* of unit tests stub out
        # get_user_by_access_token in a way where it only returns a couple of
        # the fields.
        user_info = {
            "user": UserID.from_string(ret.get("name")),
            "token_id": ret.get("token_id", None),
            "is_guest": False,
            "device_id": ret.get("device_id"),
            "valid_until_ms": ret.get("valid_until_ms"),
        }
        return user_info

    def get_appservice_by_req(self, request):
        token = self.get_access_token_from_request(request)
        service = self.store.get_app_service_by_token(token)
        if not service:
            logger.warn("Unrecognised appservice access token.")
            raise InvalidClientTokenError()
        request.authenticated_entity = service.sender
        return defer.succeed(service)

    def is_server_admin(self, user):
        """ Check if the given user is a local server admin.

        Args:
            user (UserID): user to check

        Returns:
            bool: True if the user is an admin
        """
        return self.store.is_server_admin(user)

    @defer.inlineCallbacks
    def compute_auth_events(self, event, current_state_ids, for_verification=False):
        if event.type == EventTypes.Create:
            return []

        auth_ids = []

        key = (EventTypes.PowerLevels, "")
        power_level_event_id = current_state_ids.get(key)

        if power_level_event_id:
            auth_ids.append(power_level_event_id)

        key = (EventTypes.JoinRules, "")
        join_rule_event_id = current_state_ids.get(key)

        key = (EventTypes.Member, event.sender)
        member_event_id = current_state_ids.get(key)

        key = (EventTypes.Create, "")
        create_event_id = current_state_ids.get(key)
        if create_event_id:
            auth_ids.append(create_event_id)

        if join_rule_event_id:
            join_rule_event = yield self.store.get_event(join_rule_event_id)
            join_rule = join_rule_event.content.get("join_rule")
            is_public = join_rule == JoinRules.PUBLIC if join_rule else False
        else:
            is_public = False

        if event.type == EventTypes.Member:
            e_type = event.content["membership"]
            if e_type in [Membership.JOIN, Membership.INVITE]:
                if join_rule_event_id:
                    auth_ids.append(join_rule_event_id)

            if e_type == Membership.JOIN:
                if member_event_id and not is_public:
                    auth_ids.append(member_event_id)
            else:
                if member_event_id:
                    auth_ids.append(member_event_id)

                if for_verification:
                    key = (EventTypes.Member, event.state_key)
                    existing_event_id = current_state_ids.get(key)
                    if existing_event_id:
                        auth_ids.append(existing_event_id)

            if e_type == Membership.INVITE:
                if "third_party_invite" in event.content:
                    key = (
                        EventTypes.ThirdPartyInvite,
                        event.content["third_party_invite"]["signed"]["token"],
                    )
                    third_party_invite_id = current_state_ids.get(key)
                    if third_party_invite_id:
                        auth_ids.append(third_party_invite_id)
        elif member_event_id:
            member_event = yield self.store.get_event(member_event_id)
            if member_event.content["membership"] == Membership.JOIN:
                auth_ids.append(member_event.event_id)

        return auth_ids

    @defer.inlineCallbacks
    def check_can_change_room_list(self, room_id, user):
        """Check if the user is allowed to edit the room's entry in the
        published room list.

        Args:
            room_id (str)
            user (UserID)
        """

        is_admin = yield self.is_server_admin(user)
        if is_admin:
            return True

        user_id = user.to_string()
        yield self.check_joined_room(room_id, user_id)

        # We currently require the user is a "moderator" in the room. We do this
        # by checking if they would (theoretically) be able to change the
        # m.room.aliases events
        power_level_event = yield self.state.get_current_state(
            room_id, EventTypes.PowerLevels, ""
        )

        auth_events = {}
        if power_level_event:
            auth_events[(EventTypes.PowerLevels, "")] = power_level_event

        send_level = event_auth.get_send_level(
            EventTypes.Aliases, "", power_level_event
        )
        user_level = event_auth.get_user_power_level(user_id, auth_events)

        if user_level < send_level:
            raise AuthError(
                403,
                "This server requires you to be a moderator in the room to"
                " edit its room list entry",
            )

    @staticmethod
    def has_access_token(request):
        """Checks if the request has an access_token.

        Returns:
            bool: False if no access_token was given, True otherwise.
        """
        query_params = request.args.get(b"access_token")
        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
        return bool(query_params) or bool(auth_headers)

    @staticmethod
    def get_access_token_from_request(request):
        """Extracts the access_token from the request.

        Args:
            request: The http request.
        Returns:
            unicode: The access_token
        Raises:
            MissingClientTokenError: If there isn't a single access_token in the
                request
        """

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
        query_params = request.args.get(b"access_token")
        if auth_headers:
            # Try the get the access_token from a "Authorization: Bearer"
            # header
            if query_params is not None:
                raise MissingClientTokenError(
                    "Mixing Authorization headers and access_token query parameters."
                )
            if len(auth_headers) > 1:
                raise MissingClientTokenError("Too many Authorization headers.")
            parts = auth_headers[0].split(b" ")
            if parts[0] == b"Bearer" and len(parts) == 2:
                return parts[1].decode("ascii")
            else:
                raise MissingClientTokenError("Invalid Authorization header.")
        else:
            # Try to get the access_token from the query params.
            if not query_params:
                raise MissingClientTokenError()

            return query_params[0].decode("ascii")

    @defer.inlineCallbacks
    def check_in_room_or_world_readable(self, room_id, user_id):
        """Checks that the user is or was in the room or the room is world
        readable. If it isn't then an exception is raised.

        Returns:
            Deferred[tuple[str, str|None]]: Resolves to the current membership of
                the user in the room and the membership event ID of the user. If
                the user is not in the room and never has been, then
                `(Membership.JOIN, None)` is returned.
        """

        try:
            # check_user_was_in_room will return the most recent membership
            # event for the user if:
            #  * The user is a non-guest user, and was ever in the room
            #  * The user is a guest user, and has joined the room
            # else it will throw.
            member_event = yield self.check_user_was_in_room(room_id, user_id)
            return (member_event.membership, member_event.event_id)
        except AuthError:
            visibility = yield self.state.get_current_state(
                room_id, EventTypes.RoomHistoryVisibility, ""
            )
            if (
                visibility
                and visibility.content["history_visibility"] == "world_readable"
            ):
                return (Membership.JOIN, None)
                return
            raise AuthError(
                403, "Guest access not allowed", errcode=Codes.GUEST_ACCESS_FORBIDDEN
            )

    @defer.inlineCallbacks
    def check_auth_blocking(self, user_id=None, threepid=None):
        """Checks if the user should be rejected for some external reason,
        such as monthly active user limiting or global disable flag

        Args:
            user_id(str|None): If present, checks for presence against existing
                MAU cohort

            threepid(dict|None): If present, checks for presence against configured
                reserved threepid. Used in cases where the user is trying register
                with a MAU blocked server, normally they would be rejected but their
                threepid is on the reserved list. user_id and
                threepid should never be set at the same time.
        """

        # Never fail an auth check for the server notices users or support user
        # This can be a problem where event creation is prohibited due to blocking
        if user_id is not None:
            if user_id == self.hs.config.server_notices_mxid:
                return
            if (yield self.store.is_support_user(user_id)):
                return

        if self.hs.config.hs_disabled:
            raise ResourceLimitError(
                403,
                self.hs.config.hs_disabled_message,
                errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
                admin_contact=self.hs.config.admin_contact,
                limit_type=self.hs.config.hs_disabled_limit_type,
            )
        if self.hs.config.limit_usage_by_mau is True:
            assert not (user_id and threepid)

            # If the user is already part of the MAU cohort or a trial user
            if user_id:
                timestamp = yield self.store.user_last_seen_monthly_active(user_id)
                if timestamp:
                    return

                is_trial = yield self.store.is_trial_user(user_id)
                if is_trial:
                    return
            elif threepid:
                # If the user does not exist yet, but is signing up with a
                # reserved threepid then pass auth check
                if is_threepid_reserved(
                    self.hs.config.mau_limits_reserved_threepids, threepid
                ):
                    return
            # Else if there is no room in the MAU bucket, bail
            current_mau = yield self.store.get_monthly_active_count()
            if current_mau >= self.hs.config.max_mau_value:
                raise ResourceLimitError(
                    403,
                    "Monthly Active User Limit Exceeded",
                    admin_contact=self.hs.config.admin_contact,
                    errcode=Codes.RESOURCE_LIMIT_EXCEEDED,
                    limit_type="monthly_active_user",
                )
