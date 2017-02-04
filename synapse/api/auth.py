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

import pymacaroons
from twisted.internet import defer

import synapse.types
from synapse import event_auth
from synapse.api.constants import EventTypes, Membership, JoinRules
from synapse.api.errors import AuthError, Codes
from synapse.types import UserID
from synapse.util.logcontext import preserve_context_over_fn
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


AuthEventTypes = (
    EventTypes.Create, EventTypes.Member, EventTypes.PowerLevels,
    EventTypes.JoinRules, EventTypes.RoomHistoryVisibility,
    EventTypes.ThirdPartyInvite,
)

# guests always get this device id.
GUEST_DEVICE_ID = "guest_device"


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
        self.TOKEN_NOT_FOUND_HTTP_STATUS = 401

    @defer.inlineCallbacks
    def check_from_context(self, event, context, do_sig_check=True):
        auth_events_ids = yield self.compute_auth_events(
            event, context.prev_state_ids, for_verification=True,
        )
        auth_events = yield self.store.get_events(auth_events_ids)
        auth_events = {
            (e.type, e.state_key): e for e in auth_events.values()
        }
        self.check(event, auth_events=auth_events, do_sig_check=do_sig_check)

    def check(self, event, auth_events, do_sig_check=True):
        """ Checks if this event is correctly authed.

        Args:
            event: the event being checked.
            auth_events (dict: event-key -> event): the existing room state.


        Returns:
            True if the auth checks pass.
        """
        with Measure(self.clock, "auth.check"):
            event_auth.check(event, auth_events, do_sig_check=do_sig_check)

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
            member = current_state.get(
                (EventTypes.Member, user_id),
                None
            )
        else:
            member = yield self.state.get_current_state(
                room_id=room_id,
                event_type=EventTypes.Member,
                state_key=user_id
            )

        self._check_joined_room(member, user_id, room_id)
        defer.returnValue(member)

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
            room_id=room_id,
            event_type=EventTypes.Member,
            state_key=user_id
        )
        membership = member.membership if member else None

        if membership not in (Membership.JOIN, Membership.LEAVE):
            raise AuthError(403, "User %s not in room %s" % (
                user_id, room_id
            ))

        if membership == Membership.LEAVE:
            forgot = yield self.store.did_forget(user_id, room_id)
            if forgot:
                raise AuthError(403, "User %s not in room %s" % (
                    user_id, room_id
                ))

        defer.returnValue(member)

    @defer.inlineCallbacks
    def check_host_in_room(self, room_id, host):
        with Measure(self.clock, "check_host_in_room"):
            latest_event_ids = yield self.store.get_latest_event_ids_in_room(room_id)

            logger.debug("calling resolve_state_groups from check_host_in_room")
            entry = yield self.state.resolve_state_groups(
                room_id, latest_event_ids
            )

            ret = yield self.store.is_host_joined(
                room_id, host, entry.state_group, entry.state
            )
            defer.returnValue(ret)

    def _check_joined_room(self, member, user_id, room_id):
        if not member or member.membership != Membership.JOIN:
            raise AuthError(403, "User %s not in room %s (%s)" % (
                user_id, room_id, repr(member)
            ))

    def can_federate(self, event, auth_events):
        creation_event = auth_events.get((EventTypes.Create, ""))

        return creation_event.content.get("m.federate", True) is True

    def get_public_keys(self, invite_event):
        return event_auth.get_public_keys(invite_event)

    @defer.inlineCallbacks
    def get_user_by_req(self, request, allow_guest=False, rights="access"):
        """ Get a registered user's ID.

        Args:
            request - An HTTP request with an access_token query parameter.
        Returns:
            defer.Deferred: resolves to a ``synapse.types.Requester`` object
        Raises:
            AuthError if no user by that token exists or the token is invalid.
        """
        # Can optionally look elsewhere in the request (e.g. headers)
        try:
            user_id, app_service = yield self._get_appservice_user_id(request)
            if user_id:
                request.authenticated_entity = user_id
                defer.returnValue(
                    synapse.types.create_requester(user_id, app_service=app_service)
                )

            access_token = get_access_token_from_request(
                request, self.TOKEN_NOT_FOUND_HTTP_STATUS
            )

            user_info = yield self.get_user_by_access_token(access_token, rights)
            user = user_info["user"]
            token_id = user_info["token_id"]
            is_guest = user_info["is_guest"]

            # device_id may not be present if get_user_by_access_token has been
            # stubbed out.
            device_id = user_info.get("device_id")

            ip_addr = self.hs.get_ip_from_request(request)
            user_agent = request.requestHeaders.getRawHeaders(
                "User-Agent",
                default=[""]
            )[0]
            if user and access_token and ip_addr:
                preserve_context_over_fn(
                    self.store.insert_client_ip,
                    user=user,
                    access_token=access_token,
                    ip=ip_addr,
                    user_agent=user_agent,
                    device_id=device_id,
                )

            if is_guest and not allow_guest:
                raise AuthError(
                    403, "Guest access not allowed", errcode=Codes.GUEST_ACCESS_FORBIDDEN
                )

            request.authenticated_entity = user.to_string()

            defer.returnValue(synapse.types.create_requester(
                user, token_id, is_guest, device_id, app_service=app_service)
            )
        except KeyError:
            raise AuthError(
                self.TOKEN_NOT_FOUND_HTTP_STATUS, "Missing access token.",
                errcode=Codes.MISSING_TOKEN
            )

    @defer.inlineCallbacks
    def _get_appservice_user_id(self, request):
        app_service = self.store.get_app_service_by_token(
            get_access_token_from_request(
                request, self.TOKEN_NOT_FOUND_HTTP_STATUS
            )
        )
        if app_service is None:
            defer.returnValue((None, None))

        if "user_id" not in request.args:
            defer.returnValue((app_service.sender, app_service))

        user_id = request.args["user_id"][0]
        if app_service.sender == user_id:
            defer.returnValue((app_service.sender, app_service))

        if not app_service.is_interested_in_user(user_id):
            raise AuthError(
                403,
                "Application service cannot masquerade as this user."
            )
        if not (yield self.store.get_user_by_id(user_id)):
            raise AuthError(
                403,
                "Application service has not registered this user"
            )
        defer.returnValue((user_id, app_service))

    @defer.inlineCallbacks
    def get_user_by_access_token(self, token, rights="access"):
        """ Validate access token and get user_id from it

        Args:
            token (str): The access token to get the user by.
            rights (str): The operation being performed; the access token must
                allow this.
        Returns:
            dict : dict that includes the user and the ID of their access token.
        Raises:
            AuthError if no user by that token exists or the token is invalid.
        """
        try:
            macaroon = pymacaroons.Macaroon.deserialize(token)
        except Exception:  # deserialize can throw more-or-less anything
            # doesn't look like a macaroon: treat it as an opaque token which
            # must be in the database.
            # TODO: it would be nice to get rid of this, but apparently some
            # people use access tokens which aren't macaroons
            r = yield self._look_up_user_by_access_token(token)
            defer.returnValue(r)

        try:
            user_id = self.get_user_id_from_macaroon(macaroon)
            user = UserID.from_string(user_id)

            self.validate_macaroon(
                macaroon, rights, self.hs.config.expire_access_token,
                user_id=user_id,
            )

            guest = False
            for caveat in macaroon.caveats:
                if caveat.caveat_id == "guest = true":
                    guest = True

            if guest:
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
                    raise AuthError(
                        self.TOKEN_NOT_FOUND_HTTP_STATUS,
                        "Unknown user_id %s" % user_id,
                        errcode=Codes.UNKNOWN_TOKEN
                    )
                if not stored_user["is_guest"]:
                    raise AuthError(
                        self.TOKEN_NOT_FOUND_HTTP_STATUS,
                        "Guest access token used for regular user",
                        errcode=Codes.UNKNOWN_TOKEN
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
                # This codepath exists for several reasons:
                #   * so that we can actually return a token ID, which is used
                #     in some parts of the schema (where we probably ought to
                #     use device IDs instead)
                #   * the only way we currently have to invalidate an
                #     access_token is by removing it from the database, so we
                #     have to check here that it is still in the db
                #   * some attributes (notably device_id) aren't stored in the
                #     macaroon. They probably should be.
                # TODO: build the dictionary from the macaroon once the
                # above are fixed
                ret = yield self._look_up_user_by_access_token(token)
                if ret["user"] != user:
                    logger.error(
                        "Macaroon user (%s) != DB user (%s)",
                        user,
                        ret["user"]
                    )
                    raise AuthError(
                        self.TOKEN_NOT_FOUND_HTTP_STATUS,
                        "User mismatch in macaroon",
                        errcode=Codes.UNKNOWN_TOKEN
                    )
            defer.returnValue(ret)
        except (pymacaroons.exceptions.MacaroonException, TypeError, ValueError):
            raise AuthError(
                self.TOKEN_NOT_FOUND_HTTP_STATUS, "Invalid macaroon passed.",
                errcode=Codes.UNKNOWN_TOKEN
            )

    def get_user_id_from_macaroon(self, macaroon):
        """Retrieve the user_id given by the caveats on the macaroon.

        Does *not* validate the macaroon.

        Args:
            macaroon (pymacaroons.Macaroon): The macaroon to validate

        Returns:
            (str) user id

        Raises:
            AuthError if there is no user_id caveat in the macaroon
        """
        user_prefix = "user_id = "
        for caveat in macaroon.caveats:
            if caveat.caveat_id.startswith(user_prefix):
                return caveat.caveat_id[len(user_prefix):]
        raise AuthError(
            self.TOKEN_NOT_FOUND_HTTP_STATUS, "No user caveat in macaroon",
            errcode=Codes.UNKNOWN_TOKEN
        )

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
        expiry = int(caveat[len(prefix):])
        now = self.hs.get_clock().time_msec()
        return now < expiry

    @defer.inlineCallbacks
    def _look_up_user_by_access_token(self, token):
        ret = yield self.store.get_user_by_access_token(token)
        if not ret:
            logger.warn("Unrecognised access token - not in store: %s" % (token,))
            raise AuthError(
                self.TOKEN_NOT_FOUND_HTTP_STATUS, "Unrecognised access token.",
                errcode=Codes.UNKNOWN_TOKEN
            )
        # we use ret.get() below because *lots* of unit tests stub out
        # get_user_by_access_token in a way where it only returns a couple of
        # the fields.
        user_info = {
            "user": UserID.from_string(ret.get("name")),
            "token_id": ret.get("token_id", None),
            "is_guest": False,
            "device_id": ret.get("device_id"),
        }
        defer.returnValue(user_info)

    def get_appservice_by_req(self, request):
        try:
            token = get_access_token_from_request(
                request, self.TOKEN_NOT_FOUND_HTTP_STATUS
            )
            service = self.store.get_app_service_by_token(token)
            if not service:
                logger.warn("Unrecognised appservice access token: %s" % (token,))
                raise AuthError(
                    self.TOKEN_NOT_FOUND_HTTP_STATUS,
                    "Unrecognised access token.",
                    errcode=Codes.UNKNOWN_TOKEN
                )
            request.authenticated_entity = service.sender
            return defer.succeed(service)
        except KeyError:
            raise AuthError(
                self.TOKEN_NOT_FOUND_HTTP_STATUS, "Missing access token."
            )

    def is_server_admin(self, user):
        return self.store.is_server_admin(user)

    @defer.inlineCallbacks
    def add_auth_events(self, builder, context):
        auth_ids = yield self.compute_auth_events(builder, context.prev_state_ids)

        auth_events_entries = yield self.store.add_event_hashes(
            auth_ids
        )

        builder.auth_events = auth_events_entries

    @defer.inlineCallbacks
    def compute_auth_events(self, event, current_state_ids, for_verification=False):
        if event.type == EventTypes.Create:
            defer.returnValue([])

        auth_ids = []

        key = (EventTypes.PowerLevels, "", )
        power_level_event_id = current_state_ids.get(key)

        if power_level_event_id:
            auth_ids.append(power_level_event_id)

        key = (EventTypes.JoinRules, "", )
        join_rule_event_id = current_state_ids.get(key)

        key = (EventTypes.Member, event.user_id, )
        member_event_id = current_state_ids.get(key)

        key = (EventTypes.Create, "", )
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
                    key = (EventTypes.Member, event.state_key, )
                    existing_event_id = current_state_ids.get(key)
                    if existing_event_id:
                        auth_ids.append(existing_event_id)

            if e_type == Membership.INVITE:
                if "third_party_invite" in event.content:
                    key = (
                        EventTypes.ThirdPartyInvite,
                        event.content["third_party_invite"]["signed"]["token"]
                    )
                    third_party_invite_id = current_state_ids.get(key)
                    if third_party_invite_id:
                        auth_ids.append(third_party_invite_id)
        elif member_event_id:
            member_event = yield self.store.get_event(member_event_id)
            if member_event.content["membership"] == Membership.JOIN:
                auth_ids.append(member_event.event_id)

        defer.returnValue(auth_ids)

    def check_redaction(self, event, auth_events):
        """Check whether the event sender is allowed to redact the target event.

        Returns:
            True if the the sender is allowed to redact the target event if the
            target event was created by them.
            False if the sender is allowed to redact the target event with no
            further checks.

        Raises:
            AuthError if the event sender is definitely not allowed to redact
            the target event.
        """
        return event_auth.check_redaction(event, auth_events)

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
            defer.returnValue(True)

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
            EventTypes.Aliases, "", auth_events
        )
        user_level = event_auth.get_user_power_level(user_id, auth_events)

        if user_level < send_level:
            raise AuthError(
                403,
                "This server requires you to be a moderator in the room to"
                " edit its room list entry"
            )


def has_access_token(request):
    """Checks if the request has an access_token.

    Returns:
        bool: False if no access_token was given, True otherwise.
    """
    query_params = request.args.get("access_token")
    auth_headers = request.requestHeaders.getRawHeaders("Authorization")
    return bool(query_params) or bool(auth_headers)


def get_access_token_from_request(request, token_not_found_http_status=401):
    """Extracts the access_token from the request.

    Args:
        request: The http request.
        token_not_found_http_status(int): The HTTP status code to set in the
            AuthError if the token isn't found. This is used in some of the
            legacy APIs to change the status code to 403 from the default of
            401 since some of the old clients depended on auth errors returning
            403.
    Returns:
        str: The access_token
    Raises:
        AuthError: If there isn't an access_token in the request.
    """

    auth_headers = request.requestHeaders.getRawHeaders("Authorization")
    query_params = request.args.get("access_token")
    if auth_headers:
        # Try the get the access_token from a "Authorization: Bearer"
        # header
        if query_params is not None:
            raise AuthError(
                token_not_found_http_status,
                "Mixing Authorization headers and access_token query parameters.",
                errcode=Codes.MISSING_TOKEN,
            )
        if len(auth_headers) > 1:
            raise AuthError(
                token_not_found_http_status,
                "Too many Authorization headers.",
                errcode=Codes.MISSING_TOKEN,
            )
        parts = auth_headers[0].split(" ")
        if parts[0] == "Bearer" and len(parts) == 2:
            return parts[1]
        else:
            raise AuthError(
                token_not_found_http_status,
                "Invalid Authorization header.",
                errcode=Codes.MISSING_TOKEN,
            )
    else:
        # Try to get the access_token from the query params.
        if not query_params:
            raise AuthError(
                token_not_found_http_status,
                "Missing access token.",
                errcode=Codes.MISSING_TOKEN
            )

        return query_params[0]
