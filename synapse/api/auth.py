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
from canonicaljson import encode_canonical_json
from signedjson.key import decode_verify_key_bytes
from signedjson.sign import verify_signed_json, SignatureVerifyException
from twisted.internet import defer
from unpaddedbase64 import decode_base64

import synapse.types
from synapse.api.constants import EventTypes, Membership, JoinRules
from synapse.api.errors import AuthError, Codes, SynapseError, EventSizeError
from synapse.types import UserID, get_domain_from_id
from synapse.util.logcontext import preserve_context_over_fn
from synapse.util.logutils import log_function
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


AuthEventTypes = (
    EventTypes.Create, EventTypes.Member, EventTypes.PowerLevels,
    EventTypes.JoinRules, EventTypes.RoomHistoryVisibility,
    EventTypes.ThirdPartyInvite,
)


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
            self.check_size_limits(event)

            if not hasattr(event, "room_id"):
                raise AuthError(500, "Event has no room_id: %s" % event)

            if do_sig_check:
                sender_domain = get_domain_from_id(event.sender)
                event_id_domain = get_domain_from_id(event.event_id)

                is_invite_via_3pid = (
                    event.type == EventTypes.Member
                    and event.membership == Membership.INVITE
                    and "third_party_invite" in event.content
                )

                # Check the sender's domain has signed the event
                if not event.signatures.get(sender_domain):
                    # We allow invites via 3pid to have a sender from a different
                    # HS, as the sender must match the sender of the original
                    # 3pid invite. This is checked further down with the
                    # other dedicated membership checks.
                    if not is_invite_via_3pid:
                        raise AuthError(403, "Event not signed by sender's server")

                # Check the event_id's domain has signed the event
                if not event.signatures.get(event_id_domain):
                    raise AuthError(403, "Event not signed by sending server")

            if auth_events is None:
                # Oh, we don't know what the state of the room was, so we
                # are trusting that this is allowed (at least for now)
                logger.warn("Trusting event: %s", event.event_id)
                return True

            if event.type == EventTypes.Create:
                room_id_domain = get_domain_from_id(event.room_id)
                if room_id_domain != sender_domain:
                    raise AuthError(
                        403,
                        "Creation event's room_id domain does not match sender's"
                    )
                # FIXME
                return True

            creation_event = auth_events.get((EventTypes.Create, ""), None)

            if not creation_event:
                raise SynapseError(
                    403,
                    "Room %r does not exist" % (event.room_id,)
                )

            creating_domain = get_domain_from_id(event.room_id)
            originating_domain = get_domain_from_id(event.sender)
            if creating_domain != originating_domain:
                if not self.can_federate(event, auth_events):
                    raise AuthError(
                        403,
                        "This room has been marked as unfederatable."
                    )

            # FIXME: Temp hack
            if event.type == EventTypes.Aliases:
                if not event.is_state():
                    raise AuthError(
                        403,
                        "Alias event must be a state event",
                    )
                if not event.state_key:
                    raise AuthError(
                        403,
                        "Alias event must have non-empty state_key"
                    )
                sender_domain = get_domain_from_id(event.sender)
                if event.state_key != sender_domain:
                    raise AuthError(
                        403,
                        "Alias event's state_key does not match sender's domain"
                    )
                return True

            logger.debug(
                "Auth events: %s",
                [a.event_id for a in auth_events.values()]
            )

            if event.type == EventTypes.Member:
                allowed = self.is_membership_change_allowed(
                    event, auth_events
                )
                if allowed:
                    logger.debug("Allowing! %s", event)
                else:
                    logger.debug("Denying! %s", event)
                return allowed

            self.check_event_sender_in_room(event, auth_events)

            # Special case to allow m.room.third_party_invite events wherever
            # a user is allowed to issue invites.  Fixes
            # https://github.com/vector-im/vector-web/issues/1208 hopefully
            if event.type == EventTypes.ThirdPartyInvite:
                user_level = self._get_user_power_level(event.user_id, auth_events)
                invite_level = self._get_named_level(auth_events, "invite", 0)

                if user_level < invite_level:
                    raise AuthError(
                        403, (
                            "You cannot issue a third party invite for %s." %
                            (event.content.display_name,)
                        )
                    )
                else:
                    return True

            self._can_send_event(event, auth_events)

            if event.type == EventTypes.PowerLevels:
                self._check_power_levels(event, auth_events)

            if event.type == EventTypes.Redaction:
                self.check_redaction(event, auth_events)

            logger.debug("Allowing! %s", event)

    def check_size_limits(self, event):
        def too_big(field):
            raise EventSizeError("%s too large" % (field,))

        if len(event.user_id) > 255:
            too_big("user_id")
        if len(event.room_id) > 255:
            too_big("room_id")
        if event.is_state() and len(event.state_key) > 255:
            too_big("state_key")
        if len(event.type) > 255:
            too_big("type")
        if len(event.event_id) > 255:
            too_big("event_id")
        if len(encode_canonical_json(event.get_pdu_json())) > 65536:
            too_big("event")

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

            entry = yield self.state.resolve_state_groups(
                room_id, latest_event_ids
            )

            ret = yield self.store.is_host_joined(
                room_id, host, entry.state_group, entry.state
            )
            defer.returnValue(ret)

    def check_event_sender_in_room(self, event, auth_events):
        key = (EventTypes.Member, event.user_id, )
        member_event = auth_events.get(key)

        return self._check_joined_room(
            member_event,
            event.user_id,
            event.room_id
        )

    def _check_joined_room(self, member, user_id, room_id):
        if not member or member.membership != Membership.JOIN:
            raise AuthError(403, "User %s not in room %s (%s)" % (
                user_id, room_id, repr(member)
            ))

    def can_federate(self, event, auth_events):
        creation_event = auth_events.get((EventTypes.Create, ""))

        return creation_event.content.get("m.federate", True) is True

    @log_function
    def is_membership_change_allowed(self, event, auth_events):
        membership = event.content["membership"]

        # Check if this is the room creator joining:
        if len(event.prev_events) == 1 and Membership.JOIN == membership:
            # Get room creation event:
            key = (EventTypes.Create, "", )
            create = auth_events.get(key)
            if create and event.prev_events[0][0] == create.event_id:
                if create.content["creator"] == event.state_key:
                    return True

        target_user_id = event.state_key

        creating_domain = get_domain_from_id(event.room_id)
        target_domain = get_domain_from_id(target_user_id)
        if creating_domain != target_domain:
            if not self.can_federate(event, auth_events):
                raise AuthError(
                    403,
                    "This room has been marked as unfederatable."
                )

        # get info about the caller
        key = (EventTypes.Member, event.user_id, )
        caller = auth_events.get(key)

        caller_in_room = caller and caller.membership == Membership.JOIN
        caller_invited = caller and caller.membership == Membership.INVITE

        # get info about the target
        key = (EventTypes.Member, target_user_id, )
        target = auth_events.get(key)

        target_in_room = target and target.membership == Membership.JOIN
        target_banned = target and target.membership == Membership.BAN

        key = (EventTypes.JoinRules, "", )
        join_rule_event = auth_events.get(key)
        if join_rule_event:
            join_rule = join_rule_event.content.get(
                "join_rule", JoinRules.INVITE
            )
        else:
            join_rule = JoinRules.INVITE

        user_level = self._get_user_power_level(event.user_id, auth_events)
        target_level = self._get_user_power_level(
            target_user_id, auth_events
        )

        # FIXME (erikj): What should we do here as the default?
        ban_level = self._get_named_level(auth_events, "ban", 50)

        logger.debug(
            "is_membership_change_allowed: %s",
            {
                "caller_in_room": caller_in_room,
                "caller_invited": caller_invited,
                "target_banned": target_banned,
                "target_in_room": target_in_room,
                "membership": membership,
                "join_rule": join_rule,
                "target_user_id": target_user_id,
                "event.user_id": event.user_id,
            }
        )

        if Membership.INVITE == membership and "third_party_invite" in event.content:
            if not self._verify_third_party_invite(event, auth_events):
                raise AuthError(403, "You are not invited to this room.")
            if target_banned:
                raise AuthError(
                    403, "%s is banned from the room" % (target_user_id,)
                )
            return True

        if Membership.JOIN != membership:
            if (caller_invited
                    and Membership.LEAVE == membership
                    and target_user_id == event.user_id):
                return True

            if not caller_in_room:  # caller isn't joined
                raise AuthError(
                    403,
                    "%s not in room %s." % (event.user_id, event.room_id,)
                )

        if Membership.INVITE == membership:
            # TODO (erikj): We should probably handle this more intelligently
            # PRIVATE join rules.

            # Invites are valid iff caller is in the room and target isn't.
            if target_banned:
                raise AuthError(
                    403, "%s is banned from the room" % (target_user_id,)
                )
            elif target_in_room:  # the target is already in the room.
                raise AuthError(403, "%s is already in the room." %
                                     target_user_id)
            else:
                invite_level = self._get_named_level(auth_events, "invite", 0)

                if user_level < invite_level:
                    raise AuthError(
                        403, "You cannot invite user %s." % target_user_id
                    )
        elif Membership.JOIN == membership:
            # Joins are valid iff caller == target and they were:
            # invited: They are accepting the invitation
            # joined: It's a NOOP
            if event.user_id != target_user_id:
                raise AuthError(403, "Cannot force another user to join.")
            elif target_banned:
                raise AuthError(403, "You are banned from this room")
            elif join_rule == JoinRules.PUBLIC:
                pass
            elif join_rule == JoinRules.INVITE:
                if not caller_in_room and not caller_invited:
                    raise AuthError(403, "You are not invited to this room.")
            else:
                # TODO (erikj): may_join list
                # TODO (erikj): private rooms
                raise AuthError(403, "You are not allowed to join this room")
        elif Membership.LEAVE == membership:
            # TODO (erikj): Implement kicks.
            if target_banned and user_level < ban_level:
                raise AuthError(
                    403, "You cannot unban user &s." % (target_user_id,)
                )
            elif target_user_id != event.user_id:
                kick_level = self._get_named_level(auth_events, "kick", 50)

                if user_level < kick_level or user_level <= target_level:
                    raise AuthError(
                        403, "You cannot kick user %s." % target_user_id
                    )
        elif Membership.BAN == membership:
            if user_level < ban_level or user_level <= target_level:
                raise AuthError(403, "You don't have permission to ban")
        else:
            raise AuthError(500, "Unknown membership %s" % membership)

        return True

    def _verify_third_party_invite(self, event, auth_events):
        """
        Validates that the invite event is authorized by a previous third-party invite.

        Checks that the public key, and keyserver, match those in the third party invite,
        and that the invite event has a signature issued using that public key.

        Args:
            event: The m.room.member join event being validated.
            auth_events: All relevant previous context events which may be used
                for authorization decisions.

        Return:
            True if the event fulfills the expectations of a previous third party
            invite event.
        """
        if "third_party_invite" not in event.content:
            return False
        if "signed" not in event.content["third_party_invite"]:
            return False
        signed = event.content["third_party_invite"]["signed"]
        for key in {"mxid", "token"}:
            if key not in signed:
                return False

        token = signed["token"]

        invite_event = auth_events.get(
            (EventTypes.ThirdPartyInvite, token,)
        )
        if not invite_event:
            return False

        if invite_event.sender != event.sender:
            return False

        if event.user_id != invite_event.user_id:
            return False

        if signed["mxid"] != event.state_key:
            return False
        if signed["token"] != token:
            return False

        for public_key_object in self.get_public_keys(invite_event):
            public_key = public_key_object["public_key"]
            try:
                for server, signature_block in signed["signatures"].items():
                    for key_name, encoded_signature in signature_block.items():
                        if not key_name.startswith("ed25519:"):
                            continue
                        verify_key = decode_verify_key_bytes(
                            key_name,
                            decode_base64(public_key)
                        )
                        verify_signed_json(signed, server, verify_key)

                        # We got the public key from the invite, so we know that the
                        # correct server signed the signed bundle.
                        # The caller is responsible for checking that the signing
                        # server has not revoked that public key.
                        return True
            except (KeyError, SignatureVerifyException,):
                continue
        return False

    def get_public_keys(self, invite_event):
        public_keys = []
        if "public_key" in invite_event.content:
            o = {
                "public_key": invite_event.content["public_key"],
            }
            if "key_validity_url" in invite_event.content:
                o["key_validity_url"] = invite_event.content["key_validity_url"]
            public_keys.append(o)
        public_keys.extend(invite_event.content.get("public_keys", []))
        return public_keys

    def _get_power_level_event(self, auth_events):
        key = (EventTypes.PowerLevels, "", )
        return auth_events.get(key)

    def _get_user_power_level(self, user_id, auth_events):
        power_level_event = self._get_power_level_event(auth_events)

        if power_level_event:
            level = power_level_event.content.get("users", {}).get(user_id)
            if not level:
                level = power_level_event.content.get("users_default", 0)

            if level is None:
                return 0
            else:
                return int(level)
        else:
            key = (EventTypes.Create, "", )
            create_event = auth_events.get(key)
            if (create_event is not None and
                    create_event.content["creator"] == user_id):
                return 100
            else:
                return 0

    def _get_named_level(self, auth_events, name, default):
        power_level_event = self._get_power_level_event(auth_events)

        if not power_level_event:
            return default

        level = power_level_event.content.get(name, None)
        if level is not None:
            return int(level)
        else:
            return default

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
        """ Get a registered user's ID.

        Args:
            token (str): The access token to get the user by.
        Returns:
            dict : dict that includes the user and the ID of their access token.
        Raises:
            AuthError if no user by that token exists or the token is invalid.
        """
        try:
            ret = yield self.get_user_from_macaroon(token, rights)
        except AuthError:
            # TODO(daniel): Remove this fallback when all existing access tokens
            # have been re-issued as macaroons.
            if self.hs.config.expire_access_token:
                raise
            ret = yield self._look_up_user_by_access_token(token)

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def get_user_from_macaroon(self, macaroon_str, rights="access"):
        try:
            macaroon = pymacaroons.Macaroon.deserialize(macaroon_str)

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
                ret = {
                    "user": user,
                    "is_guest": True,
                    "token_id": None,
                    "device_id": None,
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
                ret = yield self._look_up_user_by_access_token(macaroon_str)
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
            type_string(str): The kind of token required (e.g. "access", "refresh",
                              "delete_pusher")
            verify_expiry(bool): Whether to verify whether the macaroon has expired.
                This should really always be True, but there exist access tokens
                in the wild which expire when they should not, so we can't
                enforce expiry yet.
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
        if verify_expiry:
            v.satisfy_general(self._verify_expiry)
        else:
            v.satisfy_general(lambda c: c.startswith("time < "))

        # access_tokens and refresh_tokens include a nonce for uniqueness: any
        # value is acceptable
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

    def _get_send_level(self, etype, state_key, auth_events):
        key = (EventTypes.PowerLevels, "", )
        send_level_event = auth_events.get(key)
        send_level = None
        if send_level_event:
            send_level = send_level_event.content.get("events", {}).get(
                etype
            )
            if send_level is None:
                if state_key is not None:
                    send_level = send_level_event.content.get(
                        "state_default", 50
                    )
                else:
                    send_level = send_level_event.content.get(
                        "events_default", 0
                    )

        if send_level:
            send_level = int(send_level)
        else:
            send_level = 0

        return send_level

    @log_function
    def _can_send_event(self, event, auth_events):
        send_level = self._get_send_level(
            event.type, event.get("state_key", None), auth_events
        )
        user_level = self._get_user_power_level(event.user_id, auth_events)

        if user_level < send_level:
            raise AuthError(
                403,
                "You don't have permission to post that to the room. " +
                "user_level (%d) < send_level (%d)" % (user_level, send_level)
            )

        # Check state_key
        if hasattr(event, "state_key"):
            if event.state_key.startswith("@"):
                if event.state_key != event.user_id:
                    raise AuthError(
                        403,
                        "You are not allowed to set others state"
                    )

        return True

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
        user_level = self._get_user_power_level(event.user_id, auth_events)

        redact_level = self._get_named_level(auth_events, "redact", 50)

        if user_level >= redact_level:
            return False

        redacter_domain = get_domain_from_id(event.event_id)
        redactee_domain = get_domain_from_id(event.redacts)
        if redacter_domain == redactee_domain:
            return True

        raise AuthError(
            403,
            "You don't have permission to redact events"
        )

    def _check_power_levels(self, event, auth_events):
        user_list = event.content.get("users", {})
        # Validate users
        for k, v in user_list.items():
            try:
                UserID.from_string(k)
            except:
                raise SynapseError(400, "Not a valid user_id: %s" % (k,))

            try:
                int(v)
            except:
                raise SynapseError(400, "Not a valid power level: %s" % (v,))

        key = (event.type, event.state_key, )
        current_state = auth_events.get(key)

        if not current_state:
            return

        user_level = self._get_user_power_level(event.user_id, auth_events)

        # Check other levels:
        levels_to_check = [
            ("users_default", None),
            ("events_default", None),
            ("state_default", None),
            ("ban", None),
            ("redact", None),
            ("kick", None),
            ("invite", None),
        ]

        old_list = current_state.content.get("users")
        for user in set(old_list.keys() + user_list.keys()):
            levels_to_check.append(
                (user, "users")
            )

        old_list = current_state.content.get("events")
        new_list = event.content.get("events")
        for ev_id in set(old_list.keys() + new_list.keys()):
            levels_to_check.append(
                (ev_id, "events")
            )

        old_state = current_state.content
        new_state = event.content

        for level_to_check, dir in levels_to_check:
            old_loc = old_state
            new_loc = new_state
            if dir:
                old_loc = old_loc.get(dir, {})
                new_loc = new_loc.get(dir, {})

            if level_to_check in old_loc:
                old_level = int(old_loc[level_to_check])
            else:
                old_level = None

            if level_to_check in new_loc:
                new_level = int(new_loc[level_to_check])
            else:
                new_level = None

            if new_level is not None and old_level is not None:
                if new_level == old_level:
                    continue

            if dir == "users" and level_to_check != event.user_id:
                if old_level == user_level:
                    raise AuthError(
                        403,
                        "You don't have permission to remove ops level equal "
                        "to your own"
                    )

            if old_level > user_level or new_level > user_level:
                raise AuthError(
                    403,
                    "You don't have permission to add ops level greater "
                    "than your own"
                )

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

        send_level = self._get_send_level(
            EventTypes.Aliases, "", auth_events
        )
        user_level = self._get_user_power_level(user_id, auth_events)

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
