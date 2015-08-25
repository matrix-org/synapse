# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

"""This module contains classes for authenticating the user."""

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership, JoinRules
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.util.logutils import log_function
from synapse.types import UserID

import logging

logger = logging.getLogger(__name__)


AuthEventTypes = (
    EventTypes.Create, EventTypes.Member, EventTypes.PowerLevels,
    EventTypes.JoinRules, EventTypes.RoomHistoryVisibility,
)


class Auth(object):

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self.TOKEN_NOT_FOUND_HTTP_STATUS = 401

    def check(self, event, auth_events):
        """ Checks if this event is correctly authed.

        Args:
            event: the event being checked.
            auth_events (dict: event-key -> event): the existing room state.


        Returns:
            True if the auth checks pass.
        """
        try:
            if not hasattr(event, "room_id"):
                raise AuthError(500, "Event has no room_id: %s" % event)
            if auth_events is None:
                # Oh, we don't know what the state of the room was, so we
                # are trusting that this is allowed (at least for now)
                logger.warn("Trusting event: %s", event.event_id)
                return True

            if event.type == EventTypes.Create:
                # FIXME
                return True

            # FIXME: Temp hack
            if event.type == EventTypes.Aliases:
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
            self._can_send_event(event, auth_events)

            if event.type == EventTypes.PowerLevels:
                self._check_power_levels(event, auth_events)

            if event.type == EventTypes.Redaction:
                self._check_redaction(event, auth_events)

            logger.debug("Allowing! %s", event)
        except AuthError as e:
            logger.info(
                "Event auth check failed on event %s with msg: %s",
                event, e.msg
            )
            logger.info("Denying! %s", event)
            raise

    @defer.inlineCallbacks
    def check_joined_room(self, room_id, user_id, current_state=None):
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
    def check_host_in_room(self, room_id, host):
        curr_state = yield self.state.get_current_state(room_id)

        for event in curr_state.values():
            if event.type == EventTypes.Member:
                try:
                    if UserID.from_string(event.state_key).domain != host:
                        continue
                except:
                    logger.warn("state_key not user_id: %s", event.state_key)
                    continue

                if event.content["membership"] == Membership.JOIN:
                    defer.returnValue(True)

        defer.returnValue(False)

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

        if Membership.JOIN != membership:
            # JOIN is the only action you can perform if you're not in the room
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
    def get_user_by_req(self, request):
        """ Get a registered user's ID.

        Args:
            request - An HTTP request with an access_token query parameter.
        Returns:
            tuple of:
                UserID (str)
                Access token ID (str)
        Raises:
            AuthError if no user by that token exists or the token is invalid.
        """
        # Can optionally look elsewhere in the request (e.g. headers)
        try:
            access_token = request.args["access_token"][0]

            # Check for application service tokens with a user_id override
            try:
                app_service = yield self.store.get_app_service_by_token(
                    access_token
                )
                if not app_service:
                    raise KeyError

                user_id = app_service.sender
                if "user_id" in request.args:
                    user_id = request.args["user_id"][0]
                    if not app_service.is_interested_in_user(user_id):
                        raise AuthError(
                            403,
                            "Application service cannot masquerade as this user."
                        )

                if not user_id:
                    raise KeyError

                request.authenticated_entity = user_id

                defer.returnValue(
                    (UserID.from_string(user_id), "")
                )
                return
            except KeyError:
                pass  # normal users won't have the user_id query parameter set.

            user_info = yield self.get_user_by_access_token(access_token)
            user = user_info["user"]
            token_id = user_info["token_id"]

            ip_addr = self.hs.get_ip_from_request(request)
            user_agent = request.requestHeaders.getRawHeaders(
                "User-Agent",
                default=[""]
            )[0]
            if user and access_token and ip_addr:
                self.store.insert_client_ip(
                    user=user,
                    access_token=access_token,
                    ip=ip_addr,
                    user_agent=user_agent
                )

            request.authenticated_entity = user.to_string()

            defer.returnValue((user, token_id,))
        except KeyError:
            raise AuthError(
                self.TOKEN_NOT_FOUND_HTTP_STATUS, "Missing access token.",
                errcode=Codes.MISSING_TOKEN
            )

    @defer.inlineCallbacks
    def get_user_by_access_token(self, token):
        """ Get a registered user's ID.

        Args:
            token (str): The access token to get the user by.
        Returns:
            dict : dict that includes the user and whether the
                user is a server admin.
        Raises:
            AuthError if no user by that token exists or the token is invalid.
        """
        ret = yield self.store.get_user_by_access_token(token)
        if not ret:
            raise AuthError(
                self.TOKEN_NOT_FOUND_HTTP_STATUS, "Unrecognised access token.",
                errcode=Codes.UNKNOWN_TOKEN
            )
        user_info = {
            "admin": bool(ret.get("admin", False)),
            "user": UserID.from_string(ret.get("name")),
            "token_id": ret.get("token_id", None),
        }

        defer.returnValue(user_info)

    @defer.inlineCallbacks
    def get_appservice_by_req(self, request):
        try:
            token = request.args["access_token"][0]
            service = yield self.store.get_app_service_by_token(token)
            if not service:
                raise AuthError(
                    self.TOKEN_NOT_FOUND_HTTP_STATUS,
                    "Unrecognised access token.",
                    errcode=Codes.UNKNOWN_TOKEN
                )
            request.authenticated_entity = service.sender
            defer.returnValue(service)
        except KeyError:
            raise AuthError(
                self.TOKEN_NOT_FOUND_HTTP_STATUS, "Missing access token."
            )

    def is_server_admin(self, user):
        return self.store.is_server_admin(user)

    @defer.inlineCallbacks
    def add_auth_events(self, builder, context):
        auth_ids = self.compute_auth_events(builder, context.current_state)

        auth_events_entries = yield self.store.add_event_hashes(
            auth_ids
        )

        builder.auth_events = auth_events_entries

    def compute_auth_events(self, event, current_state):
        if event.type == EventTypes.Create:
            return []

        auth_ids = []

        key = (EventTypes.PowerLevels, "", )
        power_level_event = current_state.get(key)

        if power_level_event:
            auth_ids.append(power_level_event.event_id)

        key = (EventTypes.JoinRules, "", )
        join_rule_event = current_state.get(key)

        key = (EventTypes.Member, event.user_id, )
        member_event = current_state.get(key)

        key = (EventTypes.Create, "", )
        create_event = current_state.get(key)
        if create_event:
            auth_ids.append(create_event.event_id)

        if join_rule_event:
            join_rule = join_rule_event.content.get("join_rule")
            is_public = join_rule == JoinRules.PUBLIC if join_rule else False
        else:
            is_public = False

        if event.type == EventTypes.Member:
            e_type = event.content["membership"]
            if e_type in [Membership.JOIN, Membership.INVITE]:
                if join_rule_event:
                    auth_ids.append(join_rule_event.event_id)

            if e_type == Membership.JOIN:
                if member_event and not is_public:
                    auth_ids.append(member_event.event_id)
            else:
                if member_event:
                    auth_ids.append(member_event.event_id)
        elif member_event:
            if member_event.content["membership"] == Membership.JOIN:
                auth_ids.append(member_event.event_id)

        return auth_ids

    @log_function
    def _can_send_event(self, event, auth_events):
        key = (EventTypes.PowerLevels, "", )
        send_level_event = auth_events.get(key)
        send_level = None
        if send_level_event:
            send_level = send_level_event.content.get("events", {}).get(
                event.type
            )
            if send_level is None:
                if hasattr(event, "state_key"):
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
                else:
                    sender_domain = UserID.from_string(
                        event.user_id
                    ).domain

                    if sender_domain != event.state_key:
                        raise AuthError(
                            403,
                            "You are not allowed to set others state"
                        )

        return True

    def _check_redaction(self, event, auth_events):
        user_level = self._get_user_power_level(event.user_id, auth_events)

        redact_level = self._get_named_level(auth_events, "redact", 50)

        if user_level < redact_level:
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
