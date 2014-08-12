# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from synapse.api.constants import Membership
from synapse.api.errors import AuthError, StoreError
from synapse.api.events.room import (RoomTopicEvent, RoomMemberEvent,
                                     MessageEvent, FeedbackEvent)

import logging

logger = logging.getLogger(__name__)


class Auth(object):

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def check(self, event, raises=False):
        """ Checks if this event is correctly authed.

        Returns:
            True if the auth checks pass.
        Raises:
            AuthError if there was a problem authorising this event. This will
            be raised only if raises=True.
        """
        try:
            if event.type in [RoomTopicEvent.TYPE, MessageEvent.TYPE,
                              FeedbackEvent.TYPE]:
                yield self.check_joined_room(event.room_id, event.user_id)
                defer.returnValue(True)
            elif event.type == RoomMemberEvent.TYPE:
                allowed = yield self.is_membership_change_allowed(event)
                defer.returnValue(allowed)
            else:
                raise AuthError(500, "Unknown event type %s" % event.type)
        except AuthError as e:
            logger.info("Event auth check failed on event %s with msg: %s",
                        event, e.msg)
            if raises:
                raise e
        defer.returnValue(False)

    @defer.inlineCallbacks
    def check_joined_room(self, room_id, user_id):
        try:
            member = yield self.store.get_room_member(
                room_id=room_id,
                user_id=user_id
            )
            if not member or member.membership != Membership.JOIN:
                raise AuthError(403, "User %s not in room %s" %
                                (user_id, room_id))
            defer.returnValue(member)
        except AttributeError:
            pass
        defer.returnValue(None)

    @defer.inlineCallbacks
    def is_membership_change_allowed(self, event):
        # does this room even exist
        room = yield self.store.get_room(event.room_id)
        if not room:
            raise AuthError(403, "Room does not exist")

        # get info about the caller
        try:
            caller = yield self.store.get_room_member(
                user_id=event.user_id,
                room_id=event.room_id)
        except:
            caller = None
        caller_in_room = caller and caller.membership == "join"

        # get info about the target
        try:
            target = yield self.store.get_room_member(
                user_id=event.target_user_id,
                room_id=event.room_id)
        except:
            target = None
        target_in_room = target and target.membership == "join"

        membership = event.content["membership"]

        if Membership.INVITE == membership:
            # Invites are valid iff caller is in the room and target isn't.
            if not caller_in_room:  # caller isn't joined
                raise AuthError(403, "You are not in room %s." % event.room_id)
            elif target_in_room:  # the target is already in the room.
                raise AuthError(403, "%s is already in the room." %
                                     event.target_user_id)
        elif Membership.JOIN == membership:
            # Joins are valid iff caller == target and they were:
            # invited: They are accepting the invitation
            # joined: It's a NOOP
            if event.user_id != event.target_user_id:
                raise AuthError(403, "Cannot force another user to join.")
            elif room.is_public:
                pass  # anyone can join public rooms.
            elif (not caller or caller.membership not in
                    [Membership.INVITE, Membership.JOIN]):
                raise AuthError(403, "You are not invited to this room.")
        elif Membership.LEAVE == membership:
            if not caller_in_room:  # trying to leave a room you aren't joined
                raise AuthError(403, "You are not in room %s." % event.room_id)
            elif event.target_user_id != event.user_id:
                # trying to force another user to leave
                raise AuthError(403, "Cannot force %s to leave." %
                                event.target_user_id)
        else:
            raise AuthError(500, "Unknown membership %s" % membership)

        defer.returnValue(True)

    def get_user_by_req(self, request):
        """ Get a registered user's ID.

        Args:
            request - An HTTP request with an access_token query parameter.
        Returns:
            UserID : User ID object of the user making the request
        Raises:
            AuthError if no user by that token exists or the token is invalid.
        """
        # Can optionally look elsewhere in the request (e.g. headers)
        try:
            return self.get_user_by_token(request.args["access_token"][0])
        except KeyError:
            raise AuthError(403, "Missing access token.")

    @defer.inlineCallbacks
    def get_user_by_token(self, token):
        """ Get a registered user's ID.

        Args:
            token (str)- The access token to get the user by.
        Returns:
            UserID : User ID object of the user who has that access token.
        Raises:
            AuthError if no user by that token exists or the token is invalid.
        """
        try:
            user_id = yield self.store.get_user_by_token(token=token)
            defer.returnValue(self.hs.parse_userid(user_id))
        except StoreError:
            raise AuthError(403, "Unrecognised access token.")
