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
from collections import namedtuple

from six import PY3, iteritems
from six.moves import range

import msgpack
from unpaddedbase64 import decode_base64, encode_base64

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules
from synapse.types import ThirdPartyInstanceID
from synapse.util.async_helpers import concurrently_execute
from synapse.util.caches.descriptors import cachedInlineCallbacks
from synapse.util.caches.response_cache import ResponseCache

from ._base import BaseHandler

logger = logging.getLogger(__name__)

REMOTE_ROOM_LIST_POLL_INTERVAL = 60 * 1000


# This is used to indicate we should only return rooms published to the main list.
EMPTY_THIRD_PARTY_ID = ThirdPartyInstanceID(None, None)


class RoomListHandler(BaseHandler):
    def __init__(self, hs):
        super(RoomListHandler, self).__init__(hs)
        self.enable_room_list_search = hs.config.enable_room_list_search
        self.response_cache = ResponseCache(hs, "room_list")
        self.remote_response_cache = ResponseCache(hs, "remote_room_list",
                                                   timeout_ms=30 * 1000)

    def get_local_public_room_list(self, limit=None, since_token=None,
                                   search_filter=None,
                                   network_tuple=EMPTY_THIRD_PARTY_ID,
                                   from_federation=False):
        """Generate a local public room list.

        There are multiple different lists: the main one plus one per third
        party network. A client can ask for a specific list or to return all.

        Args:
            limit (int|None)
            since_token (str|None)
            search_filter (dict|None)
            network_tuple (ThirdPartyInstanceID): Which public list to use.
                This can be (None, None) to indicate the main list, or a particular
                appservice and network id to use an appservice specific one.
                Setting to None returns all public rooms across all lists.
        """
        if not self.enable_room_list_search:
            return defer.succeed({
                "chunk": [],
                "total_room_count_estimate": 0,
            })

        logger.info(
            "Getting public room list: limit=%r, since=%r, search=%r, network=%r",
            limit, since_token, bool(search_filter), network_tuple,
        )

        if search_filter:
            # We explicitly don't bother caching searches or requests for
            # appservice specific lists.
            logger.info("Bypassing cache as search request.")

            # XXX: Quick hack to stop room directory queries taking too long.
            # Timeout request after 60s. Probably want a more fundamental
            # solution at some point
            timeout = self.clock.time() + 60
            return self._get_public_room_list(
                limit, since_token, search_filter,
                network_tuple=network_tuple, timeout=timeout,
            )

        key = (limit, since_token, network_tuple)
        return self.response_cache.wrap(
            key,
            self._get_public_room_list,
            limit, since_token,
            network_tuple=network_tuple, from_federation=from_federation,
        )

    @defer.inlineCallbacks
    def _get_public_room_list(self, limit=None, since_token=None,
                              search_filter=None,
                              network_tuple=EMPTY_THIRD_PARTY_ID,
                              from_federation=False,
                              timeout=None,):
        """Generate a public room list.
        Args:
            limit (int|None): Maximum amount of rooms to return.
            since_token (str|None)
            search_filter (dict|None): Dictionary to filter rooms by.
            network_tuple (ThirdPartyInstanceID): Which public list to use.
                This can be (None, None) to indicate the main list, or a particular
                appservice and network id to use an appservice specific one.
                Setting to None returns all public rooms across all lists.
            from_federation (bool): Whether this request originated from a
                federating server or a client. Used for room filtering.
            timeout (int|None): Amount of seconds to wait for a response before
                timing out.
        """
        if since_token and since_token != "END":
            since_token = RoomListNextBatch.from_token(since_token)
        else:
            since_token = None

        rooms_to_order_value = {}
        rooms_to_num_joined = {}

        newly_visible = []
        newly_unpublished = []
        if since_token:
            stream_token = since_token.stream_ordering
            current_public_id = yield self.store.get_current_public_room_stream_id()
            public_room_stream_id = since_token.public_room_stream_id
            newly_visible, newly_unpublished = yield self.store.get_public_room_changes(
                public_room_stream_id, current_public_id,
                network_tuple=network_tuple,
            )
        else:
            stream_token = yield self.store.get_room_max_stream_ordering()
            public_room_stream_id = yield self.store.get_current_public_room_stream_id()

        room_ids = yield self.store.get_public_room_ids_at_stream_id(
            public_room_stream_id, network_tuple=network_tuple,
        )

        # We want to return rooms in a particular order: the number of joined
        # users. We then arbitrarily use the room_id as a tie breaker.

        @defer.inlineCallbacks
        def get_order_for_room(room_id):
            # Most of the rooms won't have changed between the since token and
            # now (especially if the since token is "now"). So, we can ask what
            # the current users are in a room (that will hit a cache) and then
            # check if the room has changed since the since token. (We have to
            # do it in that order to avoid races).
            # If things have changed then fall back to getting the current state
            # at the since token.
            joined_users = yield self.store.get_users_in_room(room_id)
            if self.store.has_room_changed_since(room_id, stream_token):
                latest_event_ids = yield self.store.get_forward_extremeties_for_room(
                    room_id, stream_token
                )

                if not latest_event_ids:
                    return

                joined_users = yield self.state_handler.get_current_users_in_room(
                    room_id, latest_event_ids,
                )

            num_joined_users = len(joined_users)
            rooms_to_num_joined[room_id] = num_joined_users

            if num_joined_users == 0:
                return

            # We want larger rooms to be first, hence negating num_joined_users
            rooms_to_order_value[room_id] = (-num_joined_users, room_id)

        logger.info("Getting ordering for %i rooms since %s",
                    len(room_ids), stream_token)
        yield concurrently_execute(get_order_for_room, room_ids, 10)

        sorted_entries = sorted(rooms_to_order_value.items(), key=lambda e: e[1])
        sorted_rooms = [room_id for room_id, _ in sorted_entries]

        # `sorted_rooms` should now be a list of all public room ids that is
        # stable across pagination. Therefore, we can use indices into this
        # list as our pagination tokens.

        # Filter out rooms that we don't want to return
        rooms_to_scan = [
            r for r in sorted_rooms
            if r not in newly_unpublished and rooms_to_num_joined[r] > 0
        ]

        total_room_count = len(rooms_to_scan)

        if since_token:
            # Filter out rooms we've already returned previously
            # `since_token.current_limit` is the index of the last room we
            # sent down, so we exclude it and everything before/after it.
            if since_token.direction_is_forward:
                rooms_to_scan = rooms_to_scan[since_token.current_limit + 1:]
            else:
                rooms_to_scan = rooms_to_scan[:since_token.current_limit]
                rooms_to_scan.reverse()

        logger.info("After sorting and filtering, %i rooms remain",
                    len(rooms_to_scan))

        # _append_room_entry_to_chunk will append to chunk but will stop if
        # len(chunk) > limit
        #
        # Normally we will generate enough results on the first iteration here,
        #  but if there is a search filter, _append_room_entry_to_chunk may
        # filter some results out, in which case we loop again.
        #
        # We don't want to scan over the entire range either as that
        # would potentially waste a lot of work.
        #
        # XXX if there is no limit, we may end up DoSing the server with
        # calls to get_current_state_ids for every single room on the
        # server. Surely we should cap this somehow?
        #
        if limit:
            step = limit + 1
        else:
            # step cannot be zero
            step = len(rooms_to_scan) if len(rooms_to_scan) != 0 else 1

        chunk = []
        for i in range(0, len(rooms_to_scan), step):
            if timeout and self.clock.time() > timeout:
                raise Exception("Timed out searching room directory")

            batch = rooms_to_scan[i:i + step]
            logger.info("Processing %i rooms for result", len(batch))
            yield concurrently_execute(
                lambda r: self._append_room_entry_to_chunk(
                    r, rooms_to_num_joined[r],
                    chunk, limit, search_filter,
                    from_federation=from_federation,
                ),
                batch, 5,
            )
            logger.info("Now %i rooms in result", len(chunk))
            if len(chunk) >= limit + 1:
                break

        chunk.sort(key=lambda e: (-e["num_joined_members"], e["room_id"]))

        # Work out the new limit of the batch for pagination, or None if we
        # know there are no more results that would be returned.
        # i.e., [since_token.current_limit..new_limit] is the batch of rooms
        # we've returned (or the reverse if we paginated backwards)
        # We tried to pull out limit + 1 rooms above, so if we have <= limit
        # then we know there are no more results to return
        new_limit = None
        if chunk and (not limit or len(chunk) > limit):

            if not since_token or since_token.direction_is_forward:
                if limit:
                    chunk = chunk[:limit]
                last_room_id = chunk[-1]["room_id"]
            else:
                if limit:
                    chunk = chunk[-limit:]
                last_room_id = chunk[0]["room_id"]

            new_limit = sorted_rooms.index(last_room_id)

        results = {
            "chunk": chunk,
            "total_room_count_estimate": total_room_count,
        }

        if since_token:
            results["new_rooms"] = bool(newly_visible)

        if not since_token or since_token.direction_is_forward:
            if new_limit is not None:
                results["next_batch"] = RoomListNextBatch(
                    stream_ordering=stream_token,
                    public_room_stream_id=public_room_stream_id,
                    current_limit=new_limit,
                    direction_is_forward=True,
                ).to_token()

            if since_token:
                results["prev_batch"] = since_token.copy_and_replace(
                    direction_is_forward=False,
                    current_limit=since_token.current_limit + 1,
                ).to_token()
        else:
            if new_limit is not None:
                results["prev_batch"] = RoomListNextBatch(
                    stream_ordering=stream_token,
                    public_room_stream_id=public_room_stream_id,
                    current_limit=new_limit,
                    direction_is_forward=False,
                ).to_token()

            if since_token:
                results["next_batch"] = since_token.copy_and_replace(
                    direction_is_forward=True,
                    current_limit=since_token.current_limit - 1,
                ).to_token()

        defer.returnValue(results)

    @defer.inlineCallbacks
    def _append_room_entry_to_chunk(self, room_id, num_joined_users, chunk, limit,
                                    search_filter, from_federation=False):
        """Generate the entry for a room in the public room list and append it
        to the `chunk` if it matches the search filter

        Args:
            room_id (str): The ID of the room.
            num_joined_users (int): The number of joined users in the room.
            chunk (list)
            limit (int|None): Maximum amount of rooms to display. Function will
                return if length of chunk is greater than limit + 1.
            search_filter (dict|None)
            from_federation (bool): Whether this request originated from a
                federating server or a client. Used for room filtering.
        """
        if limit and len(chunk) > limit + 1:
            # We've already got enough, so lets just drop it.
            return

        result = yield self.generate_room_entry(room_id, num_joined_users)
        if not result:
            return

        if from_federation and not result.get("m.federate", True):
            # This is a room that other servers cannot join. Do not show them
            # this room.
            return

        if _matches_room_entry(result, search_filter):
            chunk.append(result)

    @cachedInlineCallbacks(num_args=1, cache_context=True)
    def generate_room_entry(self, room_id, num_joined_users, cache_context,
                            with_alias=True, allow_private=False):
        """Returns the entry for a room

        Args:
            room_id (str): The room's ID.
            num_joined_users (int): Number of users in the room.
            cache_context: Information for cached responses.
            with_alias (bool): Whether to return the room's aliases in the result.
            allow_private (bool): Whether invite-only rooms should be shown.

        Returns:
            Deferred[dict|None]: Returns a room entry as a dictionary, or None if this
            room was determined not to be shown publicly.
        """
        result = {
            "room_id": room_id,
            "num_joined_members": num_joined_users,
        }

        current_state_ids = yield self.store.get_current_state_ids(
            room_id, on_invalidate=cache_context.invalidate,
        )

        event_map = yield self.store.get_events([
            event_id for key, event_id in iteritems(current_state_ids)
            if key[0] in (
                EventTypes.Create,
                EventTypes.JoinRules,
                EventTypes.Name,
                EventTypes.Topic,
                EventTypes.CanonicalAlias,
                EventTypes.RoomHistoryVisibility,
                EventTypes.GuestAccess,
                "m.room.avatar",
            )
        ])

        current_state = {
            (ev.type, ev.state_key): ev
            for ev in event_map.values()
        }

        # Double check that this is actually a public room.

        join_rules_event = current_state.get((EventTypes.JoinRules, ""))
        if join_rules_event:
            join_rule = join_rules_event.content.get("join_rule", None)
            if not allow_private and join_rule and join_rule != JoinRules.PUBLIC:
                defer.returnValue(None)

        # Return whether this room is open to federation users or not
        create_event = current_state.get((EventTypes.Create, ""))
        result["m.federate"] = create_event.content.get("m.federate", True)

        if with_alias:
            aliases = yield self.store.get_aliases_for_room(
                room_id, on_invalidate=cache_context.invalidate
            )
            if aliases:
                result["aliases"] = aliases

        name_event = yield current_state.get((EventTypes.Name, ""))
        if name_event:
            name = name_event.content.get("name", None)
            if name:
                result["name"] = name

        topic_event = current_state.get((EventTypes.Topic, ""))
        if topic_event:
            topic = topic_event.content.get("topic", None)
            if topic:
                result["topic"] = topic

        canonical_event = current_state.get((EventTypes.CanonicalAlias, ""))
        if canonical_event:
            canonical_alias = canonical_event.content.get("alias", None)
            if canonical_alias:
                result["canonical_alias"] = canonical_alias

        visibility_event = current_state.get((EventTypes.RoomHistoryVisibility, ""))
        visibility = None
        if visibility_event:
            visibility = visibility_event.content.get("history_visibility", None)
        result["world_readable"] = visibility == "world_readable"

        guest_event = current_state.get((EventTypes.GuestAccess, ""))
        guest = None
        if guest_event:
            guest = guest_event.content.get("guest_access", None)
        result["guest_can_join"] = guest == "can_join"

        avatar_event = current_state.get(("m.room.avatar", ""))
        if avatar_event:
            avatar_url = avatar_event.content.get("url", None)
            if avatar_url:
                result["avatar_url"] = avatar_url

        defer.returnValue(result)

    @defer.inlineCallbacks
    def get_remote_public_room_list(self, server_name, limit=None, since_token=None,
                                    search_filter=None, include_all_networks=False,
                                    third_party_instance_id=None,):
        if not self.enable_room_list_search:
            defer.returnValue({
                "chunk": [],
                "total_room_count_estimate": 0,
            })

        if search_filter:
            # We currently don't support searching across federation, so we have
            # to do it manually without pagination
            limit = None
            since_token = None

        res = yield self._get_remote_list_cached(
            server_name, limit=limit, since_token=since_token,
            include_all_networks=include_all_networks,
            third_party_instance_id=third_party_instance_id,
        )

        if search_filter:
            res = {"chunk": [
                entry
                for entry in list(res.get("chunk", []))
                if _matches_room_entry(entry, search_filter)
            ]}

        defer.returnValue(res)

    def _get_remote_list_cached(self, server_name, limit=None, since_token=None,
                                search_filter=None, include_all_networks=False,
                                third_party_instance_id=None,):
        repl_layer = self.hs.get_federation_client()
        if search_filter:
            # We can't cache when asking for search
            return repl_layer.get_public_rooms(
                server_name, limit=limit, since_token=since_token,
                search_filter=search_filter, include_all_networks=include_all_networks,
                third_party_instance_id=third_party_instance_id,
            )

        key = (
            server_name, limit, since_token, include_all_networks,
            third_party_instance_id,
        )
        return self.remote_response_cache.wrap(
            key,
            repl_layer.get_public_rooms,
            server_name, limit=limit, since_token=since_token,
            search_filter=search_filter,
            include_all_networks=include_all_networks,
            third_party_instance_id=third_party_instance_id,
        )


class RoomListNextBatch(namedtuple("RoomListNextBatch", (
    "stream_ordering",  # stream_ordering of the first public room list
    "public_room_stream_id",  # public room stream id for first public room list
    "current_limit",  # The number of previous rooms returned
    "direction_is_forward",  # Bool if this is a next_batch, false if prev_batch
))):

    KEY_DICT = {
        "stream_ordering": "s",
        "public_room_stream_id": "p",
        "current_limit": "n",
        "direction_is_forward": "d",
    }

    REVERSE_KEY_DICT = {v: k for k, v in KEY_DICT.items()}

    @classmethod
    def from_token(cls, token):
        if PY3:
            # The argument raw=False is only available on new versions of
            # msgpack, and only really needed on Python 3. Gate it behind
            # a PY3 check to avoid causing issues on Debian-packaged versions.
            decoded = msgpack.loads(decode_base64(token), raw=False)
        else:
            decoded = msgpack.loads(decode_base64(token))
        return RoomListNextBatch(**{
            cls.REVERSE_KEY_DICT[key]: val
            for key, val in decoded.items()
        })

    def to_token(self):
        return encode_base64(msgpack.dumps({
            self.KEY_DICT[key]: val
            for key, val in self._asdict().items()
        }))

    def copy_and_replace(self, **kwds):
        return self._replace(
            **kwds
        )


def _matches_room_entry(room_entry, search_filter):
    if search_filter and search_filter.get("generic_search_term", None):
        generic_search_term = search_filter["generic_search_term"].upper()
        if generic_search_term in room_entry.get("name", "").upper():
            return True
        elif generic_search_term in room_entry.get("topic", "").upper():
            return True
        elif generic_search_term in room_entry.get("canonical_alias", "").upper():
            return True
    else:
        return True

    return False
