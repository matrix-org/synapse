# Copyright 2014-2022 The Matrix.org Foundation C.I.C.
# Copyright 2020 Sorunome
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
import urllib
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    Generator,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

import attr
import ijson

from synapse.api.constants import Membership
from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.api.room_versions import RoomVersion
from synapse.api.urls import (
    FEDERATION_UNSTABLE_PREFIX,
    FEDERATION_V1_PREFIX,
    FEDERATION_V2_PREFIX,
)
from synapse.events import EventBase, make_event_from_dict
from synapse.federation.units import Transaction
from synapse.http.matrixfederationclient import ByteParser
from synapse.http.types import QueryParams
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class TransportLayerClient:
    """Sends federation HTTP requests to other servers"""

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.client = hs.get_federation_http_client()
        self._faster_joins_enabled = hs.config.experimental.faster_joins_enabled

    async def get_room_state_ids(
        self, destination: str, room_id: str, event_id: str
    ) -> JsonDict:
        """Requests the IDs of all state for a given room at the given event.

        Args:
            destination: The host name of the remote homeserver we want
                to get the state from.
            room_id: the room we want the state of
            event_id: The event we want the context at.

        Returns:
            Results in a dict received from the remote homeserver.
        """
        logger.debug("get_room_state_ids dest=%s, room=%s", destination, room_id)

        path = _create_v1_path("/state_ids/%s", room_id)
        return await self.client.get_json(
            destination,
            path=path,
            args={"event_id": event_id},
            try_trailing_slash_on_400=True,
        )

    async def get_room_state(
        self, room_version: RoomVersion, destination: str, room_id: str, event_id: str
    ) -> "StateRequestResponse":
        """Requests the full state for a given room at the given event.

        Args:
            room_version: the version of the room (required to build the event objects)
            destination: The host name of the remote homeserver we want
                to get the state from.
            room_id: the room we want the state of
            event_id: The event we want the context at.

        Returns:
            Results in a dict received from the remote homeserver.
        """
        path = _create_v1_path("/state/%s", room_id)
        return await self.client.get_json(
            destination,
            path=path,
            args={"event_id": event_id},
            parser=_StateParser(room_version),
        )

    async def get_event(
        self, destination: str, event_id: str, timeout: Optional[int] = None
    ) -> JsonDict:
        """Requests the pdu with give id and origin from the given server.

        Args:
            destination: The host name of the remote homeserver we want
                to get the state from.
            event_id: The id of the event being requested.
            timeout: How long to try (in ms) the destination for before
                giving up. None indicates no timeout.

        Returns:
            Results in a dict received from the remote homeserver.
        """
        logger.debug("get_pdu dest=%s, event_id=%s", destination, event_id)

        path = _create_v1_path("/event/%s", event_id)
        return await self.client.get_json(
            destination, path=path, timeout=timeout, try_trailing_slash_on_400=True
        )

    async def backfill(
        self, destination: str, room_id: str, event_tuples: Collection[str], limit: int
    ) -> Optional[JsonDict]:
        """Requests `limit` previous PDUs in a given context before list of
        PDUs.

        Args:
            destination
            room_id
            event_tuples:
                Must be a Collection that is falsy when empty.
                (Iterable is not enough here!)
            limit

        Returns:
            Results in a dict received from the remote homeserver.
        """
        logger.debug(
            "backfill dest=%s, room_id=%s, event_tuples=%r, limit=%s",
            destination,
            room_id,
            event_tuples,
            str(limit),
        )

        if not event_tuples:
            # TODO: raise?
            return None

        path = _create_v1_path("/backfill/%s", room_id)

        args = {"v": event_tuples, "limit": [str(limit)]}

        return await self.client.get_json(
            destination, path=path, args=args, try_trailing_slash_on_400=True
        )

    async def timestamp_to_event(
        self, destination: str, room_id: str, timestamp: int, direction: str
    ) -> Union[JsonDict, List]:
        """
        Calls a remote federating server at `destination` asking for their
        closest event to the given timestamp in the given direction.

        Args:
            destination: Domain name of the remote homeserver
            room_id: Room to fetch the event from
            timestamp: The point in time (inclusive) we should navigate from in
                the given direction to find the closest event.
            direction: ["f"|"b"] to indicate whether we should navigate forward
                or backward from the given timestamp to find the closest event.

        Returns:
            Response dict received from the remote homeserver.

        Raises:
            Various exceptions when the request fails
        """
        path = _create_path(
            FEDERATION_UNSTABLE_PREFIX,
            "/org.matrix.msc3030/timestamp_to_event/%s",
            room_id,
        )

        args = {"ts": [str(timestamp)], "dir": [direction]}

        remote_response = await self.client.get_json(
            destination, path=path, args=args, try_trailing_slash_on_400=True
        )

        return remote_response

    async def send_transaction(
        self,
        transaction: Transaction,
        json_data_callback: Optional[Callable[[], JsonDict]] = None,
    ) -> JsonDict:
        """Sends the given Transaction to its destination

        Args:
            transaction

        Returns:
            Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body.

            Fails with ``HTTPRequestException`` if we get an HTTP response
            code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if this destination
            is not on our federation whitelist
        """
        logger.debug(
            "send_data dest=%s, txid=%s",
            transaction.destination,
            transaction.transaction_id,
        )

        if transaction.destination == self.server_name:
            raise RuntimeError("Transport layer cannot send to itself!")

        # FIXME: This is only used by the tests. The actual json sent is
        # generated by the json_data_callback.
        json_data = transaction.get_dict()

        path = _create_v1_path("/send/%s", transaction.transaction_id)

        return await self.client.put_json(
            transaction.destination,
            path=path,
            data=json_data,
            json_data_callback=json_data_callback,
            long_retries=True,
            backoff_on_404=True,  # If we get a 404 the other side has gone
            try_trailing_slash_on_400=True,
        )

    async def make_query(
        self,
        destination: str,
        query_type: str,
        args: QueryParams,
        retry_on_dns_fail: bool,
        ignore_backoff: bool = False,
        prefix: str = FEDERATION_V1_PREFIX,
    ) -> JsonDict:
        path = _create_path(prefix, "/query/%s", query_type)

        return await self.client.get_json(
            destination=destination,
            path=path,
            args=args,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=10000,
            ignore_backoff=ignore_backoff,
        )

    async def make_membership_event(
        self,
        destination: str,
        room_id: str,
        user_id: str,
        membership: str,
        params: Optional[Mapping[str, Union[str, Iterable[str]]]],
    ) -> JsonDict:
        """Asks a remote server to build and sign us a membership event

        Note that this does not append any events to any graphs.

        Args:
            destination (str): address of remote homeserver
            room_id (str): room to join/leave
            user_id (str): user to be joined/left
            membership (str): one of join/leave
            params (dict[str, str|Iterable[str]]): Query parameters to include in the
                request.

        Returns:
            Succeeds when we get a 2xx HTTP response. The result
            will be the decoded JSON body (ie, the new event).

            Fails with ``HTTPRequestException`` if we get an HTTP response
            code >= 300.

            Fails with ``NotRetryingDestination`` if we are not yet ready
            to retry this server.

            Fails with ``FederationDeniedError`` if the remote destination
            is not in our federation whitelist
        """
        valid_memberships = {Membership.JOIN, Membership.LEAVE, Membership.KNOCK}

        if membership not in valid_memberships:
            raise RuntimeError(
                "make_membership_event called with membership='%s', must be one of %s"
                % (membership, ",".join(valid_memberships))
            )
        path = _create_v1_path("/make_%s/%s/%s", membership, room_id, user_id)

        ignore_backoff = False
        retry_on_dns_fail = False

        if membership == Membership.LEAVE:
            # we particularly want to do our best to send leave events. The
            # problem is that if it fails, we won't retry it later, so if the
            # remote server was just having a momentary blip, the room will be
            # out of sync.
            ignore_backoff = True
            retry_on_dns_fail = True

        return await self.client.get_json(
            destination=destination,
            path=path,
            args=params,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=20000,
            ignore_backoff=ignore_backoff,
        )

    async def send_join_v1(
        self,
        room_version: RoomVersion,
        destination: str,
        room_id: str,
        event_id: str,
        content: JsonDict,
    ) -> "SendJoinResponse":
        path = _create_v1_path("/send_join/%s/%s", room_id, event_id)

        return await self.client.put_json(
            destination=destination,
            path=path,
            data=content,
            parser=SendJoinParser(room_version, v1_api=True),
        )

    async def send_join_v2(
        self,
        room_version: RoomVersion,
        destination: str,
        room_id: str,
        event_id: str,
        content: JsonDict,
    ) -> "SendJoinResponse":
        path = _create_v2_path("/send_join/%s/%s", room_id, event_id)
        query_params: Dict[str, str] = {}
        if self._faster_joins_enabled:
            # lazy-load state on join
            query_params["org.matrix.msc3706.partial_state"] = "true"

        return await self.client.put_json(
            destination=destination,
            path=path,
            args=query_params,
            data=content,
            parser=SendJoinParser(room_version, v1_api=False),
        )

    async def send_leave_v1(
        self, destination: str, room_id: str, event_id: str, content: JsonDict
    ) -> Tuple[int, JsonDict]:
        path = _create_v1_path("/send_leave/%s/%s", room_id, event_id)

        return await self.client.put_json(
            destination=destination,
            path=path,
            data=content,
            # we want to do our best to send this through. The problem is
            # that if it fails, we won't retry it later, so if the remote
            # server was just having a momentary blip, the room will be out of
            # sync.
            ignore_backoff=True,
        )

    async def send_leave_v2(
        self, destination: str, room_id: str, event_id: str, content: JsonDict
    ) -> JsonDict:
        path = _create_v2_path("/send_leave/%s/%s", room_id, event_id)

        return await self.client.put_json(
            destination=destination,
            path=path,
            data=content,
            # we want to do our best to send this through. The problem is
            # that if it fails, we won't retry it later, so if the remote
            # server was just having a momentary blip, the room will be out of
            # sync.
            ignore_backoff=True,
        )

    async def send_knock_v1(
        self,
        destination: str,
        room_id: str,
        event_id: str,
        content: JsonDict,
    ) -> JsonDict:
        """
        Sends a signed knock membership event to a remote server. This is the second
        step for knocking after make_knock.

        Args:
            destination: The remote homeserver.
            room_id: The ID of the room to knock on.
            event_id: The ID of the knock membership event that we're sending.
            content: The knock membership event that we're sending. Note that this is not the
                `content` field of the membership event, but the entire signed membership event
                itself represented as a JSON dict.

        Returns:
            The remote homeserver can optionally return some state from the room. The response
            dictionary is in the form:

            {"knock_state_events": [<state event dict>, ...]}

            The list of state events may be empty.
        """
        path = _create_v1_path("/send_knock/%s/%s", room_id, event_id)

        return await self.client.put_json(
            destination=destination, path=path, data=content
        )

    async def send_invite_v1(
        self, destination: str, room_id: str, event_id: str, content: JsonDict
    ) -> Tuple[int, JsonDict]:
        path = _create_v1_path("/invite/%s/%s", room_id, event_id)

        return await self.client.put_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    async def send_invite_v2(
        self, destination: str, room_id: str, event_id: str, content: JsonDict
    ) -> JsonDict:
        path = _create_v2_path("/invite/%s/%s", room_id, event_id)

        return await self.client.put_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    async def get_public_rooms(
        self,
        remote_server: str,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[Dict] = None,
        include_all_networks: bool = False,
        third_party_instance_id: Optional[str] = None,
    ) -> JsonDict:
        """Get the list of public rooms from a remote homeserver

        See synapse.federation.federation_client.FederationClient.get_public_rooms for
        more information.
        """
        if search_filter:
            # this uses MSC2197 (Search Filtering over Federation)
            path = _create_v1_path("/publicRooms")

            data: Dict[str, Any] = {
                "include_all_networks": "true" if include_all_networks else "false"
            }
            if third_party_instance_id:
                data["third_party_instance_id"] = third_party_instance_id
            if limit:
                data["limit"] = limit
            if since_token:
                data["since"] = since_token

            data["filter"] = search_filter

            try:
                response = await self.client.post_json(
                    destination=remote_server, path=path, data=data, ignore_backoff=True
                )
            except HttpResponseException as e:
                if e.code == 403:
                    raise SynapseError(
                        403,
                        "You are not allowed to view the public rooms list of %s"
                        % (remote_server,),
                        errcode=Codes.FORBIDDEN,
                    )
                raise
        else:
            path = _create_v1_path("/publicRooms")

            args: Dict[str, Union[str, Iterable[str]]] = {
                "include_all_networks": "true" if include_all_networks else "false"
            }
            if third_party_instance_id:
                args["third_party_instance_id"] = (third_party_instance_id,)
            if limit:
                args["limit"] = [str(limit)]
            if since_token:
                args["since"] = [since_token]

            try:
                response = await self.client.get_json(
                    destination=remote_server, path=path, args=args, ignore_backoff=True
                )
            except HttpResponseException as e:
                if e.code == 403:
                    raise SynapseError(
                        403,
                        "You are not allowed to view the public rooms list of %s"
                        % (remote_server,),
                        errcode=Codes.FORBIDDEN,
                    )
                raise

        return response

    async def exchange_third_party_invite(
        self, destination: str, room_id: str, event_dict: JsonDict
    ) -> JsonDict:
        path = _create_v1_path("/exchange_third_party_invite/%s", room_id)

        return await self.client.put_json(
            destination=destination, path=path, data=event_dict
        )

    async def get_event_auth(
        self, destination: str, room_id: str, event_id: str
    ) -> JsonDict:
        path = _create_v1_path("/event_auth/%s/%s", room_id, event_id)

        return await self.client.get_json(destination=destination, path=path)

    async def query_client_keys(
        self, destination: str, query_content: JsonDict, timeout: int
    ) -> JsonDict:
        """Query the device keys for a list of user ids hosted on a remote
        server.

        Request:
            {
              "device_keys": {
                "<user_id>": ["<device_id>"]
              }
            }

        Response:
            {
              "device_keys": {
                "<user_id>": {
                  "<device_id>": {...}
                }
              },
              "master_key": {
                "<user_id>": {...}
                }
              },
              "self_signing_key": {
                "<user_id>": {...}
              }
            }

        Args:
            destination: The server to query.
            query_content: The user ids to query.
        Returns:
            A dict containing device and cross-signing keys.
        """
        path = _create_v1_path("/user/keys/query")

        return await self.client.post_json(
            destination=destination, path=path, data=query_content, timeout=timeout
        )

    async def query_user_devices(
        self, destination: str, user_id: str, timeout: int
    ) -> JsonDict:
        """Query the devices for a user id hosted on a remote server.

        Response:
            {
              "stream_id": "...",
              "devices": [ { ... } ],
              "master_key": {
                "user_id": "<user_id>",
                "usage": [...],
                "keys": {...},
                "signatures": {
                  "<user_id>": {...}
                }
              },
              "self_signing_key": {
                "user_id": "<user_id>",
                "usage": [...],
                "keys": {...},
                "signatures": {
                  "<user_id>": {...}
                }
              }
            }

        Args:
            destination: The server to query.
            query_content: The user ids to query.
        Returns:
            A dict containing device and cross-signing keys.
        """
        path = _create_v1_path("/user/devices/%s", user_id)

        return await self.client.get_json(
            destination=destination, path=path, timeout=timeout
        )

    async def claim_client_keys(
        self, destination: str, query_content: JsonDict, timeout: Optional[int]
    ) -> JsonDict:
        """Claim one-time keys for a list of devices hosted on a remote server.

        Request:
            {
              "one_time_keys": {
                "<user_id>": {
                  "<device_id>": "<algorithm>"
                }
              }
            }

        Response:
            {
              "device_keys": {
                "<user_id>": {
                  "<device_id>": {
                    "<algorithm>:<key_id>": "<key_base64>"
                  }
                }
              }
            }

        Args:
            destination: The server to query.
            query_content: The user ids to query.
        Returns:
            A dict containing the one-time keys.
        """

        path = _create_v1_path("/user/keys/claim")

        return await self.client.post_json(
            destination=destination, path=path, data=query_content, timeout=timeout
        )

    async def get_missing_events(
        self,
        destination: str,
        room_id: str,
        earliest_events: Iterable[str],
        latest_events: Iterable[str],
        limit: int,
        min_depth: int,
        timeout: int,
    ) -> JsonDict:
        path = _create_v1_path("/get_missing_events/%s", room_id)

        return await self.client.post_json(
            destination=destination,
            path=path,
            data={
                "limit": int(limit),
                "min_depth": int(min_depth),
                "earliest_events": earliest_events,
                "latest_events": latest_events,
            },
            timeout=timeout,
        )

    async def get_room_complexity(self, destination: str, room_id: str) -> JsonDict:
        """
        Args:
            destination: The remote server
            room_id: The room ID to ask about.
        """
        path = _create_path(FEDERATION_UNSTABLE_PREFIX, "/rooms/%s/complexity", room_id)

        return await self.client.get_json(destination=destination, path=path)

    async def get_room_hierarchy(
        self, destination: str, room_id: str, suggested_only: bool
    ) -> JsonDict:
        """
        Args:
            destination: The remote server
            room_id: The room ID to ask about.
            suggested_only: if True, only suggested rooms will be returned
        """
        path = _create_v1_path("/hierarchy/%s", room_id)

        return await self.client.get_json(
            destination=destination,
            path=path,
            args={"suggested_only": "true" if suggested_only else "false"},
        )

    async def get_room_hierarchy_unstable(
        self, destination: str, room_id: str, suggested_only: bool
    ) -> JsonDict:
        """
        Args:
            destination: The remote server
            room_id: The room ID to ask about.
            suggested_only: if True, only suggested rooms will be returned
        """
        path = _create_path(
            FEDERATION_UNSTABLE_PREFIX, "/org.matrix.msc2946/hierarchy/%s", room_id
        )

        return await self.client.get_json(
            destination=destination,
            path=path,
            args={"suggested_only": "true" if suggested_only else "false"},
        )

    async def get_account_status(
        self, destination: str, user_ids: List[str]
    ) -> JsonDict:
        """
        Args:
            destination: The remote server.
            user_ids: The user ID(s) for which to request account status(es).
        """
        path = _create_path(
            FEDERATION_UNSTABLE_PREFIX, "/org.matrix.msc3720/account_status"
        )

        return await self.client.post_json(
            destination=destination, path=path, data={"user_ids": user_ids}
        )


def _create_path(federation_prefix: str, path: str, *args: str) -> str:
    """
    Ensures that all args are url encoded.
    """
    return federation_prefix + path % tuple(urllib.parse.quote(arg, "") for arg in args)


def _create_v1_path(path: str, *args: str) -> str:
    """Creates a path against V1 federation API from the path template and
    args. Ensures that all args are url encoded.

    Example:

        _create_v1_path("/event/%s", event_id)

    Args:
        path: String template for the path
        args: Args to insert into path. Each arg will be url encoded
    """
    return _create_path(FEDERATION_V1_PREFIX, path, *args)


def _create_v2_path(path: str, *args: str) -> str:
    """Creates a path against V2 federation API from the path template and
    args. Ensures that all args are url encoded.

    Example:

        _create_v2_path("/event/%s", event_id)

    Args:
        path: String template for the path
        args: Args to insert into path. Each arg will be url encoded
    """
    return _create_path(FEDERATION_V2_PREFIX, path, *args)


@attr.s(slots=True, auto_attribs=True)
class SendJoinResponse:
    """The parsed response of a `/send_join` request."""

    # The list of auth events from the /send_join response.
    auth_events: List[EventBase]
    # The list of state from the /send_join response.
    state: List[EventBase]
    # The raw join event from the /send_join response.
    event_dict: JsonDict
    # The parsed join event from the /send_join response. This will be None if
    # "event" is not included in the response.
    event: Optional[EventBase] = None

    # The room state is incomplete
    partial_state: bool = False

    # List of servers in the room
    servers_in_room: Optional[List[str]] = None


@attr.s(slots=True, auto_attribs=True)
class StateRequestResponse:
    """The parsed response of a `/state` request."""

    auth_events: List[EventBase]
    state: List[EventBase]


@ijson.coroutine
def _event_parser(event_dict: JsonDict) -> Generator[None, Tuple[str, Any], None]:
    """Helper function for use with `ijson.kvitems_coro` to parse key-value pairs
    to add them to a given dictionary.
    """

    while True:
        key, value = yield
        event_dict[key] = value


@ijson.coroutine
def _event_list_parser(
    room_version: RoomVersion, events: List[EventBase]
) -> Generator[None, JsonDict, None]:
    """Helper function for use with `ijson.items_coro` to parse an array of
    events and add them to the given list.
    """

    while True:
        obj = yield
        event = make_event_from_dict(obj, room_version)
        events.append(event)


@ijson.coroutine
def _partial_state_parser(response: SendJoinResponse) -> Generator[None, Any, None]:
    """Helper function for use with `ijson.items_coro`

    Parses the partial_state field in send_join responses
    """
    while True:
        val = yield
        if not isinstance(val, bool):
            raise TypeError("partial_state must be a boolean")
        response.partial_state = val


@ijson.coroutine
def _servers_in_room_parser(response: SendJoinResponse) -> Generator[None, Any, None]:
    """Helper function for use with `ijson.items_coro`

    Parses the servers_in_room field in send_join responses
    """
    while True:
        val = yield
        if not isinstance(val, list) or any(not isinstance(x, str) for x in val):
            raise TypeError("servers_in_room must be a list of strings")
        response.servers_in_room = val


class SendJoinParser(ByteParser[SendJoinResponse]):
    """A parser for the response to `/send_join` requests.

    Args:
        room_version: The version of the room.
        v1_api: Whether the response is in the v1 format.
    """

    CONTENT_TYPE = "application/json"

    # /send_join responses can be huge, so we override the size limit here. The response
    # is parsed in a streaming manner, which helps alleviate the issue of memory
    # usage a bit.
    MAX_RESPONSE_SIZE = 500 * 1024 * 1024

    def __init__(self, room_version: RoomVersion, v1_api: bool):
        self._response = SendJoinResponse([], [], event_dict={})
        self._room_version = room_version
        self._coros: List[Generator[None, bytes, None]] = []

        # The V1 API has the shape of `[200, {...}]`, which we handle by
        # prefixing with `item.*`.
        prefix = "item." if v1_api else ""

        self._coros = [
            ijson.items_coro(
                _event_list_parser(room_version, self._response.state),
                prefix + "state.item",
                use_float=True,
            ),
            ijson.items_coro(
                _event_list_parser(room_version, self._response.auth_events),
                prefix + "auth_chain.item",
                use_float=True,
            ),
            ijson.kvitems_coro(
                _event_parser(self._response.event_dict),
                prefix + "event",
                use_float=True,
            ),
        ]

        if not v1_api:
            self._coros.append(
                ijson.items_coro(
                    _partial_state_parser(self._response),
                    "org.matrix.msc3706.partial_state",
                    use_float="True",
                )
            )

            self._coros.append(
                ijson.items_coro(
                    _servers_in_room_parser(self._response),
                    "org.matrix.msc3706.servers_in_room",
                    use_float="True",
                )
            )

    def write(self, data: bytes) -> int:
        for c in self._coros:
            c.send(data)

        return len(data)

    def finish(self) -> SendJoinResponse:
        for c in self._coros:
            c.close()

        if self._response.event_dict:
            self._response.event = make_event_from_dict(
                self._response.event_dict, self._room_version
            )
        return self._response


class _StateParser(ByteParser[StateRequestResponse]):
    """A parser for the response to `/state` requests.

    Args:
        room_version: The version of the room.
    """

    CONTENT_TYPE = "application/json"

    # As with /send_join, /state responses can be huge.
    MAX_RESPONSE_SIZE = 500 * 1024 * 1024

    def __init__(self, room_version: RoomVersion):
        self._response = StateRequestResponse([], [])
        self._room_version = room_version
        self._coros: List[Generator[None, bytes, None]] = [
            ijson.items_coro(
                _event_list_parser(room_version, self._response.state),
                "pdus.item",
                use_float=True,
            ),
            ijson.items_coro(
                _event_list_parser(room_version, self._response.auth_events),
                "auth_chain.item",
                use_float=True,
            ),
        ]

    def write(self, data: bytes) -> int:
        for c in self._coros:
            c.send(data)
        return len(data)

    def finish(self) -> StateRequestResponse:
        for c in self._coros:
            c.close()
        return self._response
