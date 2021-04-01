# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from typing import Any, Dict, List, Optional

from synapse.api.constants import Membership
from synapse.api.errors import Codes, HttpResponseException, SynapseError
from synapse.api.urls import (
    FEDERATION_UNSTABLE_PREFIX,
    FEDERATION_V1_PREFIX,
    FEDERATION_V2_PREFIX,
)
from synapse.logging.utils import log_function
from synapse.types import JsonDict

logger = logging.getLogger(__name__)


class TransportLayerClient:
    """Sends federation HTTP requests to other servers"""

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.client = hs.get_federation_http_client()

    @log_function
    def get_room_state_ids(self, destination, room_id, event_id):
        """Requests all state for a given room from the given server at the
        given event. Returns the state's event_id's

        Args:
            destination (str): The host name of the remote homeserver we want
                to get the state from.
            context (str): The name of the context we want the state of
            event_id (str): The event we want the context at.

        Returns:
            Awaitable: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_room_state_ids dest=%s, room=%s", destination, room_id)

        path = _create_v1_path("/state_ids/%s", room_id)
        return self.client.get_json(
            destination,
            path=path,
            args={"event_id": event_id},
            try_trailing_slash_on_400=True,
        )

    @log_function
    def get_event(self, destination, event_id, timeout=None):
        """Requests the pdu with give id and origin from the given server.

        Args:
            destination (str): The host name of the remote homeserver we want
                to get the state from.
            event_id (str): The id of the event being requested.
            timeout (int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout.

        Returns:
            Awaitable: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_pdu dest=%s, event_id=%s", destination, event_id)

        path = _create_v1_path("/event/%s", event_id)
        return self.client.get_json(
            destination, path=path, timeout=timeout, try_trailing_slash_on_400=True
        )

    @log_function
    def backfill(self, destination, room_id, event_tuples, limit):
        """Requests `limit` previous PDUs in a given context before list of
        PDUs.

        Args:
            dest (str)
            room_id (str)
            event_tuples (list)
            limit (int)

        Returns:
            Awaitable: Results in a dict received from the remote homeserver.
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
            return

        path = _create_v1_path("/backfill/%s", room_id)

        args = {"v": event_tuples, "limit": [str(limit)]}

        return self.client.get_json(
            destination, path=path, args=args, try_trailing_slash_on_400=True
        )

    @log_function
    async def send_transaction(self, transaction, json_data_callback=None):
        """Sends the given Transaction to its destination

        Args:
            transaction (Transaction)

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

        response = await self.client.put_json(
            transaction.destination,
            path=path,
            data=json_data,
            json_data_callback=json_data_callback,
            long_retries=True,
            backoff_on_404=True,  # If we get a 404 the other side has gone
            try_trailing_slash_on_400=True,
        )

        return response

    @log_function
    async def make_query(
        self, destination, query_type, args, retry_on_dns_fail, ignore_backoff=False
    ):
        path = _create_v1_path("/query/%s", query_type)

        content = await self.client.get_json(
            destination=destination,
            path=path,
            args=args,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=10000,
            ignore_backoff=ignore_backoff,
        )

        return content

    @log_function
    async def make_membership_event(
        self, destination, room_id, user_id, membership, params
    ):
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
        valid_memberships = {Membership.JOIN, Membership.LEAVE}
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

        content = await self.client.get_json(
            destination=destination,
            path=path,
            args=params,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=20000,
            ignore_backoff=ignore_backoff,
        )

        return content

    @log_function
    async def send_join_v1(self, destination, room_id, event_id, content):
        path = _create_v1_path("/send_join/%s/%s", room_id, event_id)

        response = await self.client.put_json(
            destination=destination, path=path, data=content
        )

        return response

    @log_function
    async def send_join_v2(self, destination, room_id, event_id, content):
        path = _create_v2_path("/send_join/%s/%s", room_id, event_id)

        response = await self.client.put_json(
            destination=destination, path=path, data=content
        )

        return response

    @log_function
    async def send_leave_v1(self, destination, room_id, event_id, content):
        path = _create_v1_path("/send_leave/%s/%s", room_id, event_id)

        response = await self.client.put_json(
            destination=destination,
            path=path,
            data=content,
            # we want to do our best to send this through. The problem is
            # that if it fails, we won't retry it later, so if the remote
            # server was just having a momentary blip, the room will be out of
            # sync.
            ignore_backoff=True,
        )

        return response

    @log_function
    async def send_leave_v2(self, destination, room_id, event_id, content):
        path = _create_v2_path("/send_leave/%s/%s", room_id, event_id)

        response = await self.client.put_json(
            destination=destination,
            path=path,
            data=content,
            # we want to do our best to send this through. The problem is
            # that if it fails, we won't retry it later, so if the remote
            # server was just having a momentary blip, the room will be out of
            # sync.
            ignore_backoff=True,
        )

        return response

    @log_function
    async def send_invite_v1(self, destination, room_id, event_id, content):
        path = _create_v1_path("/invite/%s/%s", room_id, event_id)

        response = await self.client.put_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

        return response

    @log_function
    async def send_invite_v2(self, destination, room_id, event_id, content):
        path = _create_v2_path("/invite/%s/%s", room_id, event_id)

        response = await self.client.put_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

        return response

    @log_function
    async def get_public_rooms(
        self,
        remote_server: str,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[Dict] = None,
        include_all_networks: bool = False,
        third_party_instance_id: Optional[str] = None,
    ):
        """Get the list of public rooms from a remote homeserver

        See synapse.federation.federation_client.FederationClient.get_public_rooms for
        more information.
        """
        if search_filter:
            # this uses MSC2197 (Search Filtering over Federation)
            path = _create_v1_path("/publicRooms")

            data = {
                "include_all_networks": "true" if include_all_networks else "false"
            }  # type: Dict[str, Any]
            if third_party_instance_id:
                data["third_party_instance_id"] = third_party_instance_id
            if limit:
                data["limit"] = str(limit)
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

            args = {
                "include_all_networks": "true" if include_all_networks else "false"
            }  # type: Dict[str, Any]
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

    @log_function
    async def exchange_third_party_invite(self, destination, room_id, event_dict):
        path = _create_v1_path("/exchange_third_party_invite/%s", room_id)

        response = await self.client.put_json(
            destination=destination, path=path, data=event_dict
        )

        return response

    @log_function
    async def get_event_auth(self, destination, room_id, event_id):
        path = _create_v1_path("/event_auth/%s/%s", room_id, event_id)

        content = await self.client.get_json(destination=destination, path=path)

        return content

    @log_function
    async def query_client_keys(self, destination, query_content, timeout):
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
            destination(str): The server to query.
            query_content(dict): The user ids to query.
        Returns:
            A dict containing device and cross-signing keys.
        """
        path = _create_v1_path("/user/keys/query")

        content = await self.client.post_json(
            destination=destination, path=path, data=query_content, timeout=timeout
        )
        return content

    @log_function
    async def query_user_devices(self, destination, user_id, timeout):
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
            destination(str): The server to query.
            query_content(dict): The user ids to query.
        Returns:
            A dict containing device and cross-signing keys.
        """
        path = _create_v1_path("/user/devices/%s", user_id)

        content = await self.client.get_json(
            destination=destination, path=path, timeout=timeout
        )
        return content

    @log_function
    async def claim_client_keys(self, destination, query_content, timeout):
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
            destination(str): The server to query.
            query_content(dict): The user ids to query.
        Returns:
            A dict containing the one-time keys.
        """

        path = _create_v1_path("/user/keys/claim")

        content = await self.client.post_json(
            destination=destination, path=path, data=query_content, timeout=timeout
        )
        return content

    @log_function
    async def get_missing_events(
        self,
        destination,
        room_id,
        earliest_events,
        latest_events,
        limit,
        min_depth,
        timeout,
    ):
        path = _create_v1_path("/get_missing_events/%s", room_id)

        content = await self.client.post_json(
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

        return content

    @log_function
    def get_group_profile(self, destination, group_id, requester_user_id):
        """Get a group profile"""
        path = _create_v1_path("/groups/%s/profile", group_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def update_group_profile(self, destination, group_id, requester_user_id, content):
        """Update a remote group profile

        Args:
            destination (str)
            group_id (str)
            requester_user_id (str)
            content (dict): The new profile of the group
        """
        path = _create_v1_path("/groups/%s/profile", group_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def get_group_summary(self, destination, group_id, requester_user_id):
        """Get a group summary"""
        path = _create_v1_path("/groups/%s/summary", group_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def get_rooms_in_group(self, destination, group_id, requester_user_id):
        """Get all rooms in a group"""
        path = _create_v1_path("/groups/%s/rooms", group_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    def add_room_to_group(
        self, destination, group_id, requester_user_id, room_id, content
    ):
        """Add a room to a group"""
        path = _create_v1_path("/groups/%s/room/%s", group_id, room_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    def update_room_in_group(
        self, destination, group_id, requester_user_id, room_id, config_key, content
    ):
        """Update room in group"""
        path = _create_v1_path(
            "/groups/%s/room/%s/config/%s", group_id, room_id, config_key
        )

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    def remove_room_from_group(self, destination, group_id, requester_user_id, room_id):
        """Remove a room from a group"""
        path = _create_v1_path("/groups/%s/room/%s", group_id, room_id)

        return self.client.delete_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def get_users_in_group(self, destination, group_id, requester_user_id):
        """Get users in a group"""
        path = _create_v1_path("/groups/%s/users", group_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def get_invited_users_in_group(self, destination, group_id, requester_user_id):
        """Get users that have been invited to a group"""
        path = _create_v1_path("/groups/%s/invited_users", group_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def accept_group_invite(self, destination, group_id, user_id, content):
        """Accept a group invite"""
        path = _create_v1_path("/groups/%s/users/%s/accept_invite", group_id, user_id)

        return self.client.post_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    @log_function
    def join_group(self, destination, group_id, user_id, content):
        """Attempts to join a group"""
        path = _create_v1_path("/groups/%s/users/%s/join", group_id, user_id)

        return self.client.post_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    @log_function
    def invite_to_group(
        self, destination, group_id, user_id, requester_user_id, content
    ):
        """Invite a user to a group"""
        path = _create_v1_path("/groups/%s/users/%s/invite", group_id, user_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def invite_to_group_notification(self, destination, group_id, user_id, content):
        """Sent by group server to inform a user's server that they have been
        invited.
        """

        path = _create_v1_path("/groups/local/%s/users/%s/invite", group_id, user_id)

        return self.client.post_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    @log_function
    def remove_user_from_group(
        self, destination, group_id, requester_user_id, user_id, content
    ):
        """Remove a user from a group"""
        path = _create_v1_path("/groups/%s/users/%s/remove", group_id, user_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def remove_user_from_group_notification(
        self, destination, group_id, user_id, content
    ):
        """Sent by group server to inform a user's server that they have been
        kicked from the group.
        """

        path = _create_v1_path("/groups/local/%s/users/%s/remove", group_id, user_id)

        return self.client.post_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    @log_function
    def renew_group_attestation(self, destination, group_id, user_id, content):
        """Sent by either a group server or a user's server to periodically update
        the attestations
        """

        path = _create_v1_path("/groups/%s/renew_attestation/%s", group_id, user_id)

        return self.client.post_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    @log_function
    def update_group_summary_room(
        self, destination, group_id, user_id, room_id, category_id, content
    ):
        """Update a room entry in a group summary"""
        if category_id:
            path = _create_v1_path(
                "/groups/%s/summary/categories/%s/rooms/%s",
                group_id,
                category_id,
                room_id,
            )
        else:
            path = _create_v1_path("/groups/%s/summary/rooms/%s", group_id, room_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def delete_group_summary_room(
        self, destination, group_id, user_id, room_id, category_id
    ):
        """Delete a room entry in a group summary"""
        if category_id:
            path = _create_v1_path(
                "/groups/%s/summary/categories/%s/rooms/%s",
                group_id,
                category_id,
                room_id,
            )
        else:
            path = _create_v1_path("/groups/%s/summary/rooms/%s", group_id, room_id)

        return self.client.delete_json(
            destination=destination,
            path=path,
            args={"requester_user_id": user_id},
            ignore_backoff=True,
        )

    @log_function
    def get_group_categories(self, destination, group_id, requester_user_id):
        """Get all categories in a group"""
        path = _create_v1_path("/groups/%s/categories", group_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def get_group_category(self, destination, group_id, requester_user_id, category_id):
        """Get category info in a group"""
        path = _create_v1_path("/groups/%s/categories/%s", group_id, category_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def update_group_category(
        self, destination, group_id, requester_user_id, category_id, content
    ):
        """Update a category in a group"""
        path = _create_v1_path("/groups/%s/categories/%s", group_id, category_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def delete_group_category(
        self, destination, group_id, requester_user_id, category_id
    ):
        """Delete a category in a group"""
        path = _create_v1_path("/groups/%s/categories/%s", group_id, category_id)

        return self.client.delete_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def get_group_roles(self, destination, group_id, requester_user_id):
        """Get all roles in a group"""
        path = _create_v1_path("/groups/%s/roles", group_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def get_group_role(self, destination, group_id, requester_user_id, role_id):
        """Get a roles info"""
        path = _create_v1_path("/groups/%s/roles/%s", group_id, role_id)

        return self.client.get_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def update_group_role(
        self, destination, group_id, requester_user_id, role_id, content
    ):
        """Update a role in a group"""
        path = _create_v1_path("/groups/%s/roles/%s", group_id, role_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def delete_group_role(self, destination, group_id, requester_user_id, role_id):
        """Delete a role in a group"""
        path = _create_v1_path("/groups/%s/roles/%s", group_id, role_id)

        return self.client.delete_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    @log_function
    def update_group_summary_user(
        self, destination, group_id, requester_user_id, user_id, role_id, content
    ):
        """Update a users entry in a group"""
        if role_id:
            path = _create_v1_path(
                "/groups/%s/summary/roles/%s/users/%s", group_id, role_id, user_id
            )
        else:
            path = _create_v1_path("/groups/%s/summary/users/%s", group_id, user_id)

        return self.client.post_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def set_group_join_policy(self, destination, group_id, requester_user_id, content):
        """Sets the join policy for a group"""
        path = _create_v1_path("/groups/%s/settings/m.join_policy", group_id)

        return self.client.put_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            data=content,
            ignore_backoff=True,
        )

    @log_function
    def delete_group_summary_user(
        self, destination, group_id, requester_user_id, user_id, role_id
    ):
        """Delete a users entry in a group"""
        if role_id:
            path = _create_v1_path(
                "/groups/%s/summary/roles/%s/users/%s", group_id, role_id, user_id
            )
        else:
            path = _create_v1_path("/groups/%s/summary/users/%s", group_id, user_id)

        return self.client.delete_json(
            destination=destination,
            path=path,
            args={"requester_user_id": requester_user_id},
            ignore_backoff=True,
        )

    def bulk_get_publicised_groups(self, destination, user_ids):
        """Get the groups a list of users are publicising"""

        path = _create_v1_path("/get_groups_publicised")

        content = {"user_ids": user_ids}

        return self.client.post_json(
            destination=destination, path=path, data=content, ignore_backoff=True
        )

    def get_room_complexity(self, destination, room_id):
        """
        Args:
            destination (str): The remote server
            room_id (str): The room ID to ask about.
        """
        path = _create_path(FEDERATION_UNSTABLE_PREFIX, "/rooms/%s/complexity", room_id)

        return self.client.get_json(destination=destination, path=path)

    async def get_space_summary(
        self,
        destination: str,
        room_id: str,
        suggested_only: bool,
        max_rooms_per_space: Optional[int],
        exclude_rooms: List[str],
    ) -> JsonDict:
        """
        Args:
            destination: The remote server
            room_id: The room ID to ask about.
            suggested_only: if True, only suggested rooms will be returned
            max_rooms_per_space: an optional limit to the number of children to be
               returned per space
            exclude_rooms: a list of any rooms we can skip
        """
        path = _create_path(
            FEDERATION_UNSTABLE_PREFIX, "/org.matrix.msc2946/spaces/%s", room_id
        )

        params = {
            "suggested_only": suggested_only,
            "exclude_rooms": exclude_rooms,
        }
        if max_rooms_per_space is not None:
            params["max_rooms_per_space"] = max_rooms_per_space

        return await self.client.post_json(
            destination=destination, path=path, data=params
        )


def _create_path(federation_prefix, path, *args):
    """
    Ensures that all args are url encoded.
    """
    return federation_prefix + path % tuple(urllib.parse.quote(arg, "") for arg in args)


def _create_v1_path(path, *args):
    """Creates a path against V1 federation API from the path template and
    args. Ensures that all args are url encoded.

    Example:

        _create_v1_path("/event/%s", event_id)

    Args:
        path (str): String template for the path
        args: ([str]): Args to insert into path. Each arg will be url encoded

    Returns:
        str
    """
    return _create_path(FEDERATION_V1_PREFIX, path, *args)


def _create_v2_path(path, *args):
    """Creates a path against V2 federation API from the path template and
    args. Ensures that all args are url encoded.

    Example:

        _create_v2_path("/event/%s", event_id)

    Args:
        path (str): String template for the path
        args: ([str]): Args to insert into path. Each arg will be url encoded

    Returns:
        str
    """
    return _create_path(FEDERATION_V2_PREFIX, path, *args)
