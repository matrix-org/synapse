# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
from synapse.api.constants import Membership

from synapse.api.urls import FEDERATION_PREFIX as PREFIX
from synapse.util.logutils import log_function

import logging


logger = logging.getLogger(__name__)


class TransportLayerClient(object):
    """Sends federation HTTP requests to other servers"""

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.client = hs.get_http_client()

    @log_function
    def get_room_state(self, destination, room_id, event_id):
        """ Requests all state for a given room from the given server at the
        given event.

        Args:
            destination (str): The host name of the remote home server we want
                to get the state from.
            context (str): The name of the context we want the state of
            event_id (str): The event we want the context at.

        Returns:
            Deferred: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_room_state dest=%s, room=%s",
                     destination, room_id)

        path = PREFIX + "/state/%s/" % room_id
        return self.client.get_json(
            destination, path=path, args={"event_id": event_id},
        )

    @log_function
    def get_room_state_ids(self, destination, room_id, event_id):
        """ Requests all state for a given room from the given server at the
        given event. Returns the state's event_id's

        Args:
            destination (str): The host name of the remote home server we want
                to get the state from.
            context (str): The name of the context we want the state of
            event_id (str): The event we want the context at.

        Returns:
            Deferred: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_room_state_ids dest=%s, room=%s",
                     destination, room_id)

        path = PREFIX + "/state_ids/%s/" % room_id
        return self.client.get_json(
            destination, path=path, args={"event_id": event_id},
        )

    @log_function
    def get_event(self, destination, event_id, timeout=None):
        """ Requests the pdu with give id and origin from the given server.

        Args:
            destination (str): The host name of the remote home server we want
                to get the state from.
            event_id (str): The id of the event being requested.
            timeout (int): How long to try (in ms) the destination for before
                giving up. None indicates no timeout.

        Returns:
            Deferred: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_pdu dest=%s, event_id=%s",
                     destination, event_id)

        path = PREFIX + "/event/%s/" % (event_id, )
        return self.client.get_json(destination, path=path, timeout=timeout)

    @log_function
    def backfill(self, destination, room_id, event_tuples, limit):
        """ Requests `limit` previous PDUs in a given context before list of
        PDUs.

        Args:
            dest (str)
            room_id (str)
            event_tuples (list)
            limt (int)

        Returns:
            Deferred: Results in a dict received from the remote homeserver.
        """
        logger.debug(
            "backfill dest=%s, room_id=%s, event_tuples=%s, limit=%s",
            destination, room_id, repr(event_tuples), str(limit)
        )

        if not event_tuples:
            # TODO: raise?
            return

        path = PREFIX + "/backfill/%s/" % (room_id,)

        args = {
            "v": event_tuples,
            "limit": [str(limit)],
        }

        return self.client.get_json(
            destination,
            path=path,
            args=args,
        )

    @defer.inlineCallbacks
    @log_function
    def send_transaction(self, transaction, json_data_callback=None):
        """ Sends the given Transaction to its destination

        Args:
            transaction (Transaction)

        Returns:
            Deferred: Results of the deferred is a tuple in the form of
            (response_code, response_body) where the response_body is a
            python dict decoded from json
        """
        logger.debug(
            "send_data dest=%s, txid=%s",
            transaction.destination, transaction.transaction_id
        )

        if transaction.destination == self.server_name:
            raise RuntimeError("Transport layer cannot send to itself!")

        # FIXME: This is only used by the tests. The actual json sent is
        # generated by the json_data_callback.
        json_data = transaction.get_dict()

        response = yield self.client.put_json(
            transaction.destination,
            path=PREFIX + "/send/%s/" % transaction.transaction_id,
            data=json_data,
            json_data_callback=json_data_callback,
            long_retries=True,
        )

        logger.debug(
            "send_data dest=%s, txid=%s, got response: 200",
            transaction.destination, transaction.transaction_id,
        )

        defer.returnValue(response)

    @defer.inlineCallbacks
    @log_function
    def make_query(self, destination, query_type, args, retry_on_dns_fail):
        path = PREFIX + "/query/%s" % query_type

        content = yield self.client.get_json(
            destination=destination,
            path=path,
            args=args,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=10000,
        )

        defer.returnValue(content)

    @defer.inlineCallbacks
    @log_function
    def make_membership_event(self, destination, room_id, user_id, membership):
        valid_memberships = {Membership.JOIN, Membership.LEAVE}
        if membership not in valid_memberships:
            raise RuntimeError(
                "make_membership_event called with membership='%s', must be one of %s" %
                (membership, ",".join(valid_memberships))
            )
        path = PREFIX + "/make_%s/%s/%s" % (membership, room_id, user_id)

        content = yield self.client.get_json(
            destination=destination,
            path=path,
            retry_on_dns_fail=False,
            timeout=20000,
        )

        defer.returnValue(content)

    @defer.inlineCallbacks
    @log_function
    def send_join(self, destination, room_id, event_id, content):
        path = PREFIX + "/send_join/%s/%s" % (room_id, event_id)

        response = yield self.client.put_json(
            destination=destination,
            path=path,
            data=content,
        )

        defer.returnValue(response)

    @defer.inlineCallbacks
    @log_function
    def send_leave(self, destination, room_id, event_id, content):
        path = PREFIX + "/send_leave/%s/%s" % (room_id, event_id)

        response = yield self.client.put_json(
            destination=destination,
            path=path,
            data=content,
        )

        defer.returnValue(response)

    @defer.inlineCallbacks
    @log_function
    def send_invite(self, destination, room_id, event_id, content):
        path = PREFIX + "/invite/%s/%s" % (room_id, event_id)

        response = yield self.client.put_json(
            destination=destination,
            path=path,
            data=content,
        )

        defer.returnValue(response)

    @defer.inlineCallbacks
    @log_function
    def get_public_rooms(self, remote_server, limit, since_token,
                         search_filter=None, include_all_networks=False,
                         third_party_instance_id=None):
        path = PREFIX + "/publicRooms"

        args = {
            "include_all_networks": "true" if include_all_networks else "false",
        }
        if third_party_instance_id:
            args["third_party_instance_id"] = third_party_instance_id,
        if limit:
            args["limit"] = [str(limit)]
        if since_token:
            args["since"] = [since_token]

        # TODO(erikj): Actually send the search_filter across federation.

        response = yield self.client.get_json(
            destination=remote_server,
            path=path,
            args=args,
        )

        defer.returnValue(response)

    @defer.inlineCallbacks
    @log_function
    def exchange_third_party_invite(self, destination, room_id, event_dict):
        path = PREFIX + "/exchange_third_party_invite/%s" % (room_id,)

        response = yield self.client.put_json(
            destination=destination,
            path=path,
            data=event_dict,
        )

        defer.returnValue(response)

    @defer.inlineCallbacks
    @log_function
    def get_event_auth(self, destination, room_id, event_id):
        path = PREFIX + "/event_auth/%s/%s" % (room_id, event_id)

        content = yield self.client.get_json(
            destination=destination,
            path=path,
        )

        defer.returnValue(content)

    @defer.inlineCallbacks
    @log_function
    def send_query_auth(self, destination, room_id, event_id, content):
        path = PREFIX + "/query_auth/%s/%s" % (room_id, event_id)

        content = yield self.client.post_json(
            destination=destination,
            path=path,
            data=content,
        )

        defer.returnValue(content)

    @defer.inlineCallbacks
    @log_function
    def query_client_keys(self, destination, query_content, timeout):
        """Query the device keys for a list of user ids hosted on a remote
        server.

        Request:
            {
              "device_keys": {
                "<user_id>": ["<device_id>"]
            } }

        Response:
            {
              "device_keys": {
                "<user_id>": {
                  "<device_id>": {...}
            } } }

        Args:
            destination(str): The server to query.
            query_content(dict): The user ids to query.
        Returns:
            A dict containg the device keys.
        """
        path = PREFIX + "/user/keys/query"

        content = yield self.client.post_json(
            destination=destination,
            path=path,
            data=query_content,
            timeout=timeout,
        )
        defer.returnValue(content)

    @defer.inlineCallbacks
    @log_function
    def query_user_devices(self, destination, user_id, timeout):
        """Query the devices for a user id hosted on a remote server.

        Response:
            {
              "stream_id": "...",
              "devices": [ { ... } ]
            }

        Args:
            destination(str): The server to query.
            query_content(dict): The user ids to query.
        Returns:
            A dict containg the device keys.
        """
        path = PREFIX + "/user/devices/" + user_id

        content = yield self.client.get_json(
            destination=destination,
            path=path,
            timeout=timeout,
        )
        defer.returnValue(content)

    @defer.inlineCallbacks
    @log_function
    def claim_client_keys(self, destination, query_content, timeout):
        """Claim one-time keys for a list of devices hosted on a remote server.

        Request:
            {
              "one_time_keys": {
                "<user_id>": {
                    "<device_id>": "<algorithm>"
            } } }

        Response:
            {
              "device_keys": {
                "<user_id>": {
                  "<device_id>": {
                    "<algorithm>:<key_id>": "<key_base64>"
            } } } }

        Args:
            destination(str): The server to query.
            query_content(dict): The user ids to query.
        Returns:
            A dict containg the one-time keys.
        """

        path = PREFIX + "/user/keys/claim"

        content = yield self.client.post_json(
            destination=destination,
            path=path,
            data=query_content,
            timeout=timeout,
        )
        defer.returnValue(content)

    @defer.inlineCallbacks
    @log_function
    def get_missing_events(self, destination, room_id, earliest_events,
                           latest_events, limit, min_depth, timeout):
        path = PREFIX + "/get_missing_events/%s" % (room_id,)

        content = yield self.client.post_json(
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

        defer.returnValue(content)
