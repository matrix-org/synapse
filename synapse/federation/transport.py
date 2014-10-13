# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

"""The transport layer is responsible for both sending transactions to remote
home servers and receiving a variety of requests from other home servers.

Typically, this is done over HTTP (and all home servers are required to
support HTTP), however individual pairings of servers may decide to communicate
over a different (albeit still reliable) protocol.
"""

from twisted.internet import defer

from synapse.api.urls import FEDERATION_PREFIX as PREFIX
from synapse.util.logutils import log_function

import logging
import json
import re


logger = logging.getLogger(__name__)


class TransportLayer(object):
    """This is a basic implementation of the transport layer that translates
    transactions and other requests to/from HTTP.

    Attributes:
        server_name (str): Local home server host

        server (synapse.http.server.HttpServer): the http server to
                register listeners on

        client (synapse.http.client.HttpClient): the http client used to
                send requests

        request_handler (TransportRequestHandler): The handler to fire when we
            receive requests for data.

        received_handler (TransportReceivedHandler): The handler to fire when
            we receive data.
    """

    def __init__(self, homeserver, server_name, server, client):
        """
        Args:
            server_name (str): Local home server host
            server (synapse.protocol.http.HttpServer): the http server to
                register listeners on
            client (synapse.protocol.http.HttpClient): the http client used to
                send requests
        """
        self.keyring = homeserver.get_keyring()
        self.server_name = server_name
        self.server = server
        self.client = client
        self.request_handler = None
        self.received_handler = None

    @log_function
    def get_context_state(self, destination, context):
        """ Requests all state for a given context (i.e. room) from the
        given server.

        Args:
            destination (str): The host name of the remote home server we want
                to get the state from.
            context (str): The name of the context we want the state of

        Returns:
            Deferred: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_context_state dest=%s, context=%s",
                     destination, context)

        subpath = "/state/%s/" % context

        return self._do_request_for_transaction(destination, subpath)

    @log_function
    def get_pdu(self, destination, pdu_origin, pdu_id):
        """ Requests the pdu with give id and origin from the given server.

        Args:
            destination (str): The host name of the remote home server we want
                to get the state from.
            pdu_origin (str): The home server which created the PDU.
            pdu_id (str): The id of the PDU being requested.

        Returns:
            Deferred: Results in a dict received from the remote homeserver.
        """
        logger.debug("get_pdu dest=%s, pdu_origin=%s, pdu_id=%s",
                     destination, pdu_origin, pdu_id)

        subpath = "/pdu/%s/%s/" % (pdu_origin, pdu_id)

        return self._do_request_for_transaction(destination, subpath)

    @log_function
    def backfill(self, dest, context, pdu_tuples, limit):
        """ Requests `limit` previous PDUs in a given context before list of
        PDUs.

        Args:
            dest (str)
            context (str)
            pdu_tuples (list)
            limt (int)

        Returns:
            Deferred: Results in a dict received from the remote homeserver.
        """
        logger.debug(
            "backfill dest=%s, context=%s, pdu_tuples=%s, limit=%s",
            dest, context, repr(pdu_tuples), str(limit)
        )

        if not pdu_tuples:
            return

        subpath = "/backfill/%s/" % context

        args = {"v": ["%s,%s" % (i, o) for i, o in pdu_tuples]}
        args["limit"] = limit

        return self._do_request_for_transaction(
            dest,
            subpath,
            args=args,
        )

    @defer.inlineCallbacks
    @log_function
    def send_transaction(self, transaction, json_data_callback=None):
        """ Sends the given Transaction to it's destination

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

        code, response = yield self.client.put_json(
            transaction.destination,
            path=PREFIX + "/send/%s/" % transaction.transaction_id,
            data=json_data,
            json_data_callback=json_data_callback,
        )

        logger.debug(
            "send_data dest=%s, txid=%s, got response: %d",
            transaction.destination, transaction.transaction_id, code
        )

        defer.returnValue((code, response))

    @defer.inlineCallbacks
    @log_function
    def make_query(self, destination, query_type, args, retry_on_dns_fail):
        path = PREFIX + "/query/%s" % query_type

        response = yield self.client.get_json(
            destination=destination,
            path=path,
            args=args,
            retry_on_dns_fail=retry_on_dns_fail,
        )

        defer.returnValue(response)

    @defer.inlineCallbacks
    def _authenticate_request(self, request):
        json_request = {
            "method": request.method,
            "uri": request.uri,
            "destination": self.server_name,
            "signatures": {},
        }

        content = None
        origin = None

        if request.method == "PUT":
            #TODO: Handle other method types? other content types?
            content_bytes = request.content.read()
            content = json.loads(content_bytes)
            json_request["content"] = content

        def parse_auth_header(header_str):
            params = auth.split(" ")[1].split(",")
            param_dict = dict(kv.split("=") for kv in params)
            def strip_quotes(value):
                if value.startswith("\""):
                    return value[1:-1]
                else:
                    return value
            origin = strip_quotes(param_dict["origin"])
            key = strip_quotes(param_dict["key"])
            sig = strip_quotes(param_dict["sig"])
            return (origin, key, sig)

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")

        if not auth_headers:
            #TODO(markjh): Send a 401 response?
            raise Exception("Missing auth headers")

        for auth in auth_headers:
            if auth.startswith("X-Matrix"):
                (origin, key, sig) = parse_auth_header(auth)
                json_request["origin"] = origin
                json_request["signatures"].setdefault(origin,{})[key] = sig

        from syutil.jsonutil import encode_canonical_json
        logger.debug("Checking  %s %s",
            origin, encode_canonical_json(json_request))
        yield self.keyring.verify_json_for_server(origin, json_request)

        defer.returnValue((origin, content))

    def _with_authentication(self, handler):
        @defer.inlineCallbacks
        def new_handler(request, *args, **kwargs):
            (origin, content) = yield self._authenticate_request(request)
            response = yield handler(
                origin, content, request.args, *args, **kwargs
            )
            defer.returnValue(response)
        return new_handler

    @log_function
    def register_received_handler(self, handler):
        """ Register a handler that will be fired when we receive data.

        Args:
            handler (TransportReceivedHandler)
        """
        self.received_handler = handler

        # This is when someone is trying to send us a bunch of data.
        self.server.register_path(
            "PUT",
            re.compile("^" + PREFIX + "/send/([^/]*)/$"),
            self._with_authentication(self._on_send_request)
        )

    @log_function
    def register_request_handler(self, handler):
        """ Register a handler that will be fired when we get asked for data.

        Args:
            handler (TransportRequestHandler)
        """
        self.request_handler = handler

        # TODO(markjh): Namespace the federation URI paths

        # This is for when someone asks us for everything since version X
        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/pull/$"),
            self._with_authentication(
                lambda origin, content, query:
                handler.on_pull_request(query["origin"][0], query["v"])
            )
        )

        # This is when someone asks for a data item for a given server
        # data_id pair.
        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/pdu/([^/]*)/([^/]*)/$"),
            self._with_authentication(
                lambda origin, content, query, pdu_origin, pdu_id:
                handler.on_pdu_request(pdu_origin, pdu_id)
            )
        )

        # This is when someone asks for all data for a given context.
        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/state/([^/]*)/$"),
            self._with_authentication(
                lambda origin, content, query, context:
                handler.on_context_state_request(context)
            )
        )

        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/backfill/([^/]*)/$"),
            self._with_authentication(
                lambda origin, content, query, context:
                self._on_backfill_request(
                    context, query["v"], query["limit"]
                )
            )
        )

        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/context/([^/]*)/$"),
            self._with_authentication(
                lambda origin, content, query, context:
                handler.on_context_pdus_request(context)
            )
        )

        # This is when we receive a server-server Query
        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/query/([^/]*)$"),
            self._with_authentication(
                lambda origin, content, query, query_type:
                handler.on_query_request(
                    query_type, {k: v[0] for k, v in query.items()}
                )
            )
        )

    @defer.inlineCallbacks
    @log_function
    def _on_send_request(self, origin, content, query, transaction_id):
        """ Called on PUT /send/<transaction_id>/

        Args:
            request (twisted.web.http.Request): The HTTP request.
            transaction_id (str): The transaction_id associated with this
                request. This is *not* None.

        Returns:
            Deferred: Results in a tuple of `(code, response)`, where
            `response` is a python dict to be converted into JSON that is
            used as the response body.
        """
        # Parse the request
        try:
            transaction_data = content

            logger.debug(
                "Decoded %s: %s",
                transaction_id, str(transaction_data)
            )

            # We should ideally be getting this from the security layer.
            # origin = body["origin"]

            # Add some extra data to the transaction dict that isn't included
            # in the request body.
            transaction_data.update(
                transaction_id=transaction_id,
                destination=self.server_name
            )

        except Exception as e:
            logger.exception(e)
            defer.returnValue((400, {"error": "Invalid transaction"}))
            return

        code, response = yield self.received_handler.on_incoming_transaction(
            transaction_data
        )

        defer.returnValue((code, response))

    @defer.inlineCallbacks
    @log_function
    def _do_request_for_transaction(self, destination, subpath, args={}):
        """
        Args:
            destination (str)
            path (str)
            args (dict): This is parsed directly to the HttpClient.

        Returns:
            Deferred: Results in a dict.
        """

        data = yield self.client.get_json(
            destination,
            path=PREFIX + subpath,
            args=args,
        )

        # Add certain keys to the JSON, ready for decoding as a Transaction
        data.update(
            origin=destination,
            destination=self.server_name,
            transaction_id=None
        )

        defer.returnValue(data)

    @log_function
    def _on_backfill_request(self, context, v_list, limits):
        if not limits:
            return defer.succeed(
                (400, {"error": "Did not include limit param"})
            )

        limit = int(limits[-1])

        versions = [v.split(",", 1) for v in v_list]

        return self.request_handler.on_backfill_request(
            context, versions, limit)


class TransportReceivedHandler(object):
    """ Callbacks used when we receive a transaction
    """
    def on_incoming_transaction(self, transaction):
        """ Called on PUT /send/<transaction_id>, or on response to a request
        that we sent (e.g. a backfill request)

        Args:
            transaction (synapse.transaction.Transaction): The transaction that
                was sent to us.

        Returns:
            twisted.internet.defer.Deferred: A deferred that gets fired when
            the transaction has finished being processed.

            The result should be a tuple in the form of
            `(response_code, respond_body)`, where `response_body` is a python
            dict that will get serialized to JSON.

            On errors, the dict should have an `error` key with a brief message
            of what went wrong.
        """
        pass


class TransportRequestHandler(object):
    """ Handlers used when someone want's data from us
    """
    def on_pull_request(self, versions):
        """ Called on GET /pull/?v=...

        This is hit when a remote home server wants to get all data
        after a given transaction. Mainly used when a home server comes back
        online and wants to get everything it has missed.

        Args:
            versions (list): A list of transaction_ids that should be used to
                determine what PDUs the remote side have not yet seen.

        Returns:
            Deferred: Resultsin a tuple in the form of
            `(response_code, respond_body)`, where `response_body` is a python
            dict that will get serialized to JSON.

            On errors, the dict should have an `error` key with a brief message
            of what went wrong.
        """
        pass

    def on_pdu_request(self, pdu_origin, pdu_id):
        """ Called on GET /pdu/<pdu_origin>/<pdu_id>/

        Someone wants a particular PDU. This PDU may or may not have originated
        from us.

        Args:
            pdu_origin (str)
            pdu_id (str)

        Returns:
            Deferred: Resultsin a tuple in the form of
            `(response_code, respond_body)`, where `response_body` is a python
            dict that will get serialized to JSON.

            On errors, the dict should have an `error` key with a brief message
            of what went wrong.
        """
        pass

    def on_context_state_request(self, context):
        """ Called on GET /state/<context>/

        Gets hit when someone wants all the *current* state for a given
        contexts.

        Args:
            context (str): The name of the context that we're interested in.

        Returns:
            twisted.internet.defer.Deferred: A deferred that gets fired when
            the transaction has finished being processed.

            The result should be a tuple in the form of
            `(response_code, respond_body)`, where `response_body` is a python
            dict that will get serialized to JSON.

            On errors, the dict should have an `error` key with a brief message
            of what went wrong.
        """
        pass

    def on_backfill_request(self, context, versions, limit):
        """ Called on GET /backfill/<context>/?v=...&limit=...

        Gets hit when we want to backfill backwards on a given context from
        the given point.

        Args:
            context (str): The context to backfill
            versions (list): A list of 2-tuples representing where to backfill
                from, in the form `(pdu_id, origin)`
            limit (int): How many pdus to return.

        Returns:
            Deferred: Results in a tuple in the form of
            `(response_code, respond_body)`, where `response_body` is a python
            dict that will get serialized to JSON.

            On errors, the dict should have an `error` key with a brief message
            of what went wrong.
        """
        pass

    def on_query_request(self):
        """ Called on a GET /query/<query_type> request. """
