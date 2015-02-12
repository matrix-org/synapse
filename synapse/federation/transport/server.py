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

from twisted.internet import defer

from synapse.api.urls import FEDERATION_PREFIX as PREFIX
from synapse.api.errors import Codes, SynapseError
from synapse.util.logutils import log_function

import logging
import simplejson as json
import re


logger = logging.getLogger(__name__)


class TransportLayerServer(object):
    """Handles incoming federation HTTP requests"""

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

        if request.method in ["PUT", "POST"]:
            # TODO: Handle other method types? other content types?
            try:
                content_bytes = request.content.read()
                content = json.loads(content_bytes)
                json_request["content"] = content
            except:
                raise SynapseError(400, "Unable to parse JSON", Codes.BAD_JSON)

        def parse_auth_header(header_str):
            try:
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
            except:
                raise SynapseError(
                    400, "Malformed Authorization header", Codes.UNAUTHORIZED
                )

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")

        if not auth_headers:
            raise SynapseError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED,
            )

        for auth in auth_headers:
            if auth.startswith("X-Matrix"):
                (origin, key, sig) = parse_auth_header(auth)
                json_request["origin"] = origin
                json_request["signatures"].setdefault(origin, {})[key] = sig

        if not json_request["signatures"]:
            raise SynapseError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED,
            )

        yield self.keyring.verify_json_for_server(origin, json_request)

        defer.returnValue((origin, content))

    def _with_authentication(self, handler):
        @defer.inlineCallbacks
        def new_handler(request, *args, **kwargs):
            try:
                (origin, content) = yield self._authenticate_request(request)
                response = yield handler(
                    origin, content, request.args, *args, **kwargs
                )
            except:
                logger.exception("_authenticate_request failed")
                raise
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
            re.compile("^" + PREFIX + "/event/([^/]*)/$"),
            self._with_authentication(
                lambda origin, content, query, event_id:
                handler.on_pdu_request(origin, event_id)
            )
        )

        # This is when someone asks for all data for a given context.
        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/state/([^/]*)/$"),
            self._with_authentication(
                lambda origin, content, query, context:
                handler.on_context_state_request(
                    origin,
                    context,
                    query.get("event_id", [None])[0],
                )
            )
        )

        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/backfill/([^/]*)/$"),
            self._with_authentication(
                lambda origin, content, query, context:
                self._on_backfill_request(
                    origin, context, query["v"], query["limit"]
                )
            )
        )

        # This is when we receive a server-server Query
        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/query/([^/]*)$"),
            self._with_authentication(
                lambda origin, content, query, query_type:
                handler.on_query_request(
                    query_type,
                    {k: v[0].decode("utf-8") for k, v in query.items()}
                )
            )
        )

        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/make_join/([^/]*)/([^/]*)$"),
            self._with_authentication(
                lambda origin, content, query, context, user_id:
                self._on_make_join_request(
                    origin, content, query, context, user_id
                )
            )
        )

        self.server.register_path(
            "GET",
            re.compile("^" + PREFIX + "/event_auth/([^/]*)/([^/]*)$"),
            self._with_authentication(
                lambda origin, content, query, context, event_id:
                handler.on_event_auth(
                    origin, context, event_id,
                )
            )
        )

        self.server.register_path(
            "PUT",
            re.compile("^" + PREFIX + "/send_join/([^/]*)/([^/]*)$"),
            self._with_authentication(
                lambda origin, content, query, context, event_id:
                self._on_send_join_request(
                    origin, content, query,
                )
            )
        )

        self.server.register_path(
            "PUT",
            re.compile("^" + PREFIX + "/invite/([^/]*)/([^/]*)$"),
            self._with_authentication(
                lambda origin, content, query, context, event_id:
                self._on_invite_request(
                    origin, content, query,
                )
            )
        )
        self.server.register_path(
            "POST",
            re.compile("^" + PREFIX + "/query_auth/([^/]*)/([^/]*)$"),
            self._with_authentication(
                lambda origin, content, query, context, event_id:
                self._on_query_auth_request(
                    origin, content, event_id,
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

        try:
            handler = self.received_handler
            code, response = yield handler.on_incoming_transaction(
                transaction_data
            )
        except:
            logger.exception("on_incoming_transaction failed")
            raise

        defer.returnValue((code, response))

    @log_function
    def _on_backfill_request(self, origin, context, v_list, limits):
        if not limits:
            return defer.succeed(
                (400, {"error": "Did not include limit param"})
            )

        limit = int(limits[-1])

        versions = v_list

        return self.request_handler.on_backfill_request(
            origin, context, versions, limit
        )

    @defer.inlineCallbacks
    @log_function
    def _on_make_join_request(self, origin, content, query, context, user_id):
        content = yield self.request_handler.on_make_join_request(
            context, user_id,
        )
        defer.returnValue((200, content))

    @defer.inlineCallbacks
    @log_function
    def _on_send_join_request(self, origin, content, query):
        content = yield self.request_handler.on_send_join_request(
            origin, content,
        )

        defer.returnValue((200, content))

    @defer.inlineCallbacks
    @log_function
    def _on_invite_request(self, origin, content, query):
        content = yield self.request_handler.on_invite_request(
            origin, content,
        )

        defer.returnValue((200, content))

    @defer.inlineCallbacks
    @log_function
    def _on_query_auth_request(self, origin, content, event_id):
        new_content = yield self.request_handler.on_query_auth_request(
            origin, content, event_id
        )

        defer.returnValue((200, new_content))
