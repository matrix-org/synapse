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

from synapse.api.urls import FEDERATION_PREFIX as PREFIX
from synapse.api.errors import Codes, SynapseError
from synapse.http.server import JsonResource
from synapse.http.servlet import (
    parse_json_object_from_request, parse_integer_from_args, parse_string_from_args,
    parse_boolean_from_args,
)
from synapse.util.ratelimitutils import FederationRateLimiter
from synapse.util.versionstring import get_version_string
from synapse.types import ThirdPartyInstanceID

import functools
import logging
import re
import synapse


logger = logging.getLogger(__name__)


class TransportLayerServer(JsonResource):
    """Handles incoming federation HTTP requests"""

    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()

        super(TransportLayerServer, self).__init__(hs, canonical_json=False)

        self.authenticator = Authenticator(hs)
        self.ratelimiter = FederationRateLimiter(
            self.clock,
            window_size=hs.config.federation_rc_window_size,
            sleep_limit=hs.config.federation_rc_sleep_limit,
            sleep_msec=hs.config.federation_rc_sleep_delay,
            reject_limit=hs.config.federation_rc_reject_limit,
            concurrent_requests=hs.config.federation_rc_concurrent,
        )

        self.register_servlets()

    def register_servlets(self):
        register_servlets(
            self.hs,
            resource=self,
            ratelimiter=self.ratelimiter,
            authenticator=self.authenticator,
        )


class AuthenticationError(SynapseError):
    """There was a problem authenticating the request"""
    pass


class NoAuthenticationError(AuthenticationError):
    """The request had no authentication information"""
    pass


class Authenticator(object):
    def __init__(self, hs):
        self.keyring = hs.get_keyring()
        self.server_name = hs.hostname

    # A method just so we can pass 'self' as the authenticator to the Servlets
    @defer.inlineCallbacks
    def authenticate_request(self, request, content):
        json_request = {
            "method": request.method,
            "uri": request.uri,
            "destination": self.server_name,
            "signatures": {},
        }

        if content is not None:
            json_request["content"] = content

        origin = None

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
                raise AuthenticationError(
                    400, "Malformed Authorization header", Codes.UNAUTHORIZED
                )

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")

        if not auth_headers:
            raise NoAuthenticationError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED,
            )

        for auth in auth_headers:
            if auth.startswith("X-Matrix"):
                (origin, key, sig) = parse_auth_header(auth)
                json_request["origin"] = origin
                json_request["signatures"].setdefault(origin, {})[key] = sig

        if not json_request["signatures"]:
            raise NoAuthenticationError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED,
            )

        yield self.keyring.verify_json_for_server(origin, json_request)

        logger.info("Request from %s", origin)
        request.authenticated_entity = origin

        defer.returnValue(origin)


class BaseFederationServlet(object):
    REQUIRE_AUTH = True

    def __init__(self, handler, authenticator, ratelimiter, server_name,
                 room_list_handler):
        self.handler = handler
        self.authenticator = authenticator
        self.ratelimiter = ratelimiter
        self.room_list_handler = room_list_handler

    def _wrap(self, func):
        authenticator = self.authenticator
        ratelimiter = self.ratelimiter

        @defer.inlineCallbacks
        @functools.wraps(func)
        def new_func(request, *args, **kwargs):
            content = None
            if request.method in ["PUT", "POST"]:
                # TODO: Handle other method types? other content types?
                content = parse_json_object_from_request(request)

            try:
                origin = yield authenticator.authenticate_request(request, content)
            except NoAuthenticationError:
                origin = None
                if self.REQUIRE_AUTH:
                    logger.exception("authenticate_request failed")
                    raise
            except:
                logger.exception("authenticate_request failed")
                raise

            if origin:
                with ratelimiter.ratelimit(origin) as d:
                    yield d
                    response = yield func(
                        origin, content, request.args, *args, **kwargs
                    )
            else:
                response = yield func(
                    origin, content, request.args, *args, **kwargs
                )

            defer.returnValue(response)

        # Extra logic that functools.wraps() doesn't finish
        new_func.__self__ = func.__self__

        return new_func

    def register(self, server):
        pattern = re.compile("^" + PREFIX + self.PATH + "$")

        for method in ("GET", "PUT", "POST"):
            code = getattr(self, "on_%s" % (method), None)
            if code is None:
                continue

            server.register_paths(method, (pattern,), self._wrap(code))


class FederationSendServlet(BaseFederationServlet):
    PATH = "/send/(?P<transaction_id>[^/]*)/"

    def __init__(self, handler, server_name, **kwargs):
        super(FederationSendServlet, self).__init__(
            handler, server_name=server_name, **kwargs
        )
        self.server_name = server_name

    # This is when someone is trying to send us a bunch of data.
    @defer.inlineCallbacks
    def on_PUT(self, origin, content, query, transaction_id):
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

            logger.info(
                "Received txn %s from %s. (PDUs: %d, EDUs: %d, failures: %d)",
                transaction_id, origin,
                len(transaction_data.get("pdus", [])),
                len(transaction_data.get("edus", [])),
                len(transaction_data.get("failures", [])),
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
            code, response = yield self.handler.on_incoming_transaction(
                transaction_data
            )
        except:
            logger.exception("on_incoming_transaction failed")
            raise

        defer.returnValue((code, response))


class FederationPullServlet(BaseFederationServlet):
    PATH = "/pull/"

    # This is for when someone asks us for everything since version X
    def on_GET(self, origin, content, query):
        return self.handler.on_pull_request(query["origin"][0], query["v"])


class FederationEventServlet(BaseFederationServlet):
    PATH = "/event/(?P<event_id>[^/]*)/"

    # This is when someone asks for a data item for a given server data_id pair.
    def on_GET(self, origin, content, query, event_id):
        return self.handler.on_pdu_request(origin, event_id)


class FederationStateServlet(BaseFederationServlet):
    PATH = "/state/(?P<context>[^/]*)/"

    # This is when someone asks for all data for a given context.
    def on_GET(self, origin, content, query, context):
        return self.handler.on_context_state_request(
            origin,
            context,
            query.get("event_id", [None])[0],
        )


class FederationStateIdsServlet(BaseFederationServlet):
    PATH = "/state_ids/(?P<room_id>[^/]*)/"

    def on_GET(self, origin, content, query, room_id):
        return self.handler.on_state_ids_request(
            origin,
            room_id,
            query.get("event_id", [None])[0],
        )


class FederationBackfillServlet(BaseFederationServlet):
    PATH = "/backfill/(?P<context>[^/]*)/"

    def on_GET(self, origin, content, query, context):
        versions = query["v"]
        limits = query["limit"]

        if not limits:
            return defer.succeed((400, {"error": "Did not include limit param"}))

        limit = int(limits[-1])

        return self.handler.on_backfill_request(origin, context, versions, limit)


class FederationQueryServlet(BaseFederationServlet):
    PATH = "/query/(?P<query_type>[^/]*)"

    # This is when we receive a server-server Query
    def on_GET(self, origin, content, query, query_type):
        return self.handler.on_query_request(
            query_type,
            {k: v[0].decode("utf-8") for k, v in query.items()}
        )


class FederationMakeJoinServlet(BaseFederationServlet):
    PATH = "/make_join/(?P<context>[^/]*)/(?P<user_id>[^/]*)"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, context, user_id):
        content = yield self.handler.on_make_join_request(context, user_id)
        defer.returnValue((200, content))


class FederationMakeLeaveServlet(BaseFederationServlet):
    PATH = "/make_leave/(?P<context>[^/]*)/(?P<user_id>[^/]*)"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, context, user_id):
        content = yield self.handler.on_make_leave_request(context, user_id)
        defer.returnValue((200, content))


class FederationSendLeaveServlet(BaseFederationServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<txid>[^/]*)"

    @defer.inlineCallbacks
    def on_PUT(self, origin, content, query, room_id, txid):
        content = yield self.handler.on_send_leave_request(origin, content)
        defer.returnValue((200, content))


class FederationEventAuthServlet(BaseFederationServlet):
    PATH = "/event_auth/(?P<context>[^/]*)/(?P<event_id>[^/]*)"

    def on_GET(self, origin, content, query, context, event_id):
        return self.handler.on_event_auth(origin, context, event_id)


class FederationSendJoinServlet(BaseFederationServlet):
    PATH = "/send_join/(?P<context>[^/]*)/(?P<event_id>[^/]*)"

    @defer.inlineCallbacks
    def on_PUT(self, origin, content, query, context, event_id):
        # TODO(paul): assert that context/event_id parsed from path actually
        #   match those given in content
        content = yield self.handler.on_send_join_request(origin, content)
        defer.returnValue((200, content))


class FederationInviteServlet(BaseFederationServlet):
    PATH = "/invite/(?P<context>[^/]*)/(?P<event_id>[^/]*)"

    @defer.inlineCallbacks
    def on_PUT(self, origin, content, query, context, event_id):
        # TODO(paul): assert that context/event_id parsed from path actually
        #   match those given in content
        content = yield self.handler.on_invite_request(origin, content)
        defer.returnValue((200, content))


class FederationThirdPartyInviteExchangeServlet(BaseFederationServlet):
    PATH = "/exchange_third_party_invite/(?P<room_id>[^/]*)"

    @defer.inlineCallbacks
    def on_PUT(self, origin, content, query, room_id):
        content = yield self.handler.on_exchange_third_party_invite_request(
            origin, room_id, content
        )
        defer.returnValue((200, content))


class FederationClientKeysQueryServlet(BaseFederationServlet):
    PATH = "/user/keys/query"

    def on_POST(self, origin, content, query):
        return self.handler.on_query_client_keys(origin, content)


class FederationUserDevicesQueryServlet(BaseFederationServlet):
    PATH = "/user/devices/(?P<user_id>[^/]*)"

    def on_GET(self, origin, content, query, user_id):
        return self.handler.on_query_user_devices(origin, user_id)


class FederationClientKeysClaimServlet(BaseFederationServlet):
    PATH = "/user/keys/claim"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query):
        response = yield self.handler.on_claim_client_keys(origin, content)
        defer.returnValue((200, response))


class FederationQueryAuthServlet(BaseFederationServlet):
    PATH = "/query_auth/(?P<context>[^/]*)/(?P<event_id>[^/]*)"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, context, event_id):
        new_content = yield self.handler.on_query_auth_request(
            origin, content, context, event_id
        )

        defer.returnValue((200, new_content))


class FederationGetMissingEventsServlet(BaseFederationServlet):
    # TODO(paul): Why does this path alone end with "/?" optional?
    PATH = "/get_missing_events/(?P<room_id>[^/]*)/?"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, room_id):
        limit = int(content.get("limit", 10))
        min_depth = int(content.get("min_depth", 0))
        earliest_events = content.get("earliest_events", [])
        latest_events = content.get("latest_events", [])

        content = yield self.handler.on_get_missing_events(
            origin,
            room_id=room_id,
            earliest_events=earliest_events,
            latest_events=latest_events,
            min_depth=min_depth,
            limit=limit,
        )

        defer.returnValue((200, content))


class On3pidBindServlet(BaseFederationServlet):
    PATH = "/3pid/onbind"

    REQUIRE_AUTH = False

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query):
        if "invites" in content:
            last_exception = None
            for invite in content["invites"]:
                try:
                    if "signed" not in invite or "token" not in invite["signed"]:
                        message = ("Rejecting received notification of third-"
                                   "party invite without signed: %s" % (invite,))
                        logger.info(message)
                        raise SynapseError(400, message)
                    yield self.handler.exchange_third_party_invite(
                        invite["sender"],
                        invite["mxid"],
                        invite["room_id"],
                        invite["signed"],
                    )
                except Exception as e:
                    last_exception = e
            if last_exception:
                raise last_exception
        defer.returnValue((200, {}))


class OpenIdUserInfo(BaseFederationServlet):
    """
    Exchange a bearer token for information about a user.

    The response format should be compatible with:
        http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

    GET /openid/userinfo?access_token=ABDEFGH HTTP/1.1

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "sub": "@userpart:example.org",
    }
    """

    PATH = "/openid/userinfo"

    REQUIRE_AUTH = False

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query):
        token = query.get("access_token", [None])[0]
        if token is None:
            defer.returnValue((401, {
                "errcode": "M_MISSING_TOKEN", "error": "Access Token required"
            }))
            return

        user_id = yield self.handler.on_openid_userinfo(token)

        if user_id is None:
            defer.returnValue((401, {
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Access Token unknown or expired"
            }))

        defer.returnValue((200, {"sub": user_id}))


class PublicRoomList(BaseFederationServlet):
    """
    Fetch the public room list for this server.

    This API returns information in the same format as /publicRooms on the
    client API, but will only ever include local public rooms and hence is
    intended for consumption by other home servers.

    GET /publicRooms HTTP/1.1

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "chunk": [
            {
                "aliases": [
                    "#test:localhost"
                ],
                "guest_can_join": false,
                "name": "test room",
                "num_joined_members": 3,
                "room_id": "!whkydVegtvatLfXmPN:localhost",
                "world_readable": false
            }
        ],
        "end": "END",
        "start": "START"
    }
    """

    PATH = "/publicRooms"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query):
        limit = parse_integer_from_args(query, "limit", 0)
        since_token = parse_string_from_args(query, "since", None)
        include_all_networks = parse_boolean_from_args(
            query, "include_all_networks", False
        )
        third_party_instance_id = parse_string_from_args(
            query, "third_party_instance_id", None
        )

        if include_all_networks:
            network_tuple = None
        elif third_party_instance_id:
            network_tuple = ThirdPartyInstanceID.from_string(third_party_instance_id)
        else:
            network_tuple = ThirdPartyInstanceID(None, None)

        data = yield self.room_list_handler.get_local_public_room_list(
            limit, since_token,
            network_tuple=network_tuple
        )
        defer.returnValue((200, data))


class FederationVersionServlet(BaseFederationServlet):
    PATH = "/version"

    REQUIRE_AUTH = False

    def on_GET(self, origin, content, query):
        return defer.succeed((200, {
            "server": {
                "name": "Synapse",
                "version": get_version_string(synapse)
            },
        }))


SERVLET_CLASSES = (
    FederationSendServlet,
    FederationPullServlet,
    FederationEventServlet,
    FederationStateServlet,
    FederationStateIdsServlet,
    FederationBackfillServlet,
    FederationQueryServlet,
    FederationMakeJoinServlet,
    FederationMakeLeaveServlet,
    FederationEventServlet,
    FederationSendJoinServlet,
    FederationSendLeaveServlet,
    FederationInviteServlet,
    FederationQueryAuthServlet,
    FederationGetMissingEventsServlet,
    FederationEventAuthServlet,
    FederationClientKeysQueryServlet,
    FederationUserDevicesQueryServlet,
    FederationClientKeysClaimServlet,
    FederationThirdPartyInviteExchangeServlet,
    On3pidBindServlet,
    OpenIdUserInfo,
    PublicRoomList,
    FederationVersionServlet,
)


def register_servlets(hs, resource, authenticator, ratelimiter):
    for servletclass in SERVLET_CLASSES:
        servletclass(
            handler=hs.get_replication_layer(),
            authenticator=authenticator,
            ratelimiter=ratelimiter,
            server_name=hs.hostname,
            room_list_handler=hs.get_room_list_handler(),
        ).register(resource)
