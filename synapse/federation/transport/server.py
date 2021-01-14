# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import functools
import logging
import re
from typing import Optional, Tuple, Type

import synapse
from synapse.api.errors import Codes, FederationDeniedError, SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.api.urls import (
    FEDERATION_UNSTABLE_PREFIX,
    FEDERATION_V1_PREFIX,
    FEDERATION_V2_PREFIX,
)
from synapse.http.endpoint import parse_and_validate_server_name
from synapse.http.server import JsonResource
from synapse.http.servlet import (
    parse_boolean_from_args,
    parse_integer_from_args,
    parse_json_object_from_request,
    parse_string_from_args,
)
from synapse.logging.context import run_in_background
from synapse.logging.opentracing import (
    start_active_span,
    start_active_span_from_request,
    tags,
    whitelisted_homeserver,
)
from synapse.server import HomeServer
from synapse.types import ThirdPartyInstanceID, get_domain_from_id
from synapse.util.versionstring import get_version_string

logger = logging.getLogger(__name__)


class TransportLayerServer(JsonResource):
    """Handles incoming federation HTTP requests"""

    def __init__(self, hs, servlet_groups=None):
        """Initialize the TransportLayerServer

        Will by default register all servlets. For custom behaviour, pass in
        a list of servlet_groups to register.

        Args:
            hs (synapse.server.HomeServer): homeserver
            servlet_groups (list[str], optional): List of servlet groups to register.
                Defaults to ``DEFAULT_SERVLET_GROUPS``.
        """
        self.hs = hs
        self.clock = hs.get_clock()
        self.servlet_groups = servlet_groups

        super().__init__(hs, canonical_json=False)

        self.authenticator = Authenticator(hs)
        self.ratelimiter = hs.get_federation_ratelimiter()

        self.register_servlets()

    def register_servlets(self):
        register_servlets(
            self.hs,
            resource=self,
            ratelimiter=self.ratelimiter,
            authenticator=self.authenticator,
            servlet_groups=self.servlet_groups,
        )


class AuthenticationError(SynapseError):
    """There was a problem authenticating the request"""

    pass


class NoAuthenticationError(AuthenticationError):
    """The request had no authentication information"""

    pass


class Authenticator:
    def __init__(self, hs: HomeServer):
        self._clock = hs.get_clock()
        self.keyring = hs.get_keyring()
        self.server_name = hs.hostname
        self.store = hs.get_datastore()
        self.federation_domain_whitelist = hs.config.federation_domain_whitelist
        self.notifier = hs.get_notifier()

        self.replication_client = None
        if hs.config.worker.worker_app:
            self.replication_client = hs.get_tcp_replication()

    # A method just so we can pass 'self' as the authenticator to the Servlets
    async def authenticate_request(self, request, content):
        now = self._clock.time_msec()
        json_request = {
            "method": request.method.decode("ascii"),
            "uri": request.uri.decode("ascii"),
            "destination": self.server_name,
            "signatures": {},
        }

        if content is not None:
            json_request["content"] = content

        origin = None

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")

        if not auth_headers:
            raise NoAuthenticationError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED
            )

        for auth in auth_headers:
            if auth.startswith(b"X-Matrix"):
                (origin, key, sig) = _parse_auth_header(auth)
                json_request["origin"] = origin
                json_request["signatures"].setdefault(origin, {})[key] = sig

        if (
            self.federation_domain_whitelist is not None
            and origin not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(origin)

        if origin is None or not json_request["signatures"]:
            raise NoAuthenticationError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED
            )

        await self.keyring.verify_json_for_server(
            origin, json_request, now, "Incoming request"
        )

        logger.debug("Request from %s", origin)
        request.requester = origin

        # If we get a valid signed request from the other side, its probably
        # alive
        retry_timings = await self.store.get_destination_retry_timings(origin)
        if retry_timings and retry_timings["retry_last_ts"]:
            run_in_background(self._reset_retry_timings, origin)

        return origin

    async def _reset_retry_timings(self, origin):
        try:
            logger.info("Marking origin %r as up", origin)
            await self.store.set_destination_retry_timings(origin, None, 0, 0)

            # Inform the relevant places that the remote server is back up.
            self.notifier.notify_remote_server_up(origin)
            if self.replication_client:
                # If we're on a worker we try and inform master about this. The
                # replication client doesn't hook into the notifier to avoid
                # infinite loops where we send a `REMOTE_SERVER_UP` command to
                # master, which then echoes it back to us which in turn pokes
                # the notifier.
                self.replication_client.send_remote_server_up(origin)

        except Exception:
            logger.exception("Error resetting retry timings on %s", origin)


def _parse_auth_header(header_bytes):
    """Parse an X-Matrix auth header

    Args:
        header_bytes (bytes): header value

    Returns:
        Tuple[str, str, str]: origin, key id, signature.

    Raises:
        AuthenticationError if the header could not be parsed
    """
    try:
        header_str = header_bytes.decode("utf-8")
        params = header_str.split(" ")[1].split(",")
        param_dict = dict(kv.split("=") for kv in params)

        def strip_quotes(value):
            if value.startswith('"'):
                return value[1:-1]
            else:
                return value

        origin = strip_quotes(param_dict["origin"])

        # ensure that the origin is a valid server name
        parse_and_validate_server_name(origin)

        key = strip_quotes(param_dict["key"])
        sig = strip_quotes(param_dict["sig"])
        return origin, key, sig
    except Exception as e:
        logger.warning(
            "Error parsing auth header '%s': %s",
            header_bytes.decode("ascii", "replace"),
            e,
        )
        raise AuthenticationError(
            400, "Malformed Authorization header", Codes.UNAUTHORIZED
        )


class BaseFederationServlet:
    """Abstract base class for federation servlet classes.

    The servlet object should have a PATH attribute which takes the form of a regexp to
    match against the request path (excluding the /federation/v1 prefix).

    The servlet should also implement one or more of on_GET, on_POST, on_PUT, to match
    the appropriate HTTP method. These methods must be *asynchronous* and have the
    signature:

        on_<METHOD>(self, origin, content, query, **kwargs)

        With arguments:

            origin (unicode|None): The authenticated server_name of the calling server,
                unless REQUIRE_AUTH is set to False and authentication failed.

            content (unicode|None): decoded json body of the request. None if the
                request was a GET.

            query (dict[bytes, list[bytes]]): Query params from the request. url-decoded
                (ie, '+' and '%xx' are decoded) but note that it is *not* utf8-decoded
                yet.

            **kwargs (dict[unicode, unicode]): the dict mapping keys to path
                components as specified in the path match regexp.

        Returns:
            Optional[Tuple[int, object]]: either (response code, response object) to
                 return a JSON response, or None if the request has already been handled.

        Raises:
            SynapseError: to return an error code

            Exception: other exceptions will be caught, logged, and a 500 will be
                returned.
    """

    PATH = ""  # Overridden in subclasses, the regex to match against the path.

    REQUIRE_AUTH = True

    PREFIX = FEDERATION_V1_PREFIX  # Allows specifying the API version

    RATELIMIT = True  # Whether to rate limit requests or not

    def __init__(self, handler, authenticator, ratelimiter, server_name):
        self.handler = handler
        self.authenticator = authenticator
        self.ratelimiter = ratelimiter

    def _wrap(self, func):
        authenticator = self.authenticator
        ratelimiter = self.ratelimiter

        @functools.wraps(func)
        async def new_func(request, *args, **kwargs):
            """A callback which can be passed to HttpServer.RegisterPaths

            Args:
                request (twisted.web.http.Request):
                *args: unused?
                **kwargs (dict[unicode, unicode]): the dict mapping keys to path
                    components as specified in the path match regexp.

            Returns:
                Tuple[int, object]|None: (response code, response object) as returned by
                    the callback method. None if the request has already been handled.
            """
            content = None
            if request.method in [b"PUT", b"POST"]:
                # TODO: Handle other method types? other content types?
                content = parse_json_object_from_request(request)

            try:
                origin = await authenticator.authenticate_request(request, content)
            except NoAuthenticationError:
                origin = None
                if self.REQUIRE_AUTH:
                    logger.warning(
                        "authenticate_request failed: missing authentication"
                    )
                    raise
            except Exception as e:
                logger.warning("authenticate_request failed: %s", e)
                raise

            request_tags = {
                "request_id": request.get_request_id(),
                tags.SPAN_KIND: tags.SPAN_KIND_RPC_SERVER,
                tags.HTTP_METHOD: request.get_method(),
                tags.HTTP_URL: request.get_redacted_uri(),
                tags.PEER_HOST_IPV6: request.getClientIP(),
                "authenticated_entity": origin,
                "servlet_name": request.request_metrics.name,
            }

            # Only accept the span context if the origin is authenticated
            # and whitelisted
            if origin and whitelisted_homeserver(origin):
                scope = start_active_span_from_request(
                    request, "incoming-federation-request", tags=request_tags
                )
            else:
                scope = start_active_span(
                    "incoming-federation-request", tags=request_tags
                )

            with scope:
                if origin and self.RATELIMIT:
                    with ratelimiter.ratelimit(origin) as d:
                        await d
                        if request._disconnected:
                            logger.warning(
                                "client disconnected before we started processing "
                                "request"
                            )
                            return -1, None
                        response = await func(
                            origin, content, request.args, *args, **kwargs
                        )
                else:
                    response = await func(
                        origin, content, request.args, *args, **kwargs
                    )

            return response

        return new_func

    def register(self, server):
        pattern = re.compile("^" + self.PREFIX + self.PATH + "$")

        for method in ("GET", "PUT", "POST"):
            code = getattr(self, "on_%s" % (method), None)
            if code is None:
                continue

            server.register_paths(
                method, (pattern,), self._wrap(code), self.__class__.__name__,
            )


class FederationSendServlet(BaseFederationServlet):
    PATH = "/send/(?P<transaction_id>[^/]*)/?"

    # We ratelimit manually in the handler as we queue up the requests and we
    # don't want to fill up the ratelimiter with blocked requests.
    RATELIMIT = False

    def __init__(self, handler, server_name, **kwargs):
        super().__init__(handler, server_name=server_name, **kwargs)
        self.server_name = server_name

    # This is when someone is trying to send us a bunch of data.
    async def on_PUT(self, origin, content, query, transaction_id):
        """ Called on PUT /send/<transaction_id>/

        Args:
            request (twisted.web.http.Request): The HTTP request.
            transaction_id (str): The transaction_id associated with this
                request. This is *not* None.

        Returns:
            Tuple of `(code, response)`, where
            `response` is a python dict to be converted into JSON that is
            used as the response body.
        """
        # Parse the request
        try:
            transaction_data = content

            logger.debug("Decoded %s: %s", transaction_id, str(transaction_data))

            logger.info(
                "Received txn %s from %s. (PDUs: %d, EDUs: %d)",
                transaction_id,
                origin,
                len(transaction_data.get("pdus", [])),
                len(transaction_data.get("edus", [])),
            )

            # We should ideally be getting this from the security layer.
            # origin = body["origin"]

            # Add some extra data to the transaction dict that isn't included
            # in the request body.
            transaction_data.update(
                transaction_id=transaction_id, destination=self.server_name
            )

        except Exception as e:
            logger.exception(e)
            return 400, {"error": "Invalid transaction"}

        try:
            code, response = await self.handler.on_incoming_transaction(
                origin, transaction_data
            )
        except Exception:
            logger.exception("on_incoming_transaction failed")
            raise

        return code, response


class FederationEventServlet(BaseFederationServlet):
    PATH = "/event/(?P<event_id>[^/]*)/?"

    # This is when someone asks for a data item for a given server data_id pair.
    async def on_GET(self, origin, content, query, event_id):
        return await self.handler.on_pdu_request(origin, event_id)


class FederationStateV1Servlet(BaseFederationServlet):
    PATH = "/state/(?P<room_id>[^/]*)/?"

    # This is when someone asks for all data for a given room.
    async def on_GET(self, origin, content, query, room_id):
        return await self.handler.on_room_state_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None, required=False),
        )


class FederationStateIdsServlet(BaseFederationServlet):
    PATH = "/state_ids/(?P<room_id>[^/]*)/?"

    async def on_GET(self, origin, content, query, room_id):
        return await self.handler.on_state_ids_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None, required=True),
        )


class FederationBackfillServlet(BaseFederationServlet):
    PATH = "/backfill/(?P<room_id>[^/]*)/?"

    async def on_GET(self, origin, content, query, room_id):
        versions = [x.decode("ascii") for x in query[b"v"]]
        limit = parse_integer_from_args(query, "limit", None)

        if not limit:
            return 400, {"error": "Did not include limit param"}

        return await self.handler.on_backfill_request(origin, room_id, versions, limit)


class FederationQueryServlet(BaseFederationServlet):
    PATH = "/query/(?P<query_type>[^/]*)"

    # This is when we receive a server-server Query
    async def on_GET(self, origin, content, query, query_type):
        return await self.handler.on_query_request(
            query_type,
            {k.decode("utf8"): v[0].decode("utf-8") for k, v in query.items()},
        )


class FederationMakeJoinServlet(BaseFederationServlet):
    PATH = "/make_join/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"

    async def on_GET(self, origin, _content, query, room_id, user_id):
        """
        Args:
            origin (unicode): The authenticated server_name of the calling server

            _content (None): (GETs don't have bodies)

            query (dict[bytes, list[bytes]]): Query params from the request.

            **kwargs (dict[unicode, unicode]): the dict mapping keys to path
                components as specified in the path match regexp.

        Returns:
            Tuple[int, object]: (response code, response object)
        """
        versions = query.get(b"ver")
        if versions is not None:
            supported_versions = [v.decode("utf-8") for v in versions]
        else:
            supported_versions = ["1"]

        content = await self.handler.on_make_join_request(
            origin, room_id, user_id, supported_versions=supported_versions
        )
        return 200, content


class FederationMakeLeaveServlet(BaseFederationServlet):
    PATH = "/make_leave/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"

    async def on_GET(self, origin, content, query, room_id, user_id):
        content = await self.handler.on_make_leave_request(origin, room_id, user_id)
        return 200, content


class FederationV1SendLeaveServlet(BaseFederationServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_PUT(self, origin, content, query, room_id, event_id):
        content = await self.handler.on_send_leave_request(origin, content)
        return 200, (200, content)


class FederationV2SendLeaveServlet(BaseFederationServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(self, origin, content, query, room_id, event_id):
        content = await self.handler.on_send_leave_request(origin, content)
        return 200, content


class FederationEventAuthServlet(BaseFederationServlet):
    PATH = "/event_auth/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_GET(self, origin, content, query, room_id, event_id):
        return await self.handler.on_event_auth(origin, room_id, event_id)


class FederationV1SendJoinServlet(BaseFederationServlet):
    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_PUT(self, origin, content, query, room_id, event_id):
        # TODO(paul): assert that room_id/event_id parsed from path actually
        #   match those given in content
        content = await self.handler.on_send_join_request(origin, content)
        return 200, (200, content)


class FederationV2SendJoinServlet(BaseFederationServlet):
    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(self, origin, content, query, room_id, event_id):
        # TODO(paul): assert that room_id/event_id parsed from path actually
        #   match those given in content
        content = await self.handler.on_send_join_request(origin, content)
        return 200, content


class FederationV1InviteServlet(BaseFederationServlet):
    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    async def on_PUT(self, origin, content, query, room_id, event_id):
        # We don't get a room version, so we have to assume its EITHER v1 or
        # v2. This is "fine" as the only difference between V1 and V2 is the
        # state resolution algorithm, and we don't use that for processing
        # invites
        content = await self.handler.on_invite_request(
            origin, content, room_version_id=RoomVersions.V1.identifier
        )

        # V1 federation API is defined to return a content of `[200, {...}]`
        # due to a historical bug.
        return 200, (200, content)


class FederationV2InviteServlet(BaseFederationServlet):
    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    PREFIX = FEDERATION_V2_PREFIX

    async def on_PUT(self, origin, content, query, room_id, event_id):
        # TODO(paul): assert that room_id/event_id parsed from path actually
        #   match those given in content

        room_version = content["room_version"]
        event = content["event"]
        invite_room_state = content["invite_room_state"]

        # Synapse expects invite_room_state to be in unsigned, as it is in v1
        # API

        event.setdefault("unsigned", {})["invite_room_state"] = invite_room_state

        content = await self.handler.on_invite_request(
            origin, event, room_version_id=room_version
        )
        return 200, content


class FederationThirdPartyInviteExchangeServlet(BaseFederationServlet):
    PATH = "/exchange_third_party_invite/(?P<room_id>[^/]*)"

    async def on_PUT(self, origin, content, query, room_id):
        content = await self.handler.on_exchange_third_party_invite_request(content)
        return 200, content


class FederationClientKeysQueryServlet(BaseFederationServlet):
    PATH = "/user/keys/query"

    async def on_POST(self, origin, content, query):
        return await self.handler.on_query_client_keys(origin, content)


class FederationUserDevicesQueryServlet(BaseFederationServlet):
    PATH = "/user/devices/(?P<user_id>[^/]*)"

    async def on_GET(self, origin, content, query, user_id):
        return await self.handler.on_query_user_devices(origin, user_id)


class FederationClientKeysClaimServlet(BaseFederationServlet):
    PATH = "/user/keys/claim"

    async def on_POST(self, origin, content, query):
        response = await self.handler.on_claim_client_keys(origin, content)
        return 200, response


class FederationGetMissingEventsServlet(BaseFederationServlet):
    # TODO(paul): Why does this path alone end with "/?" optional?
    PATH = "/get_missing_events/(?P<room_id>[^/]*)/?"

    async def on_POST(self, origin, content, query, room_id):
        limit = int(content.get("limit", 10))
        earliest_events = content.get("earliest_events", [])
        latest_events = content.get("latest_events", [])

        content = await self.handler.on_get_missing_events(
            origin,
            room_id=room_id,
            earliest_events=earliest_events,
            latest_events=latest_events,
            limit=limit,
        )

        return 200, content


class On3pidBindServlet(BaseFederationServlet):
    PATH = "/3pid/onbind"

    REQUIRE_AUTH = False

    async def on_POST(self, origin, content, query):
        if "invites" in content:
            last_exception = None
            for invite in content["invites"]:
                try:
                    if "signed" not in invite or "token" not in invite["signed"]:
                        message = (
                            "Rejecting received notification of third-"
                            "party invite without signed: %s" % (invite,)
                        )
                        logger.info(message)
                        raise SynapseError(400, message)
                    await self.handler.exchange_third_party_invite(
                        invite["sender"],
                        invite["mxid"],
                        invite["room_id"],
                        invite["signed"],
                    )
                except Exception as e:
                    last_exception = e
            if last_exception:
                raise last_exception
        return 200, {}


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

    async def on_GET(self, origin, content, query):
        token = query.get(b"access_token", [None])[0]
        if token is None:
            return (
                401,
                {"errcode": "M_MISSING_TOKEN", "error": "Access Token required"},
            )

        user_id = await self.handler.on_openid_userinfo(token.decode("ascii"))

        if user_id is None:
            return (
                401,
                {
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Access Token unknown or expired",
                },
            )

        return 200, {"sub": user_id}


class PublicRoomList(BaseFederationServlet):
    """
    Fetch the public room list for this server.

    This API returns information in the same format as /publicRooms on the
    client API, but will only ever include local public rooms and hence is
    intended for consumption by other homeservers.

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

    def __init__(self, handler, authenticator, ratelimiter, server_name, allow_access):
        super().__init__(handler, authenticator, ratelimiter, server_name)
        self.allow_access = allow_access

    async def on_GET(self, origin, content, query):
        if not self.allow_access:
            raise FederationDeniedError(origin)

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

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        data = await self.handler.get_local_public_room_list(
            limit, since_token, network_tuple=network_tuple, from_federation=True
        )
        return 200, data

    async def on_POST(self, origin, content, query):
        # This implements MSC2197 (Search Filtering over Federation)
        if not self.allow_access:
            raise FederationDeniedError(origin)

        limit = int(content.get("limit", 100))  # type: Optional[int]
        since_token = content.get("since", None)
        search_filter = content.get("filter", None)

        include_all_networks = content.get("include_all_networks", False)
        third_party_instance_id = content.get("third_party_instance_id", None)

        if include_all_networks:
            network_tuple = None
            if third_party_instance_id is not None:
                raise SynapseError(
                    400, "Can't use include_all_networks with an explicit network"
                )
        elif third_party_instance_id is None:
            network_tuple = ThirdPartyInstanceID(None, None)
        else:
            network_tuple = ThirdPartyInstanceID.from_string(third_party_instance_id)

        if search_filter is None:
            logger.warning("Nonefilter")

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        data = await self.handler.get_local_public_room_list(
            limit=limit,
            since_token=since_token,
            search_filter=search_filter,
            network_tuple=network_tuple,
            from_federation=True,
        )

        return 200, data


class FederationVersionServlet(BaseFederationServlet):
    PATH = "/version"

    REQUIRE_AUTH = False

    async def on_GET(self, origin, content, query):
        return (
            200,
            {"server": {"name": "Synapse", "version": get_version_string(synapse)}},
        )


class FederationGroupsProfileServlet(BaseFederationServlet):
    """Get/set the basic profile of a group on behalf of a user
    """

    PATH = "/groups/(?P<group_id>[^/]*)/profile"

    async def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_group_profile(group_id, requester_user_id)

        return 200, new_content

    async def on_POST(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.update_group_profile(
            group_id, requester_user_id, content
        )

        return 200, new_content


class FederationGroupsSummaryServlet(BaseFederationServlet):
    PATH = "/groups/(?P<group_id>[^/]*)/summary"

    async def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_group_summary(group_id, requester_user_id)

        return 200, new_content


class FederationGroupsRoomsServlet(BaseFederationServlet):
    """Get the rooms in a group on behalf of a user
    """

    PATH = "/groups/(?P<group_id>[^/]*)/rooms"

    async def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_rooms_in_group(group_id, requester_user_id)

        return 200, new_content


class FederationGroupsAddRoomsServlet(BaseFederationServlet):
    """Add/remove room from group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/room/(?P<room_id>[^/]*)"

    async def on_POST(self, origin, content, query, group_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.add_room_to_group(
            group_id, requester_user_id, room_id, content
        )

        return 200, new_content

    async def on_DELETE(self, origin, content, query, group_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.remove_room_from_group(
            group_id, requester_user_id, room_id
        )

        return 200, new_content


class FederationGroupsAddRoomsConfigServlet(BaseFederationServlet):
    """Update room config in group
    """

    PATH = (
        "/groups/(?P<group_id>[^/]*)/room/(?P<room_id>[^/]*)"
        "/config/(?P<config_key>[^/]*)"
    )

    async def on_POST(self, origin, content, query, group_id, room_id, config_key):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        result = await self.handler.update_room_in_group(
            group_id, requester_user_id, room_id, config_key, content
        )

        return 200, result


class FederationGroupsUsersServlet(BaseFederationServlet):
    """Get the users in a group on behalf of a user
    """

    PATH = "/groups/(?P<group_id>[^/]*)/users"

    async def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_users_in_group(group_id, requester_user_id)

        return 200, new_content


class FederationGroupsInvitedUsersServlet(BaseFederationServlet):
    """Get the users that have been invited to a group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/invited_users"

    async def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_invited_users_in_group(
            group_id, requester_user_id
        )

        return 200, new_content


class FederationGroupsInviteServlet(BaseFederationServlet):
    """Ask a group server to invite someone to the group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/invite"

    async def on_POST(self, origin, content, query, group_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.invite_to_group(
            group_id, user_id, requester_user_id, content
        )

        return 200, new_content


class FederationGroupsAcceptInviteServlet(BaseFederationServlet):
    """Accept an invitation from the group server
    """

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/accept_invite"

    async def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(user_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = await self.handler.accept_invite(group_id, user_id, content)

        return 200, new_content


class FederationGroupsJoinServlet(BaseFederationServlet):
    """Attempt to join a group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/join"

    async def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(user_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = await self.handler.join_group(group_id, user_id, content)

        return 200, new_content


class FederationGroupsRemoveUserServlet(BaseFederationServlet):
    """Leave or kick a user from the group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/remove"

    async def on_POST(self, origin, content, query, group_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.remove_user_from_group(
            group_id, user_id, requester_user_id, content
        )

        return 200, new_content


class FederationGroupsLocalInviteServlet(BaseFederationServlet):
    """A group server has invited a local user
    """

    PATH = "/groups/local/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/invite"

    async def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(group_id) != origin:
            raise SynapseError(403, "group_id doesn't match origin")

        new_content = await self.handler.on_invite(group_id, user_id, content)

        return 200, new_content


class FederationGroupsRemoveLocalUserServlet(BaseFederationServlet):
    """A group server has removed a local user
    """

    PATH = "/groups/local/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/remove"

    async def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(group_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = await self.handler.user_removed_from_group(
            group_id, user_id, content
        )

        return 200, new_content


class FederationGroupsRenewAttestaionServlet(BaseFederationServlet):
    """A group or user's server renews their attestation
    """

    PATH = "/groups/(?P<group_id>[^/]*)/renew_attestation/(?P<user_id>[^/]*)"

    async def on_POST(self, origin, content, query, group_id, user_id):
        # We don't need to check auth here as we check the attestation signatures

        new_content = await self.handler.on_renew_attestation(
            group_id, user_id, content
        )

        return 200, new_content


class FederationGroupsSummaryRoomsServlet(BaseFederationServlet):
    """Add/remove a room from the group summary, with optional category.

    Matches both:
        - /groups/:group/summary/rooms/:room_id
        - /groups/:group/summary/categories/:category/rooms/:room_id
    """

    PATH = (
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/categories/(?P<category_id>[^/]+))?"
        "/rooms/(?P<room_id>[^/]*)"
    )

    async def on_POST(self, origin, content, query, group_id, category_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = await self.handler.update_group_summary_room(
            group_id,
            requester_user_id,
            room_id=room_id,
            category_id=category_id,
            content=content,
        )

        return 200, resp

    async def on_DELETE(self, origin, content, query, group_id, category_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = await self.handler.delete_group_summary_room(
            group_id, requester_user_id, room_id=room_id, category_id=category_id
        )

        return 200, resp


class FederationGroupsCategoriesServlet(BaseFederationServlet):
    """Get all categories for a group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/categories/?"

    async def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_categories(group_id, requester_user_id)

        return 200, resp


class FederationGroupsCategoryServlet(BaseFederationServlet):
    """Add/remove/get a category in a group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/categories/(?P<category_id>[^/]+)"

    async def on_GET(self, origin, content, query, group_id, category_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_category(
            group_id, requester_user_id, category_id
        )

        return 200, resp

    async def on_POST(self, origin, content, query, group_id, category_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = await self.handler.upsert_group_category(
            group_id, requester_user_id, category_id, content
        )

        return 200, resp

    async def on_DELETE(self, origin, content, query, group_id, category_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = await self.handler.delete_group_category(
            group_id, requester_user_id, category_id
        )

        return 200, resp


class FederationGroupsRolesServlet(BaseFederationServlet):
    """Get roles in a group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/roles/?"

    async def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_roles(group_id, requester_user_id)

        return 200, resp


class FederationGroupsRoleServlet(BaseFederationServlet):
    """Add/remove/get a role in a group
    """

    PATH = "/groups/(?P<group_id>[^/]*)/roles/(?P<role_id>[^/]+)"

    async def on_GET(self, origin, content, query, group_id, role_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_role(group_id, requester_user_id, role_id)

        return 200, resp

    async def on_POST(self, origin, content, query, group_id, role_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = await self.handler.update_group_role(
            group_id, requester_user_id, role_id, content
        )

        return 200, resp

    async def on_DELETE(self, origin, content, query, group_id, role_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = await self.handler.delete_group_role(
            group_id, requester_user_id, role_id
        )

        return 200, resp


class FederationGroupsSummaryUsersServlet(BaseFederationServlet):
    """Add/remove a user from the group summary, with optional role.

    Matches both:
        - /groups/:group/summary/users/:user_id
        - /groups/:group/summary/roles/:role/users/:user_id
    """

    PATH = (
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/roles/(?P<role_id>[^/]+))?"
        "/users/(?P<user_id>[^/]*)"
    )

    async def on_POST(self, origin, content, query, group_id, role_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = await self.handler.update_group_summary_user(
            group_id,
            requester_user_id,
            user_id=user_id,
            role_id=role_id,
            content=content,
        )

        return 200, resp

    async def on_DELETE(self, origin, content, query, group_id, role_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = await self.handler.delete_group_summary_user(
            group_id, requester_user_id, user_id=user_id, role_id=role_id
        )

        return 200, resp


class FederationGroupsBulkPublicisedServlet(BaseFederationServlet):
    """Get roles in a group
    """

    PATH = "/get_groups_publicised"

    async def on_POST(self, origin, content, query):
        resp = await self.handler.bulk_get_publicised_groups(
            content["user_ids"], proxy=False
        )

        return 200, resp


class FederationGroupsSettingJoinPolicyServlet(BaseFederationServlet):
    """Sets whether a group is joinable without an invite or knock
    """

    PATH = "/groups/(?P<group_id>[^/]*)/settings/m.join_policy"

    async def on_PUT(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.set_group_join_policy(
            group_id, requester_user_id, content
        )

        return 200, new_content


class RoomComplexityServlet(BaseFederationServlet):
    """
    Indicates to other servers how complex (and therefore likely
    resource-intensive) a public room this server knows about is.
    """

    PATH = "/rooms/(?P<room_id>[^/]*)/complexity"
    PREFIX = FEDERATION_UNSTABLE_PREFIX

    async def on_GET(self, origin, content, query, room_id):

        store = self.handler.hs.get_datastore()

        is_public = await store.is_room_world_readable_or_publicly_joinable(room_id)

        if not is_public:
            raise SynapseError(404, "Room not found", errcode=Codes.INVALID_PARAM)

        complexity = await store.get_room_complexity(room_id)
        return 200, complexity


FEDERATION_SERVLET_CLASSES = (
    FederationSendServlet,
    FederationEventServlet,
    FederationStateV1Servlet,
    FederationStateIdsServlet,
    FederationBackfillServlet,
    FederationQueryServlet,
    FederationMakeJoinServlet,
    FederationMakeLeaveServlet,
    FederationEventServlet,
    FederationV1SendJoinServlet,
    FederationV2SendJoinServlet,
    FederationV1SendLeaveServlet,
    FederationV2SendLeaveServlet,
    FederationV1InviteServlet,
    FederationV2InviteServlet,
    FederationGetMissingEventsServlet,
    FederationEventAuthServlet,
    FederationClientKeysQueryServlet,
    FederationUserDevicesQueryServlet,
    FederationClientKeysClaimServlet,
    FederationThirdPartyInviteExchangeServlet,
    On3pidBindServlet,
    FederationVersionServlet,
    RoomComplexityServlet,
)  # type: Tuple[Type[BaseFederationServlet], ...]

OPENID_SERVLET_CLASSES = (
    OpenIdUserInfo,
)  # type: Tuple[Type[BaseFederationServlet], ...]

ROOM_LIST_CLASSES = (PublicRoomList,)  # type: Tuple[Type[PublicRoomList], ...]

GROUP_SERVER_SERVLET_CLASSES = (
    FederationGroupsProfileServlet,
    FederationGroupsSummaryServlet,
    FederationGroupsRoomsServlet,
    FederationGroupsUsersServlet,
    FederationGroupsInvitedUsersServlet,
    FederationGroupsInviteServlet,
    FederationGroupsAcceptInviteServlet,
    FederationGroupsJoinServlet,
    FederationGroupsRemoveUserServlet,
    FederationGroupsSummaryRoomsServlet,
    FederationGroupsCategoriesServlet,
    FederationGroupsCategoryServlet,
    FederationGroupsRolesServlet,
    FederationGroupsRoleServlet,
    FederationGroupsSummaryUsersServlet,
    FederationGroupsAddRoomsServlet,
    FederationGroupsAddRoomsConfigServlet,
    FederationGroupsSettingJoinPolicyServlet,
)  # type: Tuple[Type[BaseFederationServlet], ...]


GROUP_LOCAL_SERVLET_CLASSES = (
    FederationGroupsLocalInviteServlet,
    FederationGroupsRemoveLocalUserServlet,
    FederationGroupsBulkPublicisedServlet,
)  # type: Tuple[Type[BaseFederationServlet], ...]


GROUP_ATTESTATION_SERVLET_CLASSES = (
    FederationGroupsRenewAttestaionServlet,
)  # type: Tuple[Type[BaseFederationServlet], ...]

DEFAULT_SERVLET_GROUPS = (
    "federation",
    "room_list",
    "group_server",
    "group_local",
    "group_attestation",
    "openid",
)


def register_servlets(hs, resource, authenticator, ratelimiter, servlet_groups=None):
    """Initialize and register servlet classes.

    Will by default register all servlets. For custom behaviour, pass in
    a list of servlet_groups to register.

    Args:
        hs (synapse.server.HomeServer): homeserver
        resource (JsonResource): resource class to register to
        authenticator (Authenticator): authenticator to use
        ratelimiter (util.ratelimitutils.FederationRateLimiter): ratelimiter to use
        servlet_groups (list[str], optional): List of servlet groups to register.
            Defaults to ``DEFAULT_SERVLET_GROUPS``.
    """
    if not servlet_groups:
        servlet_groups = DEFAULT_SERVLET_GROUPS

    if "federation" in servlet_groups:
        for servletclass in FEDERATION_SERVLET_CLASSES:
            servletclass(
                handler=hs.get_federation_server(),
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
            ).register(resource)

    if "openid" in servlet_groups:
        for servletclass in OPENID_SERVLET_CLASSES:
            servletclass(
                handler=hs.get_federation_server(),
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
            ).register(resource)

    if "room_list" in servlet_groups:
        for servletclass in ROOM_LIST_CLASSES:
            servletclass(
                handler=hs.get_room_list_handler(),
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
                allow_access=hs.config.allow_public_rooms_over_federation,
            ).register(resource)

    if "group_server" in servlet_groups:
        for servletclass in GROUP_SERVER_SERVLET_CLASSES:
            servletclass(
                handler=hs.get_groups_server_handler(),
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
            ).register(resource)

    if "group_local" in servlet_groups:
        for servletclass in GROUP_LOCAL_SERVLET_CLASSES:
            servletclass(
                handler=hs.get_groups_local_handler(),
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
            ).register(resource)

    if "group_attestation" in servlet_groups:
        for servletclass in GROUP_ATTESTATION_SERVLET_CLASSES:
            servletclass(
                handler=hs.get_groups_attestation_renewer(),
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
            ).register(resource)
