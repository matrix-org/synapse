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

import functools
import logging
import re

from twisted.internet import defer

import synapse
from synapse.api.errors import Codes, FederationDeniedError, SynapseError
from synapse.api.urls import FEDERATION_PREFIX as PREFIX
from synapse.http.endpoint import parse_and_validate_server_name
from synapse.http.server import JsonResource
from synapse.http.servlet import (
    parse_boolean_from_args,
    parse_integer_from_args,
    parse_json_object_from_request,
    parse_string_from_args,
)
from synapse.types import ThirdPartyInstanceID, get_domain_from_id
from synapse.util.logcontext import run_in_background
from synapse.util.ratelimitutils import FederationRateLimiter
from synapse.util.versionstring import get_version_string

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
        self.store = hs.get_datastore()
        self.federation_domain_whitelist = hs.config.federation_domain_whitelist

    # A method just so we can pass 'self' as the authenticator to the Servlets
    @defer.inlineCallbacks
    def authenticate_request(self, request, content):
        json_request = {
            "method": request.method.decode('ascii'),
            "uri": request.uri.decode('ascii'),
            "destination": self.server_name,
            "signatures": {},
        }

        if content is not None:
            json_request["content"] = content

        origin = None

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")

        if not auth_headers:
            raise NoAuthenticationError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED,
            )

        for auth in auth_headers:
            if auth.startswith(b"X-Matrix"):
                (origin, key, sig) = _parse_auth_header(auth)
                json_request["origin"] = origin
                json_request["signatures"].setdefault(origin, {})[key] = sig

        if (
            self.federation_domain_whitelist is not None and
            origin not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(origin)

        if not json_request["signatures"]:
            raise NoAuthenticationError(
                401, "Missing Authorization headers", Codes.UNAUTHORIZED,
            )

        yield self.keyring.verify_json_for_server(origin, json_request)

        logger.info("Request from %s", origin)
        request.authenticated_entity = origin

        # If we get a valid signed request from the other side, its probably
        # alive
        retry_timings = yield self.store.get_destination_retry_timings(origin)
        if retry_timings and retry_timings["retry_last_ts"]:
            run_in_background(self._reset_retry_timings, origin)

        defer.returnValue(origin)

    @defer.inlineCallbacks
    def _reset_retry_timings(self, origin):
        try:
            logger.info("Marking origin %r as up", origin)
            yield self.store.set_destination_retry_timings(origin, 0, 0)
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
        header_str = header_bytes.decode('utf-8')
        params = header_str.split(" ")[1].split(",")
        param_dict = dict(kv.split("=") for kv in params)

        def strip_quotes(value):
            if value.startswith("\""):
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
        logger.warn(
            "Error parsing auth header '%s': %s",
            header_bytes.decode('ascii', 'replace'),
            e,
        )
        raise AuthenticationError(
            400, "Malformed Authorization header", Codes.UNAUTHORIZED,
        )


class BaseFederationServlet(object):
    """Abstract base class for federation servlet classes.

    The servlet object should have a PATH attribute which takes the form of a regexp to
    match against the request path (excluding the /federation/v1 prefix).

    The servlet should also implement one or more of on_GET, on_POST, on_PUT, to match
    the appropriate HTTP method. These methods have the signature:

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
            Deferred[(int, object)|None]: either (response code, response object) to
                 return a JSON response, or None if the request has already been handled.

        Raises:
            SynapseError: to return an error code

            Exception: other exceptions will be caught, logged, and a 500 will be
                returned.
    """
    REQUIRE_AUTH = True

    def __init__(self, handler, authenticator, ratelimiter, server_name):
        self.handler = handler
        self.authenticator = authenticator
        self.ratelimiter = ratelimiter

    def _wrap(self, func):
        authenticator = self.authenticator
        ratelimiter = self.ratelimiter

        @defer.inlineCallbacks
        @functools.wraps(func)
        def new_func(request, *args, **kwargs):
            """ A callback which can be passed to HttpServer.RegisterPaths

            Args:
                request (twisted.web.http.Request):
                *args: unused?
                **kwargs (dict[unicode, unicode]): the dict mapping keys to path
                    components as specified in the path match regexp.

            Returns:
                Deferred[(int, object)|None]: (response code, response object) as returned
                    by the callback method. None if the request has already been handled.
            """
            content = None
            if request.method in [b"PUT", b"POST"]:
                # TODO: Handle other method types? other content types?
                content = parse_json_object_from_request(request)

            try:
                origin = yield authenticator.authenticate_request(request, content)
            except NoAuthenticationError:
                origin = None
                if self.REQUIRE_AUTH:
                    logger.warn("authenticate_request failed: missing authentication")
                    raise
            except Exception as e:
                logger.warn("authenticate_request failed: %s", e)
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
                "Received txn %s from %s. (PDUs: %d, EDUs: %d)",
                transaction_id, origin,
                len(transaction_data.get("pdus", [])),
                len(transaction_data.get("edus", [])),
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
                origin, transaction_data,
            )
        except Exception:
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
            parse_string_from_args(query, "event_id", None),
        )


class FederationStateIdsServlet(BaseFederationServlet):
    PATH = "/state_ids/(?P<room_id>[^/]*)/"

    def on_GET(self, origin, content, query, room_id):
        return self.handler.on_state_ids_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None),
        )


class FederationBackfillServlet(BaseFederationServlet):
    PATH = "/backfill/(?P<context>[^/]*)/"

    def on_GET(self, origin, content, query, context):
        versions = [x.decode('ascii') for x in query[b"v"]]
        limit = parse_integer_from_args(query, "limit", None)

        if not limit:
            return defer.succeed((400, {"error": "Did not include limit param"}))

        return self.handler.on_backfill_request(origin, context, versions, limit)


class FederationQueryServlet(BaseFederationServlet):
    PATH = "/query/(?P<query_type>[^/]*)"

    # This is when we receive a server-server Query
    def on_GET(self, origin, content, query, query_type):
        return self.handler.on_query_request(
            query_type,
            {k.decode('utf8'): v[0].decode("utf-8") for k, v in query.items()}
        )


class FederationMakeJoinServlet(BaseFederationServlet):
    PATH = "/make_join/(?P<context>[^/]*)/(?P<user_id>[^/]*)"

    @defer.inlineCallbacks
    def on_GET(self, origin, _content, query, context, user_id):
        """
        Args:
            origin (unicode): The authenticated server_name of the calling server

            _content (None): (GETs don't have bodies)

            query (dict[bytes, list[bytes]]): Query params from the request.

            **kwargs (dict[unicode, unicode]): the dict mapping keys to path
                components as specified in the path match regexp.

        Returns:
            Deferred[(int, object)|None]: either (response code, response object) to
                 return a JSON response, or None if the request has already been handled.
        """
        versions = query.get(b'ver')
        if versions is not None:
            supported_versions = [v.decode("utf-8") for v in versions]
        else:
            supported_versions = ["1"]

        content = yield self.handler.on_make_join_request(
            origin, context, user_id,
            supported_versions=supported_versions,
        )
        defer.returnValue((200, content))


class FederationMakeLeaveServlet(BaseFederationServlet):
    PATH = "/make_leave/(?P<context>[^/]*)/(?P<user_id>[^/]*)"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, context, user_id):
        content = yield self.handler.on_make_leave_request(
            origin, context, user_id,
        )
        defer.returnValue((200, content))


class FederationSendLeaveServlet(BaseFederationServlet):
    PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"

    @defer.inlineCallbacks
    def on_PUT(self, origin, content, query, room_id, event_id):
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
        earliest_events = content.get("earliest_events", [])
        latest_events = content.get("latest_events", [])

        content = yield self.handler.on_get_missing_events(
            origin,
            room_id=room_id,
            earliest_events=earliest_events,
            latest_events=latest_events,
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
        token = query.get(b"access_token", [None])[0]
        if token is None:
            defer.returnValue((401, {
                "errcode": "M_MISSING_TOKEN", "error": "Access Token required"
            }))
            return

        user_id = yield self.handler.on_openid_userinfo(token.decode('ascii'))

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

        data = yield self.handler.get_local_public_room_list(
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


class FederationGroupsProfileServlet(BaseFederationServlet):
    """Get/set the basic profile of a group on behalf of a user
    """
    PATH = "/groups/(?P<group_id>[^/]*)/profile$"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.get_group_profile(
            group_id, requester_user_id
        )

        defer.returnValue((200, new_content))

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.update_group_profile(
            group_id, requester_user_id, content
        )

        defer.returnValue((200, new_content))


class FederationGroupsSummaryServlet(BaseFederationServlet):
    PATH = "/groups/(?P<group_id>[^/]*)/summary$"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.get_group_summary(
            group_id, requester_user_id
        )

        defer.returnValue((200, new_content))


class FederationGroupsRoomsServlet(BaseFederationServlet):
    """Get the rooms in a group on behalf of a user
    """
    PATH = "/groups/(?P<group_id>[^/]*)/rooms$"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.get_rooms_in_group(
            group_id, requester_user_id
        )

        defer.returnValue((200, new_content))


class FederationGroupsAddRoomsServlet(BaseFederationServlet):
    """Add/remove room from group
    """
    PATH = "/groups/(?P<group_id>[^/]*)/room/(?P<room_id>[^/]*)$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.add_room_to_group(
            group_id, requester_user_id, room_id, content
        )

        defer.returnValue((200, new_content))

    @defer.inlineCallbacks
    def on_DELETE(self, origin, content, query, group_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.remove_room_from_group(
            group_id, requester_user_id, room_id,
        )

        defer.returnValue((200, new_content))


class FederationGroupsAddRoomsConfigServlet(BaseFederationServlet):
    """Update room config in group
    """
    PATH = (
        "/groups/(?P<group_id>[^/]*)/room/(?P<room_id>[^/]*)"
        "/config/(?P<config_key>[^/]*)$"
    )

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, room_id, config_key):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        result = yield self.groups_handler.update_room_in_group(
            group_id, requester_user_id, room_id, config_key, content,
        )

        defer.returnValue((200, result))


class FederationGroupsUsersServlet(BaseFederationServlet):
    """Get the users in a group on behalf of a user
    """
    PATH = "/groups/(?P<group_id>[^/]*)/users$"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.get_users_in_group(
            group_id, requester_user_id
        )

        defer.returnValue((200, new_content))


class FederationGroupsInvitedUsersServlet(BaseFederationServlet):
    """Get the users that have been invited to a group
    """
    PATH = "/groups/(?P<group_id>[^/]*)/invited_users$"

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.get_invited_users_in_group(
            group_id, requester_user_id
        )

        defer.returnValue((200, new_content))


class FederationGroupsInviteServlet(BaseFederationServlet):
    """Ask a group server to invite someone to the group
    """
    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/invite$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.invite_to_group(
            group_id, user_id, requester_user_id, content,
        )

        defer.returnValue((200, new_content))


class FederationGroupsAcceptInviteServlet(BaseFederationServlet):
    """Accept an invitation from the group server
    """
    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/accept_invite$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(user_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = yield self.handler.accept_invite(
            group_id, user_id, content,
        )

        defer.returnValue((200, new_content))


class FederationGroupsJoinServlet(BaseFederationServlet):
    """Attempt to join a group
    """
    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/join$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(user_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = yield self.handler.join_group(
            group_id, user_id, content,
        )

        defer.returnValue((200, new_content))


class FederationGroupsRemoveUserServlet(BaseFederationServlet):
    """Leave or kick a user from the group
    """
    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/remove$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.remove_user_from_group(
            group_id, user_id, requester_user_id, content,
        )

        defer.returnValue((200, new_content))


class FederationGroupsLocalInviteServlet(BaseFederationServlet):
    """A group server has invited a local user
    """
    PATH = "/groups/local/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/invite$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(group_id) != origin:
            raise SynapseError(403, "group_id doesn't match origin")

        new_content = yield self.handler.on_invite(
            group_id, user_id, content,
        )

        defer.returnValue((200, new_content))


class FederationGroupsRemoveLocalUserServlet(BaseFederationServlet):
    """A group server has removed a local user
    """
    PATH = "/groups/local/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/remove$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, user_id):
        if get_domain_from_id(group_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = yield self.handler.user_removed_from_group(
            group_id, user_id, content,
        )

        defer.returnValue((200, new_content))


class FederationGroupsRenewAttestaionServlet(BaseFederationServlet):
    """A group or user's server renews their attestation
    """
    PATH = "/groups/(?P<group_id>[^/]*)/renew_attestation/(?P<user_id>[^/]*)$"

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, user_id):
        # We don't need to check auth here as we check the attestation signatures

        new_content = yield self.handler.on_renew_attestation(
            group_id, user_id, content
        )

        defer.returnValue((200, new_content))


class FederationGroupsSummaryRoomsServlet(BaseFederationServlet):
    """Add/remove a room from the group summary, with optional category.

    Matches both:
        - /groups/:group/summary/rooms/:room_id
        - /groups/:group/summary/categories/:category/rooms/:room_id
    """
    PATH = (
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/categories/(?P<category_id>[^/]+))?"
        "/rooms/(?P<room_id>[^/]*)$"
    )

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, category_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = yield self.handler.update_group_summary_room(
            group_id, requester_user_id,
            room_id=room_id,
            category_id=category_id,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, origin, content, query, group_id, category_id, room_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = yield self.handler.delete_group_summary_room(
            group_id, requester_user_id,
            room_id=room_id,
            category_id=category_id,
        )

        defer.returnValue((200, resp))


class FederationGroupsCategoriesServlet(BaseFederationServlet):
    """Get all categories for a group
    """
    PATH = (
        "/groups/(?P<group_id>[^/]*)/categories/$"
    )

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = yield self.handler.get_group_categories(
            group_id, requester_user_id,
        )

        defer.returnValue((200, resp))


class FederationGroupsCategoryServlet(BaseFederationServlet):
    """Add/remove/get a category in a group
    """
    PATH = (
        "/groups/(?P<group_id>[^/]*)/categories/(?P<category_id>[^/]+)$"
    )

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id, category_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = yield self.handler.get_group_category(
            group_id, requester_user_id, category_id
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, category_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = yield self.handler.upsert_group_category(
            group_id, requester_user_id, category_id, content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, origin, content, query, group_id, category_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = yield self.handler.delete_group_category(
            group_id, requester_user_id, category_id,
        )

        defer.returnValue((200, resp))


class FederationGroupsRolesServlet(BaseFederationServlet):
    """Get roles in a group
    """
    PATH = (
        "/groups/(?P<group_id>[^/]*)/roles/$"
    )

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = yield self.handler.get_group_roles(
            group_id, requester_user_id,
        )

        defer.returnValue((200, resp))


class FederationGroupsRoleServlet(BaseFederationServlet):
    """Add/remove/get a role in a group
    """
    PATH = (
        "/groups/(?P<group_id>[^/]*)/roles/(?P<role_id>[^/]+)$"
    )

    @defer.inlineCallbacks
    def on_GET(self, origin, content, query, group_id, role_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = yield self.handler.get_group_role(
            group_id, requester_user_id, role_id
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, role_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = yield self.handler.update_group_role(
            group_id, requester_user_id, role_id, content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, origin, content, query, group_id, role_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = yield self.handler.delete_group_role(
            group_id, requester_user_id, role_id,
        )

        defer.returnValue((200, resp))


class FederationGroupsSummaryUsersServlet(BaseFederationServlet):
    """Add/remove a user from the group summary, with optional role.

    Matches both:
        - /groups/:group/summary/users/:user_id
        - /groups/:group/summary/roles/:role/users/:user_id
    """
    PATH = (
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/roles/(?P<role_id>[^/]+))?"
        "/users/(?P<user_id>[^/]*)$"
    )

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query, group_id, role_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = yield self.handler.update_group_summary_user(
            group_id, requester_user_id,
            user_id=user_id,
            role_id=role_id,
            content=content,
        )

        defer.returnValue((200, resp))

    @defer.inlineCallbacks
    def on_DELETE(self, origin, content, query, group_id, role_id, user_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = yield self.handler.delete_group_summary_user(
            group_id, requester_user_id,
            user_id=user_id,
            role_id=role_id,
        )

        defer.returnValue((200, resp))


class FederationGroupsBulkPublicisedServlet(BaseFederationServlet):
    """Get roles in a group
    """
    PATH = (
        "/get_groups_publicised$"
    )

    @defer.inlineCallbacks
    def on_POST(self, origin, content, query):
        resp = yield self.handler.bulk_get_publicised_groups(
            content["user_ids"], proxy=False,
        )

        defer.returnValue((200, resp))


class FederationGroupsSettingJoinPolicyServlet(BaseFederationServlet):
    """Sets whether a group is joinable without an invite or knock
    """
    PATH = "/groups/(?P<group_id>[^/]*)/settings/m.join_policy$"

    @defer.inlineCallbacks
    def on_PUT(self, origin, content, query, group_id):
        requester_user_id = parse_string_from_args(query, "requester_user_id")
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = yield self.handler.set_group_join_policy(
            group_id, requester_user_id, content
        )

        defer.returnValue((200, new_content))


FEDERATION_SERVLET_CLASSES = (
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
    FederationVersionServlet,
)


ROOM_LIST_CLASSES = (
    PublicRoomList,
)

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
)


GROUP_LOCAL_SERVLET_CLASSES = (
    FederationGroupsLocalInviteServlet,
    FederationGroupsRemoveLocalUserServlet,
    FederationGroupsBulkPublicisedServlet,
)


GROUP_ATTESTATION_SERVLET_CLASSES = (
    FederationGroupsRenewAttestaionServlet,
)


def register_servlets(hs, resource, authenticator, ratelimiter):
    for servletclass in FEDERATION_SERVLET_CLASSES:
        servletclass(
            handler=hs.get_federation_server(),
            authenticator=authenticator,
            ratelimiter=ratelimiter,
            server_name=hs.hostname,
        ).register(resource)

    for servletclass in ROOM_LIST_CLASSES:
        servletclass(
            handler=hs.get_room_list_handler(),
            authenticator=authenticator,
            ratelimiter=ratelimiter,
            server_name=hs.hostname,
        ).register(resource)

    for servletclass in GROUP_SERVER_SERVLET_CLASSES:
        servletclass(
            handler=hs.get_groups_server_handler(),
            authenticator=authenticator,
            ratelimiter=ratelimiter,
            server_name=hs.hostname,
        ).register(resource)

    for servletclass in GROUP_LOCAL_SERVLET_CLASSES:
        servletclass(
            handler=hs.get_groups_local_handler(),
            authenticator=authenticator,
            ratelimiter=ratelimiter,
            server_name=hs.hostname,
        ).register(resource)

    for servletclass in GROUP_ATTESTATION_SERVLET_CLASSES:
        servletclass(
            handler=hs.get_groups_attestation_renewer(),
            authenticator=authenticator,
            ratelimiter=ratelimiter,
            server_name=hs.hostname,
        ).register(resource)
