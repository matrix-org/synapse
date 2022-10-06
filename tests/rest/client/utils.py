# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019-2021 The Matrix.org Foundation C.I.C.
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

import json
import re
import time
import urllib.parse
from http import HTTPStatus
from typing import (
    Any,
    AnyStr,
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
    overload,
)
from unittest.mock import patch
from urllib.parse import urlencode

import attr
from typing_extensions import Literal

from twisted.web.resource import Resource
from twisted.web.server import Site

from synapse.api.constants import Membership
from synapse.api.errors import Codes
from synapse.server import HomeServer
from synapse.types import JsonDict

from tests.server import FakeChannel, FakeSite, make_request
from tests.test_utils import FakeResponse
from tests.test_utils.html_parsers import TestHtmlParser


@attr.s(auto_attribs=True)
class RestHelper:
    """Contains extra helper functions to quickly and clearly perform a given
    REST action, which isn't the focus of the test.
    """

    hs: HomeServer
    site: Site
    auth_user_id: Optional[str]

    @overload
    def create_room_as(
        self,
        room_creator: Optional[str] = ...,
        is_public: Optional[bool] = ...,
        room_version: Optional[str] = ...,
        tok: Optional[str] = ...,
        expect_code: Literal[200] = ...,
        extra_content: Optional[Dict] = ...,
        custom_headers: Optional[Iterable[Tuple[AnyStr, AnyStr]]] = ...,
    ) -> str:
        ...

    @overload
    def create_room_as(
        self,
        room_creator: Optional[str] = ...,
        is_public: Optional[bool] = ...,
        room_version: Optional[str] = ...,
        tok: Optional[str] = ...,
        expect_code: int = ...,
        extra_content: Optional[Dict] = ...,
        custom_headers: Optional[Iterable[Tuple[AnyStr, AnyStr]]] = ...,
    ) -> Optional[str]:
        ...

    def create_room_as(
        self,
        room_creator: Optional[str] = None,
        is_public: Optional[bool] = True,
        room_version: Optional[str] = None,
        tok: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        extra_content: Optional[Dict] = None,
        custom_headers: Optional[Iterable[Tuple[AnyStr, AnyStr]]] = None,
    ) -> Optional[str]:
        """
        Create a room.

        Args:
            room_creator: The user ID to create the room with.
            is_public: If True, the `visibility` parameter will be set to
                "public". If False, it will be set to "private".
                If None, doesn't specify the `visibility` parameter in which
                case the server is supposed to make the room private according to
                the CS API.
                Defaults to public, since that is commonly needed in tests
                for convenience where room privacy is not a problem.
            room_version: The room version to create the room as. Defaults to Synapse's
                default room version.
            tok: The access token to use in the request.
            expect_code: The expected HTTP response code.
            extra_content: Extra keys to include in the body of the /createRoom request.
                Note that if is_public is set, the "visibility" key will be overridden.
                If room_version is set, the "room_version" key will be overridden.
            custom_headers: HTTP headers to include in the request.

        Returns:
            The ID of the newly created room, or None if the request failed.
        """
        temp_id = self.auth_user_id
        self.auth_user_id = room_creator
        path = "/_matrix/client/r0/createRoom"
        content = extra_content or {}
        if is_public is not None:
            content["visibility"] = "public" if is_public else "private"
        if room_version:
            content["room_version"] = room_version
        if tok:
            path = path + "?access_token=%s" % tok

        channel = make_request(
            self.hs.get_reactor(),
            self.site,
            "POST",
            path,
            content,
            custom_headers=custom_headers,
        )

        assert channel.code == expect_code, channel.result
        self.auth_user_id = temp_id

        if expect_code == HTTPStatus.OK:
            return channel.json_body["room_id"]
        else:
            return None

    def invite(
        self,
        room: str,
        src: Optional[str] = None,
        targ: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        tok: Optional[str] = None,
    ) -> None:
        self.change_membership(
            room=room,
            src=src,
            targ=targ,
            tok=tok,
            membership=Membership.INVITE,
            expect_code=expect_code,
        )

    def join(
        self,
        room: str,
        user: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        tok: Optional[str] = None,
        appservice_user_id: Optional[str] = None,
        expect_errcode: Optional[Codes] = None,
        expect_additional_fields: Optional[dict] = None,
    ) -> None:
        self.change_membership(
            room=room,
            src=user,
            targ=user,
            tok=tok,
            appservice_user_id=appservice_user_id,
            membership=Membership.JOIN,
            expect_code=expect_code,
            expect_errcode=expect_errcode,
            expect_additional_fields=expect_additional_fields,
        )

    def knock(
        self,
        room: Optional[str] = None,
        user: Optional[str] = None,
        reason: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        tok: Optional[str] = None,
    ) -> None:
        temp_id = self.auth_user_id
        self.auth_user_id = user
        path = "/knock/%s" % room
        if tok:
            path = path + "?access_token=%s" % tok

        data = {}
        if reason:
            data["reason"] = reason

        channel = make_request(
            self.hs.get_reactor(),
            self.site,
            "POST",
            path,
            data,
        )

        assert channel.code == expect_code, "Expected: %d, got: %d, resp: %r" % (
            expect_code,
            channel.code,
            channel.result["body"],
        )

        self.auth_user_id = temp_id

    def leave(
        self,
        room: str,
        user: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        tok: Optional[str] = None,
    ) -> None:
        self.change_membership(
            room=room,
            src=user,
            targ=user,
            tok=tok,
            membership=Membership.LEAVE,
            expect_code=expect_code,
        )

    def ban(
        self,
        room: str,
        src: str,
        targ: str,
        expect_code: int = HTTPStatus.OK,
        tok: Optional[str] = None,
    ) -> None:
        """A convenience helper: `change_membership` with `membership` preset to "ban"."""
        self.change_membership(
            room=room,
            src=src,
            targ=targ,
            tok=tok,
            membership=Membership.BAN,
            expect_code=expect_code,
        )

    def change_membership(
        self,
        room: str,
        src: Optional[str],
        targ: Optional[str],
        membership: str,
        extra_data: Optional[dict] = None,
        tok: Optional[str] = None,
        appservice_user_id: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        expect_errcode: Optional[str] = None,
        expect_additional_fields: Optional[dict] = None,
    ) -> None:
        """
        Send a membership state event into a room.

        Args:
            room: The ID of the room to send to
            src: The mxid of the event sender
            targ: The mxid of the event's target. The state key
            membership: The type of membership event
            extra_data: Extra information to include in the content of the event
            tok: The user access token to use
            appservice_user_id: The `user_id` URL parameter to pass.
                This allows driving an application service user
                using an application service access token in `tok`.
            expect_code: The expected HTTP response code
            expect_errcode: The expected Matrix error code
        """
        temp_id = self.auth_user_id
        self.auth_user_id = src

        path = f"/_matrix/client/r0/rooms/{room}/state/m.room.member/{targ}"
        url_params: Dict[str, str] = {}

        if tok:
            url_params["access_token"] = tok

        if appservice_user_id:
            url_params["user_id"] = appservice_user_id

        if url_params:
            path += "?" + urlencode(url_params)

        data = {"membership": membership}
        data.update(extra_data or {})

        channel = make_request(
            self.hs.get_reactor(),
            self.site,
            "PUT",
            path,
            data,
        )

        assert channel.code == expect_code, "Expected: %d, got: %d, resp: %r" % (
            expect_code,
            channel.code,
            channel.result["body"],
        )

        if expect_errcode:
            assert (
                str(channel.json_body["errcode"]) == expect_errcode
            ), "Expected: %r, got: %r, resp: %r" % (
                expect_errcode,
                channel.json_body["errcode"],
                channel.result["body"],
            )

        if expect_additional_fields is not None:
            for expect_key, expect_value in expect_additional_fields.items():
                assert expect_key in channel.json_body, "Expected field %s, got %s" % (
                    expect_key,
                    channel.json_body,
                )
                assert (
                    channel.json_body[expect_key] == expect_value
                ), "Expected: %s at %s, got: %s, resp: %s" % (
                    expect_value,
                    expect_key,
                    channel.json_body[expect_key],
                    channel.json_body,
                )

        self.auth_user_id = temp_id

    def send(
        self,
        room_id: str,
        body: Optional[str] = None,
        txn_id: Optional[str] = None,
        tok: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        custom_headers: Optional[Iterable[Tuple[AnyStr, AnyStr]]] = None,
    ) -> JsonDict:
        if body is None:
            body = "body_text_here"

        content = {"msgtype": "m.text", "body": body}

        return self.send_event(
            room_id,
            "m.room.message",
            content,
            txn_id,
            tok,
            expect_code,
            custom_headers=custom_headers,
        )

    def send_event(
        self,
        room_id: str,
        type: str,
        content: Optional[dict] = None,
        txn_id: Optional[str] = None,
        tok: Optional[str] = None,
        expect_code: int = HTTPStatus.OK,
        custom_headers: Optional[Iterable[Tuple[AnyStr, AnyStr]]] = None,
    ) -> JsonDict:
        if txn_id is None:
            txn_id = "m%s" % (str(time.time()))

        path = "/_matrix/client/r0/rooms/%s/send/%s/%s" % (room_id, type, txn_id)
        if tok:
            path = path + "?access_token=%s" % tok

        channel = make_request(
            self.hs.get_reactor(),
            self.site,
            "PUT",
            path,
            content or {},
            custom_headers=custom_headers,
        )

        assert channel.code == expect_code, "Expected: %d, got: %d, resp: %r" % (
            expect_code,
            channel.code,
            channel.result["body"],
        )

        return channel.json_body

    def _read_write_state(
        self,
        room_id: str,
        event_type: str,
        body: Optional[Dict[str, Any]],
        tok: Optional[str],
        expect_code: int = HTTPStatus.OK,
        state_key: str = "",
        method: str = "GET",
    ) -> JsonDict:
        """Read or write some state from a given room

        Args:
            room_id:
            event_type: The type of state event
            body: Body that is sent when making the request. The content of the state event.
                If None, the request to the server will have an empty body
            tok: The access token to use
            expect_code: The HTTP code to expect in the response
            state_key:
            method: "GET" or "PUT" for reading or writing state, respectively

        Returns:
            The response body from the server

        Raises:
            AssertionError: if expect_code doesn't match the HTTP code we received
        """
        path = "/_matrix/client/r0/rooms/%s/state/%s/%s" % (
            room_id,
            event_type,
            state_key,
        )
        if tok:
            path = path + "?access_token=%s" % tok

        # Set request body if provided
        content = b""
        if body is not None:
            content = json.dumps(body).encode("utf8")

        channel = make_request(self.hs.get_reactor(), self.site, method, path, content)

        assert channel.code == expect_code, "Expected: %d, got: %d, resp: %r" % (
            expect_code,
            channel.code,
            channel.result["body"],
        )

        return channel.json_body

    def get_state(
        self,
        room_id: str,
        event_type: str,
        tok: str,
        expect_code: int = HTTPStatus.OK,
        state_key: str = "",
    ) -> JsonDict:
        """Gets some state from a room

        Args:
            room_id:
            event_type: The type of state event
            tok: The access token to use
            expect_code: The HTTP code to expect in the response
            state_key:

        Returns:
            The response body from the server

        Raises:
            AssertionError: if expect_code doesn't match the HTTP code we received
        """
        return self._read_write_state(
            room_id, event_type, None, tok, expect_code, state_key, method="GET"
        )

    def send_state(
        self,
        room_id: str,
        event_type: str,
        body: Dict[str, Any],
        tok: Optional[str],
        expect_code: int = HTTPStatus.OK,
        state_key: str = "",
    ) -> JsonDict:
        """Set some state in a room

        Args:
            room_id:
            event_type: The type of state event
            body: Body that is sent when making the request. The content of the state event.
            tok: The access token to use
            expect_code: The HTTP code to expect in the response
            state_key:

        Returns:
            The response body from the server

        Raises:
            AssertionError: if expect_code doesn't match the HTTP code we received
        """
        return self._read_write_state(
            room_id, event_type, body, tok, expect_code, state_key, method="PUT"
        )

    def upload_media(
        self,
        resource: Resource,
        image_data: bytes,
        tok: str,
        filename: str = "test.png",
        expect_code: int = HTTPStatus.OK,
    ) -> JsonDict:
        """Upload a piece of test media to the media repo
        Args:
            resource: The resource that will handle the upload request
            image_data: The image data to upload
            tok: The user token to use during the upload
            filename: The filename of the media to be uploaded
            expect_code: The return code to expect from attempting to upload the media
        """
        image_length = len(image_data)
        path = "/_matrix/media/r0/upload?filename=%s" % (filename,)
        channel = make_request(
            self.hs.get_reactor(),
            FakeSite(resource, self.hs.get_reactor()),
            "POST",
            path,
            content=image_data,
            access_token=tok,
            custom_headers=[("Content-Length", str(image_length))],
        )

        assert channel.code == expect_code, "Expected: %d, got: %d, resp: %r" % (
            expect_code,
            channel.code,
            channel.result["body"],
        )

        return channel.json_body

    def login_via_oidc(
        self,
        remote_user_id: str,
        expected_status: int = 200,
    ) -> JsonDict:
        """Log in via OIDC

        Returns the result of the final token login.

        Requires that "oidc_config" in the homeserver config be set appropriately
        (TEST_OIDC_CONFIG is a suitable example) - and by implication, needs a
        "public_base_url".

        Also requires the login servlet and the OIDC callback resource to be mounted at
        the normal places.
        """
        client_redirect_url = "https://x"
        channel = self.auth_via_oidc({"sub": remote_user_id}, client_redirect_url)

        # expect a confirmation page
        assert channel.code == HTTPStatus.OK, channel.result

        # fish the matrix login token out of the body of the confirmation page
        m = re.search(
            'a href="%s.*loginToken=([^"]*)"' % (client_redirect_url,),
            channel.text_body,
        )
        assert m, channel.text_body
        login_token = m.group(1)

        # finally, submit the matrix login token to the login API, which gives us our
        # matrix access token and device id.
        channel = make_request(
            self.hs.get_reactor(),
            self.site,
            "POST",
            "/login",
            content={"type": "m.login.token", "token": login_token},
        )
        assert (
            channel.code == expected_status
        ), f"unexpected status in response: {channel.code}"
        return channel.json_body

    def auth_via_oidc(
        self,
        user_info_dict: JsonDict,
        client_redirect_url: Optional[str] = None,
        ui_auth_session_id: Optional[str] = None,
    ) -> FakeChannel:
        """Perform an OIDC authentication flow via a mock OIDC provider.

        This can be used for either login or user-interactive auth.

        Starts by making a request to the relevant synapse redirect endpoint, which is
        expected to serve a 302 to the OIDC provider. We then make a request to the
        OIDC callback endpoint, intercepting the HTTP requests that will get sent back
        to the OIDC provider.

        Requires that "oidc_config" in the homeserver config be set appropriately
        (TEST_OIDC_CONFIG is a suitable example) - and by implication, needs a
        "public_base_url".

        Also requires the login servlet and the OIDC callback resource to be mounted at
        the normal places.

        Args:
            user_info_dict: the remote userinfo that the OIDC provider should present.
                Typically this should be '{"sub": "<remote user id>"}'.
            client_redirect_url: for a login flow, the client redirect URL to pass to
                the login redirect endpoint
            ui_auth_session_id: if set, we will perform a UI Auth flow. The session id
                of the UI auth.

        Returns:
            A FakeChannel containing the result of calling the OIDC callback endpoint.
            Note that the response code may be a 200, 302 or 400 depending on how things
            went.
        """

        cookies: Dict[str, str] = {}

        # if we're doing a ui auth, hit the ui auth redirect endpoint
        if ui_auth_session_id:
            # can't set the client redirect url for UI Auth
            assert client_redirect_url is None
            oauth_uri = self.initiate_sso_ui_auth(ui_auth_session_id, cookies)
        else:
            # otherwise, hit the login redirect endpoint
            oauth_uri = self.initiate_sso_login(client_redirect_url, cookies)

        # we now have a URI for the OIDC IdP, but we skip that and go straight
        # back to synapse's OIDC callback resource. However, we do need the "state"
        # param that synapse passes to the IdP via query params, as well as the cookie
        # that synapse passes to the client.

        oauth_uri_path, _ = oauth_uri.split("?", 1)
        assert oauth_uri_path == TEST_OIDC_AUTH_ENDPOINT, (
            "unexpected SSO URI " + oauth_uri_path
        )
        return self.complete_oidc_auth(oauth_uri, cookies, user_info_dict)

    def complete_oidc_auth(
        self,
        oauth_uri: str,
        cookies: Mapping[str, str],
        user_info_dict: JsonDict,
    ) -> FakeChannel:
        """Mock out an OIDC authentication flow

        Assumes that an OIDC auth has been initiated by one of initiate_sso_login or
        initiate_sso_ui_auth; completes the OIDC bits of the flow by making a request to
        Synapse's OIDC callback endpoint, intercepting the HTTP requests that will get
        sent back to the OIDC provider.

        Requires the OIDC callback resource to be mounted at the normal place.

        Args:
            oauth_uri: the OIDC URI returned by synapse's redirect endpoint (ie,
               from initiate_sso_login or initiate_sso_ui_auth).
            cookies: the cookies set by synapse's redirect endpoint, which will be
               sent back to the callback endpoint.
            user_info_dict: the remote userinfo that the OIDC provider should present.
                Typically this should be '{"sub": "<remote user id>"}'.

        Returns:
            A FakeChannel containing the result of calling the OIDC callback endpoint.
        """
        _, oauth_uri_qs = oauth_uri.split("?", 1)
        params = urllib.parse.parse_qs(oauth_uri_qs)
        callback_uri = "%s?%s" % (
            urllib.parse.urlparse(params["redirect_uri"][0]).path,
            urllib.parse.urlencode({"state": params["state"][0], "code": "TEST_CODE"}),
        )

        # before we hit the callback uri, stub out some methods in the http client so
        # that we don't have to handle full HTTPS requests.
        # (expected url, json response) pairs, in the order we expect them.
        expected_requests = [
            # first we get a hit to the token endpoint, which we tell to return
            # a dummy OIDC access token
            (TEST_OIDC_TOKEN_ENDPOINT, {"access_token": "TEST"}),
            # and then one to the user_info endpoint, which returns our remote user id.
            (TEST_OIDC_USERINFO_ENDPOINT, user_info_dict),
        ]

        async def mock_req(
            method: str,
            uri: str,
            data: Optional[dict] = None,
            headers: Optional[Iterable[Tuple[AnyStr, AnyStr]]] = None,
        ):
            (expected_uri, resp_obj) = expected_requests.pop(0)
            assert uri == expected_uri
            resp = FakeResponse(
                code=HTTPStatus.OK,
                phrase=b"OK",
                body=json.dumps(resp_obj).encode("utf-8"),
            )
            return resp

        with patch.object(self.hs.get_proxied_http_client(), "request", mock_req):
            # now hit the callback URI with the right params and a made-up code
            channel = make_request(
                self.hs.get_reactor(),
                self.site,
                "GET",
                callback_uri,
                custom_headers=[
                    ("Cookie", "%s=%s" % (k, v)) for (k, v) in cookies.items()
                ],
            )
        return channel

    def initiate_sso_login(
        self, client_redirect_url: Optional[str], cookies: MutableMapping[str, str]
    ) -> str:
        """Make a request to the login-via-sso redirect endpoint, and return the target

        Assumes that exactly one SSO provider has been configured. Requires the login
        servlet to be mounted.

        Args:
            client_redirect_url: the client redirect URL to pass to the login redirect
                endpoint
            cookies: any cookies returned will be added to this dict

        Returns:
            the URI that the client gets redirected to (ie, the SSO server)
        """
        params = {}
        if client_redirect_url:
            params["redirectUrl"] = client_redirect_url

        # hit the redirect url (which should redirect back to the redirect url. This
        # is the easiest way of figuring out what the Host header ought to be set to
        # to keep Synapse happy.
        channel = make_request(
            self.hs.get_reactor(),
            self.site,
            "GET",
            "/_matrix/client/r0/login/sso/redirect?" + urllib.parse.urlencode(params),
        )
        assert channel.code == 302

        # hit the redirect url again with the right Host header, which should now issue
        # a cookie and redirect to the SSO provider.
        def get_location(channel: FakeChannel) -> str:
            location_values = channel.headers.getRawHeaders("Location")
            # Keep mypy happy by asserting that location_values is nonempty
            assert location_values
            return location_values[0]

        location = get_location(channel)
        parts = urllib.parse.urlsplit(location)
        channel = make_request(
            self.hs.get_reactor(),
            self.site,
            "GET",
            urllib.parse.urlunsplit(("", "") + parts[2:]),
            custom_headers=[
                ("Host", parts[1]),
            ],
        )

        assert channel.code == 302
        channel.extract_cookies(cookies)
        return get_location(channel)

    def initiate_sso_ui_auth(
        self, ui_auth_session_id: str, cookies: MutableMapping[str, str]
    ) -> str:
        """Make a request to the ui-auth-via-sso endpoint, and return the target

        Assumes that exactly one SSO provider has been configured. Requires the
        AuthRestServlet to be mounted.

        Args:
            ui_auth_session_id: the session id of the UI auth
            cookies: any cookies returned will be added to this dict

        Returns:
            the URI that the client gets linked to (ie, the SSO server)
        """
        sso_redirect_endpoint = (
            "/_matrix/client/r0/auth/m.login.sso/fallback/web?"
            + urllib.parse.urlencode({"session": ui_auth_session_id})
        )
        # hit the redirect url (which will issue a cookie and state)
        channel = make_request(
            self.hs.get_reactor(), self.site, "GET", sso_redirect_endpoint
        )
        # that should serve a confirmation page
        assert channel.code == HTTPStatus.OK, channel.text_body
        channel.extract_cookies(cookies)

        # parse the confirmation page to fish out the link.
        p = TestHtmlParser()
        p.feed(channel.text_body)
        p.close()
        assert len(p.links) == 1, "not exactly one link in confirmation page"
        oauth_uri = p.links[0]
        return oauth_uri


# an 'oidc_config' suitable for login_via_oidc.
TEST_OIDC_AUTH_ENDPOINT = "https://issuer.test/auth"
TEST_OIDC_TOKEN_ENDPOINT = "https://issuer.test/token"
TEST_OIDC_USERINFO_ENDPOINT = "https://issuer.test/userinfo"
TEST_OIDC_CONFIG = {
    "enabled": True,
    "discover": False,
    "issuer": "https://issuer.test",
    "client_id": "test-client-id",
    "client_secret": "test-client-secret",
    "scopes": ["profile"],
    "authorization_endpoint": TEST_OIDC_AUTH_ENDPOINT,
    "token_endpoint": TEST_OIDC_TOKEN_ENDPOINT,
    "userinfo_endpoint": TEST_OIDC_USERINFO_ENDPOINT,
    "user_mapping_provider": {"config": {"localpart_template": "{{ user.sub }}"}},
}
