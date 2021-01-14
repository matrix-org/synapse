import json
import time
import urllib.parse

from mock import Mock

import jwt

import synapse.rest.admin
from synapse.appservice import ApplicationService
from synapse.rest.client.v1 import login, logout
from synapse.rest.client.v2_alpha import devices, register
from synapse.rest.client.v2_alpha.account import WhoamiRestServlet

from tests import unittest
from tests.unittest import override_config

LOGIN_URL = b"/_matrix/client/r0/login"
TEST_URL = b"/_matrix/client/r0/account/whoami"


class LoginRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        logout.register_servlets,
        devices.register_servlets,
        lambda hs, http_server: WhoamiRestServlet(hs).register(http_server),
    ]

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        self.hs.config.enable_registration = True
        self.hs.config.registrations_require_3pid = []
        self.hs.config.auto_join_rooms = []
        self.hs.config.enable_registration_captcha = False

        return self.hs

    @override_config(
        {
            "rc_login": {
                "address": {"per_second": 0.17, "burst_count": 5},
                # Prevent the account login ratelimiter from raising first
                #
                # This is normally covered by the default test homeserver config
                # which sets these values to 10000, but as we're overriding the entire
                # rc_login dict here, we need to set this manually as well
                "account": {"per_second": 10000, "burst_count": 10000},
            }
        }
    )
    def test_POST_ratelimiting_per_address(self):
        # Create different users so we're sure not to be bothered by the per-user
        # ratelimiter.
        for i in range(0, 6):
            self.register_user("kermit" + str(i), "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit" + str(i)},
                "password": "monkey",
            }
            channel = self.make_request(b"POST", LOGIN_URL, params)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit" + str(i)},
            "password": "monkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    @override_config(
        {
            "rc_login": {
                "account": {"per_second": 0.17, "burst_count": 5},
                # Prevent the address login ratelimiter from raising first
                #
                # This is normally covered by the default test homeserver config
                # which sets these values to 10000, but as we're overriding the entire
                # rc_login dict here, we need to set this manually as well
                "address": {"per_second": 10000, "burst_count": 10000},
            }
        }
    )
    def test_POST_ratelimiting_per_account(self):
        self.register_user("kermit", "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit"},
                "password": "monkey",
            }
            channel = self.make_request(b"POST", LOGIN_URL, params)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "monkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    @override_config(
        {
            "rc_login": {
                # Prevent the address login ratelimiter from raising first
                #
                # This is normally covered by the default test homeserver config
                # which sets these values to 10000, but as we're overriding the entire
                # rc_login dict here, we need to set this manually as well
                "address": {"per_second": 10000, "burst_count": 10000},
                "failed_attempts": {"per_second": 0.17, "burst_count": 5},
            }
        }
    )
    def test_POST_ratelimiting_per_account_failed_attempts(self):
        self.register_user("kermit", "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit"},
                "password": "notamonkey",
            }
            channel = self.make_request(b"POST", LOGIN_URL, params)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"403", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "notamonkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"403", channel.result)

    @override_config({"session_lifetime": "24h"})
    def test_soft_logout(self):
        self.register_user("kermit", "monkey")

        # we shouldn't be able to make requests without an access token
        channel = self.make_request(b"GET", TEST_URL)
        self.assertEquals(channel.result["code"], b"401", channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_MISSING_TOKEN")

        # log in as normal
        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "monkey",
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.code, 200, channel.result)
        access_token = channel.json_body["access_token"]
        device_id = channel.json_body["device_id"]

        # we should now be able to make requests with the access token
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 200, channel.result)

        # time passes
        self.reactor.advance(24 * 3600)

        # ... and we should be soft-logouted
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        #
        # test behaviour after deleting the expired device
        #

        # we now log in as a different device
        access_token_2 = self.login("kermit", "monkey")

        # more requests with the expired token should still return a soft-logout
        self.reactor.advance(3600)
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        # ... but if we delete that device, it will be a proper logout
        self._delete_device(access_token_2, "kermit", "monkey", device_id)

        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], False)

    def _delete_device(self, access_token, user_id, password, device_id):
        """Perform the UI-Auth to delete a device"""
        channel = self.make_request(
            b"DELETE", "devices/" + device_id, access_token=access_token
        )
        self.assertEquals(channel.code, 401, channel.result)
        # check it's a UI-Auth fail
        self.assertEqual(
            set(channel.json_body.keys()),
            {"flows", "params", "session"},
            channel.result,
        )

        auth = {
            "type": "m.login.password",
            # https://github.com/matrix-org/synapse/issues/5665
            # "identifier": {"type": "m.id.user", "user": user_id},
            "user": user_id,
            "password": password,
            "session": channel.json_body["session"],
        }

        channel = self.make_request(
            b"DELETE",
            "devices/" + device_id,
            access_token=access_token,
            content={"auth": auth},
        )
        self.assertEquals(channel.code, 200, channel.result)

    @override_config({"session_lifetime": "24h"})
    def test_session_can_hard_logout_after_being_soft_logged_out(self):
        self.register_user("kermit", "monkey")

        # log in as normal
        access_token = self.login("kermit", "monkey")

        # we should now be able to make requests with the access token
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 200, channel.result)

        # time passes
        self.reactor.advance(24 * 3600)

        # ... and we should be soft-logouted
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        # Now try to hard logout this session
        channel = self.make_request(b"POST", "/logout", access_token=access_token)
        self.assertEquals(channel.result["code"], b"200", channel.result)

    @override_config({"session_lifetime": "24h"})
    def test_session_can_hard_logout_all_sessions_after_being_soft_logged_out(self):
        self.register_user("kermit", "monkey")

        # log in as normal
        access_token = self.login("kermit", "monkey")

        # we should now be able to make requests with the access token
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 200, channel.result)

        # time passes
        self.reactor.advance(24 * 3600)

        # ... and we should be soft-logouted
        channel = self.make_request(b"GET", TEST_URL, access_token=access_token)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        # Now try to hard log out all of the user's sessions
        channel = self.make_request(b"POST", "/logout/all", access_token=access_token)
        self.assertEquals(channel.result["code"], b"200", channel.result)


class CASTestCase(unittest.HomeserverTestCase):

    servlets = [
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        self.base_url = "https://matrix.goodserver.com/"
        self.redirect_path = "_synapse/client/login/sso/redirect/confirm"

        config = self.default_config()
        config["cas_config"] = {
            "enabled": True,
            "server_url": "https://fake.test",
            "service_url": "https://matrix.goodserver.com:8448",
        }

        cas_user_id = "username"
        self.user_id = "@%s:test" % cas_user_id

        async def get_raw(uri, args):
            """Return an example response payload from a call to the `/proxyValidate`
            endpoint of a CAS server, copied from
            https://apereo.github.io/cas/5.0.x/protocol/CAS-Protocol-V2-Specification.html#26-proxyvalidate-cas-20

            This needs to be returned by an async function (as opposed to set as the
            mock's return value) because the corresponding Synapse code awaits on it.
            """
            return (
                """
                <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                  <cas:authenticationSuccess>
                      <cas:user>%s</cas:user>
                      <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...</cas:proxyGrantingTicket>
                      <cas:proxies>
                          <cas:proxy>https://proxy2/pgtUrl</cas:proxy>
                          <cas:proxy>https://proxy1/pgtUrl</cas:proxy>
                      </cas:proxies>
                  </cas:authenticationSuccess>
                </cas:serviceResponse>
            """
                % cas_user_id
            ).encode("utf-8")

        mocked_http_client = Mock(spec=["get_raw"])
        mocked_http_client.get_raw.side_effect = get_raw

        self.hs = self.setup_test_homeserver(
            config=config, proxied_http_client=mocked_http_client,
        )

        return self.hs

    def prepare(self, reactor, clock, hs):
        self.deactivate_account_handler = hs.get_deactivate_account_handler()

    def test_cas_redirect_confirm(self):
        """Tests that the SSO login flow serves a confirmation page before redirecting a
        user to the redirect URL.
        """
        base_url = "/_matrix/client/r0/login/cas/ticket?redirectUrl"
        redirect_url = "https://dodgy-site.com/"

        url_parts = list(urllib.parse.urlparse(base_url))
        query = dict(urllib.parse.parse_qsl(url_parts[4]))
        query.update({"redirectUrl": redirect_url})
        query.update({"ticket": "ticket"})
        url_parts[4] = urllib.parse.urlencode(query)
        cas_ticket_url = urllib.parse.urlunparse(url_parts)

        # Get Synapse to call the fake CAS and serve the template.
        channel = self.make_request("GET", cas_ticket_url)

        # Test that the response is HTML.
        self.assertEqual(channel.code, 200)
        content_type_header_value = ""
        for header in channel.result.get("headers", []):
            if header[0] == b"Content-Type":
                content_type_header_value = header[1].decode("utf8")

        self.assertTrue(content_type_header_value.startswith("text/html"))

        # Test that the body isn't empty.
        self.assertTrue(len(channel.result["body"]) > 0)

        # And that it contains our redirect link
        self.assertIn(redirect_url, channel.result["body"].decode("UTF-8"))

    @override_config(
        {
            "sso": {
                "client_whitelist": [
                    "https://legit-site.com/",
                    "https://other-site.com/",
                ]
            }
        }
    )
    def test_cas_redirect_whitelisted(self):
        """Tests that the SSO login flow serves a redirect to a whitelisted url
        """
        self._test_redirect("https://legit-site.com/")

    @override_config({"public_baseurl": "https://example.com"})
    def test_cas_redirect_login_fallback(self):
        self._test_redirect("https://example.com/_matrix/static/client/login")

    def _test_redirect(self, redirect_url):
        """Tests that the SSO login flow serves a redirect for the given redirect URL."""
        cas_ticket_url = (
            "/_matrix/client/r0/login/cas/ticket?redirectUrl=%s&ticket=ticket"
            % (urllib.parse.quote(redirect_url))
        )

        # Get Synapse to call the fake CAS and serve the template.
        channel = self.make_request("GET", cas_ticket_url)

        self.assertEqual(channel.code, 302)
        location_headers = channel.headers.getRawHeaders("Location")
        self.assertEqual(location_headers[0][: len(redirect_url)], redirect_url)

    @override_config({"sso": {"client_whitelist": ["https://legit-site.com/"]}})
    def test_deactivated_user(self):
        """Logging in as a deactivated account should error."""
        redirect_url = "https://legit-site.com/"

        # First login (to create the user).
        self._test_redirect(redirect_url)

        # Deactivate the account.
        self.get_success(
            self.deactivate_account_handler.deactivate_account(self.user_id, False)
        )

        # Request the CAS ticket.
        cas_ticket_url = (
            "/_matrix/client/r0/login/cas/ticket?redirectUrl=%s&ticket=ticket"
            % (urllib.parse.quote(redirect_url))
        )

        # Get Synapse to call the fake CAS and serve the template.
        channel = self.make_request("GET", cas_ticket_url)

        # Because the user is deactivated they are served an error template.
        self.assertEqual(channel.code, 403)
        self.assertIn(b"SSO account deactivated", channel.result["body"])


class JWTTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
    ]

    jwt_secret = "secret"
    jwt_algorithm = "HS256"

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        self.hs.config.jwt_enabled = True
        self.hs.config.jwt_secret = self.jwt_secret
        self.hs.config.jwt_algorithm = self.jwt_algorithm
        return self.hs

    def jwt_encode(self, token: str, secret: str = jwt_secret) -> str:
        # PyJWT 2.0.0 changed the return type of jwt.encode from bytes to str.
        result = jwt.encode(token, secret, self.jwt_algorithm)
        if isinstance(result, bytes):
            return result.decode("ascii")
        return result

    def jwt_login(self, *args):
        params = json.dumps(
            {"type": "org.matrix.login.jwt", "token": self.jwt_encode(*args)}
        )
        channel = self.make_request(b"POST", LOGIN_URL, params)
        return channel

    def test_login_jwt_valid_registered(self):
        self.register_user("kermit", "monkey")
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

    def test_login_jwt_valid_unregistered(self):
        channel = self.jwt_login({"sub": "frog"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@frog:test")

    def test_login_jwt_invalid_signature(self):
        channel = self.jwt_login({"sub": "frog"}, "notsecret")
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            "JWT validation failed: Signature verification failed",
        )

    def test_login_jwt_expired(self):
        channel = self.jwt_login({"sub": "frog", "exp": 864000})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Signature has expired"
        )

    def test_login_jwt_not_before(self):
        now = int(time.time())
        channel = self.jwt_login({"sub": "frog", "nbf": now + 3600})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            "JWT validation failed: The token is not yet valid (nbf)",
        )

    def test_login_no_sub(self):
        channel = self.jwt_login({"username": "root"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(channel.json_body["error"], "Invalid JWT")

    @override_config(
        {
            "jwt_config": {
                "jwt_enabled": True,
                "secret": jwt_secret,
                "algorithm": jwt_algorithm,
                "issuer": "test-issuer",
            }
        }
    )
    def test_login_iss(self):
        """Test validating the issuer claim."""
        # A valid issuer.
        channel = self.jwt_login({"sub": "kermit", "iss": "test-issuer"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

        # An invalid issuer.
        channel = self.jwt_login({"sub": "kermit", "iss": "invalid"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Invalid issuer"
        )

        # Not providing an issuer.
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            'JWT validation failed: Token is missing the "iss" claim',
        )

    def test_login_iss_no_config(self):
        """Test providing an issuer claim without requiring it in the configuration."""
        channel = self.jwt_login({"sub": "kermit", "iss": "invalid"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

    @override_config(
        {
            "jwt_config": {
                "jwt_enabled": True,
                "secret": jwt_secret,
                "algorithm": jwt_algorithm,
                "audiences": ["test-audience"],
            }
        }
    )
    def test_login_aud(self):
        """Test validating the audience claim."""
        # A valid audience.
        channel = self.jwt_login({"sub": "kermit", "aud": "test-audience"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

        # An invalid audience.
        channel = self.jwt_login({"sub": "kermit", "aud": "invalid"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Invalid audience"
        )

        # Not providing an audience.
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            'JWT validation failed: Token is missing the "aud" claim',
        )

    def test_login_aud_no_config(self):
        """Test providing an audience without requiring it in the configuration."""
        channel = self.jwt_login({"sub": "kermit", "aud": "invalid"})
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"], "JWT validation failed: Invalid audience"
        )

    def test_login_no_token(self):
        params = json.dumps({"type": "org.matrix.login.jwt"})
        channel = self.make_request(b"POST", LOGIN_URL, params)
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(channel.json_body["error"], "Token field for JWT is missing")


# The JWTPubKeyTestCase is a complement to JWTTestCase where we instead use
# RSS256, with a public key configured in synapse as "jwt_secret", and tokens
# signed by the private key.
class JWTPubKeyTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
    ]

    # This key's pubkey is used as the jwt_secret setting of synapse. Valid
    # tokens are signed by this and validated using the pubkey. It is generated
    # with `openssl genrsa 512` (not a secure way to generate real keys, but
    # good enough for tests!)
    jwt_privatekey = "\n".join(
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIBPAIBAAJBAM50f1Q5gsdmzifLstzLHb5NhfajiOt7TKO1vSEWdq7u9x8SMFiB",
            "492RM9W/XFoh8WUfL9uL6Now6tPRDsWv3xsCAwEAAQJAUv7OOSOtiU+wzJq82rnk",
            "yR4NHqt7XX8BvkZPM7/+EjBRanmZNSp5kYZzKVaZ/gTOM9+9MwlmhidrUOweKfB/",
            "kQIhAPZwHazbjo7dYlJs7wPQz1vd+aHSEH+3uQKIysebkmm3AiEA1nc6mDdmgiUq",
            "TpIN8A4MBKmfZMWTLq6z05y/qjKyxb0CIQDYJxCwTEenIaEa4PdoJl+qmXFasVDN",
            "ZU0+XtNV7yul0wIhAMI9IhiStIjS2EppBa6RSlk+t1oxh2gUWlIh+YVQfZGRAiEA",
            "tqBR7qLZGJ5CVKxWmNhJZGt1QHoUtOch8t9C4IdOZ2g=",
            "-----END RSA PRIVATE KEY-----",
        ]
    )

    # Generated with `openssl rsa -in foo.key -pubout`, with the the above
    # private key placed in foo.key (jwt_privatekey).
    jwt_pubkey = "\n".join(
        [
            "-----BEGIN PUBLIC KEY-----",
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM50f1Q5gsdmzifLstzLHb5NhfajiOt7",
            "TKO1vSEWdq7u9x8SMFiB492RM9W/XFoh8WUfL9uL6Now6tPRDsWv3xsCAwEAAQ==",
            "-----END PUBLIC KEY-----",
        ]
    )

    # This key is used to sign tokens that shouldn't be accepted by synapse.
    # Generated just like jwt_privatekey.
    bad_privatekey = "\n".join(
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIBOgIBAAJBAL//SQrKpKbjCCnv/FlasJCv+t3k/MPsZfniJe4DVFhsktF2lwQv",
            "gLjmQD3jBUTz+/FndLSBvr3F4OHtGL9O/osCAwEAAQJAJqH0jZJW7Smzo9ShP02L",
            "R6HRZcLExZuUrWI+5ZSP7TaZ1uwJzGFspDrunqaVoPobndw/8VsP8HFyKtceC7vY",
            "uQIhAPdYInDDSJ8rFKGiy3Ajv5KWISBicjevWHF9dbotmNO9AiEAxrdRJVU+EI9I",
            "eB4qRZpY6n4pnwyP0p8f/A3NBaQPG+cCIFlj08aW/PbxNdqYoBdeBA0xDrXKfmbb",
            "iwYxBkwL0JCtAiBYmsi94sJn09u2Y4zpuCbJeDPKzWkbuwQh+W1fhIWQJQIhAKR0",
            "KydN6cRLvphNQ9c/vBTdlzWxzcSxREpguC7F1J1m",
            "-----END RSA PRIVATE KEY-----",
        ]
    )

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        self.hs.config.jwt_enabled = True
        self.hs.config.jwt_secret = self.jwt_pubkey
        self.hs.config.jwt_algorithm = "RS256"
        return self.hs

    def jwt_encode(self, token: str, secret: str = jwt_privatekey) -> str:
        # PyJWT 2.0.0 changed the return type of jwt.encode from bytes to str.
        result = jwt.encode(token, secret, "RS256")
        if isinstance(result, bytes):
            return result.decode("ascii")
        return result

    def jwt_login(self, *args):
        params = json.dumps(
            {"type": "org.matrix.login.jwt", "token": self.jwt_encode(*args)}
        )
        channel = self.make_request(b"POST", LOGIN_URL, params)
        return channel

    def test_login_jwt_valid(self):
        channel = self.jwt_login({"sub": "kermit"})
        self.assertEqual(channel.result["code"], b"200", channel.result)
        self.assertEqual(channel.json_body["user_id"], "@kermit:test")

    def test_login_jwt_invalid_signature(self):
        channel = self.jwt_login({"sub": "frog"}, self.bad_privatekey)
        self.assertEqual(channel.result["code"], b"403", channel.result)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        self.assertEqual(
            channel.json_body["error"],
            "JWT validation failed: Signature verification failed",
        )


AS_USER = "as_user_alice"


class AppserviceLoginRestServletTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
        register.register_servlets,
    ]

    def register_as_user(self, username):
        self.make_request(
            b"POST",
            "/_matrix/client/r0/register?access_token=%s" % (self.service.token,),
            {"username": username},
        )

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()

        self.service = ApplicationService(
            id="unique_identifier",
            token="some_token",
            hostname="example.com",
            sender="@asbot:example.com",
            namespaces={
                ApplicationService.NS_USERS: [
                    {"regex": r"@as_user.*", "exclusive": False}
                ],
                ApplicationService.NS_ROOMS: [],
                ApplicationService.NS_ALIASES: [],
            },
        )
        self.another_service = ApplicationService(
            id="another__identifier",
            token="another_token",
            hostname="example.com",
            sender="@as2bot:example.com",
            namespaces={
                ApplicationService.NS_USERS: [
                    {"regex": r"@as2_user.*", "exclusive": False}
                ],
                ApplicationService.NS_ROOMS: [],
                ApplicationService.NS_ALIASES: [],
            },
        )

        self.hs.get_datastore().services_cache.append(self.service)
        self.hs.get_datastore().services_cache.append(self.another_service)
        return self.hs

    def test_login_appservice_user(self):
        """Test that an appservice user can use /login
        """
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": AS_USER},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.service.token
        )

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_login_appservice_user_bot(self):
        """Test that the appservice bot can use /login
        """
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": self.service.sender},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.service.token
        )

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_login_appservice_wrong_user(self):
        """Test that non-as users cannot login with the as token
        """
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": "fibble_wibble"},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.service.token
        )

        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_login_appservice_wrong_as(self):
        """Test that as users cannot login with wrong as token
        """
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": AS_USER},
        }
        channel = self.make_request(
            b"POST", LOGIN_URL, params, access_token=self.another_service.token
        )

        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_login_appservice_no_token(self):
        """Test that users must provide a token when using the appservice
           login method
        """
        self.register_as_user(AS_USER)

        params = {
            "type": login.LoginRestServlet.APPSERVICE_TYPE,
            "identifier": {"type": "m.id.user", "user": AS_USER},
        }
        channel = self.make_request(b"POST", LOGIN_URL, params)

        self.assertEquals(channel.result["code"], b"401", channel.result)
