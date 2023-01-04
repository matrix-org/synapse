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
import json
import logging
from io import BytesIO, StringIO
from unittest.mock import Mock, patch

from twisted.web.server import Request

from synapse.http.site import SynapseRequest
from synapse.logging._terse_json import JsonFormatter, TerseJsonFormatter
from synapse.logging.context import LoggingContext, LoggingContextFilter

from tests.logging import LoggerCleanupMixin
from tests.server import FakeChannel
from tests.unittest import TestCase


class TerseJsonTestCase(LoggerCleanupMixin, TestCase):
    def setUp(self):
        self.output = StringIO()

    def get_log_line(self):
        # One log message, with a single trailing newline.
        data = self.output.getvalue()
        logs = data.splitlines()
        self.assertEqual(len(logs), 1)
        self.assertEqual(data.count("\n"), 1)
        return json.loads(logs[0])

    def test_terse_json_output(self):
        """
        The Terse JSON formatter converts log messages to JSON.
        """
        handler = logging.StreamHandler(self.output)
        handler.setFormatter(TerseJsonFormatter())
        logger = self.get_logger(handler)

        logger.info("Hello there, %s!", "wally")

        log = self.get_log_line()

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "time",
            "level",
            "namespace",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")

    def test_extra_data(self):
        """
        Additional information can be included in the structured logging.
        """
        handler = logging.StreamHandler(self.output)
        handler.setFormatter(TerseJsonFormatter())
        logger = self.get_logger(handler)

        logger.info(
            "Hello there, %s!", "wally", extra={"foo": "bar", "int": 3, "bool": True}
        )

        log = self.get_log_line()

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "time",
            "level",
            "namespace",
            # The additional keys given via extra.
            "foo",
            "int",
            "bool",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)

        # Check the values of the extra fields.
        self.assertEqual(log["foo"], "bar")
        self.assertEqual(log["int"], 3)
        self.assertIs(log["bool"], True)

    def test_json_output(self):
        """
        The Terse JSON formatter converts log messages to JSON.
        """
        handler = logging.StreamHandler(self.output)
        handler.setFormatter(JsonFormatter())
        logger = self.get_logger(handler)

        logger.info("Hello there, %s!", "wally")

        log = self.get_log_line()

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "level",
            "namespace",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")

    def test_with_context(self):
        """
        The logging context should be added to the JSON response.
        """
        handler = logging.StreamHandler(self.output)
        handler.setFormatter(JsonFormatter())
        handler.addFilter(LoggingContextFilter())
        logger = self.get_logger(handler)

        with LoggingContext("name"):
            logger.info("Hello there, %s!", "wally")

        log = self.get_log_line()

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "level",
            "namespace",
            "request",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")
        self.assertEqual(log["request"], "name")

    def test_with_request_context(self):
        """
        Information from the logging context request should be added to the JSON response.
        """
        handler = logging.StreamHandler(self.output)
        handler.setFormatter(JsonFormatter())
        handler.addFilter(LoggingContextFilter())
        logger = self.get_logger(handler)

        # A full request isn't needed here.
        site = Mock(spec=["site_tag", "server_version_string", "getResourceFor"])
        site.site_tag = "test-site"
        site.server_version_string = "Server v1"
        site.reactor = Mock()
        site.experimental_cors_msc3886 = False
        request = SynapseRequest(FakeChannel(site, None), site)
        # Call requestReceived to finish instantiating the object.
        request.content = BytesIO()
        # Partially skip some of the internal processing of SynapseRequest.
        request._started_processing = Mock()
        request.request_metrics = Mock(spec=["name"])
        with patch.object(Request, "render"):
            request.requestReceived(b"POST", b"/_matrix/client/versions", b"1.1")

        # Also set the requester to ensure the processing works.
        request.requester = "@foo:test"

        with LoggingContext(
            request.get_request_id(), parent_context=request.logcontext
        ):
            logger.info("Hello there, %s!", "wally")

        log = self.get_log_line()

        # The terse logger includes additional request information, if possible.
        expected_log_keys = [
            "log",
            "level",
            "namespace",
            "request",
            "ip_address",
            "site_tag",
            "requester",
            "authenticated_entity",
            "method",
            "url",
            "protocol",
            "user_agent",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")
        self.assertTrue(log["request"].startswith("POST-"))
        self.assertEqual(log["ip_address"], "127.0.0.1")
        self.assertEqual(log["site_tag"], "test-site")
        self.assertEqual(log["requester"], "@foo:test")
        self.assertEqual(log["authenticated_entity"], "@foo:test")
        self.assertEqual(log["method"], "POST")
        self.assertEqual(log["url"], "/_matrix/client/versions")
        self.assertEqual(log["protocol"], "1.1")
        self.assertEqual(log["user_agent"], "")

    def test_with_exception(self):
        """
        The logging exception type & value should be added to the JSON response.
        """
        handler = logging.StreamHandler(self.output)
        handler.setFormatter(JsonFormatter())
        logger = self.get_logger(handler)

        try:
            raise ValueError("That's wrong, you wally!")
        except ValueError:
            logger.exception("Hello there, %s!", "wally")

        log = self.get_log_line()

        # The terse logger should give us these keys.
        expected_log_keys = [
            "log",
            "level",
            "namespace",
            "exc_type",
            "exc_value",
        ]
        self.assertCountEqual(log.keys(), expected_log_keys)
        self.assertEqual(log["log"], "Hello there, wally!")
        self.assertEqual(log["exc_type"], "ValueError")
        self.assertEqual(log["exc_value"], "That's wrong, you wally!")
