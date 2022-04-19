# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import List, Optional

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest


class FederationTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.url = "/_synapse/admin/v1/federation/destinations"

    @parameterized.expand(
        [
            ("GET", "/_synapse/admin/v1/federation/destinations"),
            ("GET", "/_synapse/admin/v1/federation/destinations/dummy"),
            (
                "POST",
                "/_synapse/admin/v1/federation/destinations/dummy/reset_connection",
            ),
        ]
    )
    def test_requester_is_no_admin(self, method: str, url: str) -> None:
        """If the user is not a server admin, an error 403 is returned."""

        self.register_user("user", "pass", admin=False)
        other_user_tok = self.login("user", "pass")

        channel = self.make_request(
            method,
            url,
            content={},
            access_token=other_user_tok,
        )

        self.assertEqual(HTTPStatus.FORBIDDEN, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_invalid_parameter(self) -> None:
        """If parameters are invalid, an error is returned."""

        # negative limit
        channel = self.make_request(
            "GET",
            self.url + "?limit=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # negative from
        channel = self.make_request(
            "GET",
            self.url + "?from=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # unkown order_by
        channel = self.make_request(
            "GET",
            self.url + "?order_by=bar",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid search order
        channel = self.make_request(
            "GET",
            self.url + "?dir=bar",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid destination
        channel = self.make_request(
            "GET",
            self.url + "/dummy",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.NOT_FOUND, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

        # invalid destination
        channel = self.make_request(
            "POST",
            self.url + "/dummy/reset_connection",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.NOT_FOUND, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_limit(self) -> None:
        """Testing list of destinations with limit"""

        number_destinations = 20
        self._create_destinations(number_destinations)

        channel = self.make_request(
            "GET",
            self.url + "?limit=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_destinations)
        self.assertEqual(len(channel.json_body["destinations"]), 5)
        self.assertEqual(channel.json_body["next_token"], "5")
        self._check_fields(channel.json_body["destinations"])

    def test_from(self) -> None:
        """Testing list of destinations with a defined starting point (from)"""

        number_destinations = 20
        self._create_destinations(number_destinations)

        channel = self.make_request(
            "GET",
            self.url + "?from=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_destinations)
        self.assertEqual(len(channel.json_body["destinations"]), 15)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["destinations"])

    def test_limit_and_from(self) -> None:
        """Testing list of destinations with a defined starting point and limit"""

        number_destinations = 20
        self._create_destinations(number_destinations)

        channel = self.make_request(
            "GET",
            self.url + "?from=5&limit=10",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_destinations)
        self.assertEqual(channel.json_body["next_token"], "15")
        self.assertEqual(len(channel.json_body["destinations"]), 10)
        self._check_fields(channel.json_body["destinations"])

    def test_next_token(self) -> None:
        """Testing that `next_token` appears at the right place"""

        number_destinations = 20
        self._create_destinations(number_destinations)

        #  `next_token` does not appear
        # Number of results is the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=20",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_destinations)
        self.assertEqual(len(channel.json_body["destinations"]), number_destinations)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does not appear
        # Number of max results is larger than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=21",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_destinations)
        self.assertEqual(len(channel.json_body["destinations"]), number_destinations)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does appear
        # Number of max results is smaller than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=19",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_destinations)
        self.assertEqual(len(channel.json_body["destinations"]), 19)
        self.assertEqual(channel.json_body["next_token"], "19")

        # Check
        # Set `from` to value of `next_token` for request remaining entries
        #  `next_token` does not appear
        channel = self.make_request(
            "GET",
            self.url + "?from=19",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_destinations)
        self.assertEqual(len(channel.json_body["destinations"]), 1)
        self.assertNotIn("next_token", channel.json_body)

    def test_list_all_destinations(self) -> None:
        """List all destinations."""
        number_destinations = 5
        self._create_destinations(number_destinations)

        channel = self.make_request(
            "GET",
            self.url,
            {},
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(number_destinations, len(channel.json_body["destinations"]))
        self.assertEqual(number_destinations, channel.json_body["total"])

        # Check that all fields are available
        self._check_fields(channel.json_body["destinations"])

    def test_order_by(self) -> None:
        """Testing order list with parameter `order_by`"""

        def _order_test(
            expected_destination_list: List[str],
            order_by: Optional[str],
            dir: Optional[str] = None,
        ) -> None:
            """Request the list of destinations in a certain order.
            Assert that order is what we expect

            Args:
                expected_destination_list: The list of user_id in the order
                    we expect to get back from the server
                order_by: The type of ordering to give the server
                dir: The direction of ordering to give the server
            """

            url = f"{self.url}?"
            if order_by is not None:
                url += f"order_by={order_by}&"
            if dir is not None and dir in ("b", "f"):
                url += f"dir={dir}"
            channel = self.make_request(
                "GET",
                url,
                access_token=self.admin_user_tok,
            )
            self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
            self.assertEqual(channel.json_body["total"], len(expected_destination_list))

            returned_order = [
                row["destination"] for row in channel.json_body["destinations"]
            ]
            self.assertEqual(expected_destination_list, returned_order)
            self._check_fields(channel.json_body["destinations"])

        # create destinations
        dest = [
            ("sub-a.example.com", 100, 300, 200, 300),
            ("sub-b.example.com", 200, 200, 100, 100),
            ("sub-c.example.com", 300, 100, 300, 200),
        ]
        for (
            destination,
            failure_ts,
            retry_last_ts,
            retry_interval,
            last_successful_stream_ordering,
        ) in dest:
            self._create_destination(
                destination,
                failure_ts,
                retry_last_ts,
                retry_interval,
                last_successful_stream_ordering,
            )

        # order by default (destination)
        _order_test([dest[0][0], dest[1][0], dest[2][0]], None)
        _order_test([dest[0][0], dest[1][0], dest[2][0]], None, "f")
        _order_test([dest[2][0], dest[1][0], dest[0][0]], None, "b")

        # order by destination
        _order_test([dest[0][0], dest[1][0], dest[2][0]], "destination")
        _order_test([dest[0][0], dest[1][0], dest[2][0]], "destination", "f")
        _order_test([dest[2][0], dest[1][0], dest[0][0]], "destination", "b")

        # order by failure_ts
        _order_test([dest[0][0], dest[1][0], dest[2][0]], "failure_ts")
        _order_test([dest[0][0], dest[1][0], dest[2][0]], "failure_ts", "f")
        _order_test([dest[2][0], dest[1][0], dest[0][0]], "failure_ts", "b")

        # order by retry_last_ts
        _order_test([dest[2][0], dest[1][0], dest[0][0]], "retry_last_ts")
        _order_test([dest[2][0], dest[1][0], dest[0][0]], "retry_last_ts", "f")
        _order_test([dest[0][0], dest[1][0], dest[2][0]], "retry_last_ts", "b")

        # order by retry_interval
        _order_test([dest[1][0], dest[0][0], dest[2][0]], "retry_interval")
        _order_test([dest[1][0], dest[0][0], dest[2][0]], "retry_interval", "f")
        _order_test([dest[2][0], dest[0][0], dest[1][0]], "retry_interval", "b")

        # order by last_successful_stream_ordering
        _order_test(
            [dest[1][0], dest[2][0], dest[0][0]], "last_successful_stream_ordering"
        )
        _order_test(
            [dest[1][0], dest[2][0], dest[0][0]], "last_successful_stream_ordering", "f"
        )
        _order_test(
            [dest[0][0], dest[2][0], dest[1][0]], "last_successful_stream_ordering", "b"
        )

    def test_search_term(self) -> None:
        """Test that searching for a destination works correctly"""

        def _search_test(
            expected_destination: Optional[str],
            search_term: str,
        ) -> None:
            """Search for a destination and check that the returned destinationis a match

            Args:
                expected_destination: The room_id expected to be returned by the API.
                    Set to None to expect zero results for the search
                search_term: The term to search for room names with
            """
            url = f"{self.url}?destination={search_term}"
            channel = self.make_request(
                "GET",
                url.encode("ascii"),
                access_token=self.admin_user_tok,
            )
            self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

            # Check that destinations were returned
            self.assertTrue("destinations" in channel.json_body)
            self._check_fields(channel.json_body["destinations"])
            destinations = channel.json_body["destinations"]

            # Check that the expected number of destinations were returned
            expected_destination_count = 1 if expected_destination else 0
            self.assertEqual(len(destinations), expected_destination_count)
            self.assertEqual(channel.json_body["total"], expected_destination_count)

            if expected_destination:
                # Check that the first returned destination is correct
                self.assertEqual(expected_destination, destinations[0]["destination"])

        number_destinations = 3
        self._create_destinations(number_destinations)

        # Test searching
        _search_test("sub0.example.com", "0")
        _search_test("sub0.example.com", "sub0")

        _search_test("sub1.example.com", "1")
        _search_test("sub1.example.com", "1.")

        # Test case insensitive
        _search_test("sub0.example.com", "SUB0")

        _search_test(None, "foo")
        _search_test(None, "bar")

    def test_get_single_destination_with_retry_timings(self) -> None:
        """Get one specific destination which has retry timings."""
        self._create_destinations(1)

        channel = self.make_request(
            "GET",
            self.url + "/sub0.example.com",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual("sub0.example.com", channel.json_body["destination"])

        # Check that all fields are available
        # convert channel.json_body into a List
        self._check_fields([channel.json_body])

    def test_get_single_destination_no_retry_timings(self) -> None:
        """Get one specific destination which has no retry timings."""
        self._create_destination("sub0.example.com")

        channel = self.make_request(
            "GET",
            self.url + "/sub0.example.com",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual("sub0.example.com", channel.json_body["destination"])
        self.assertEqual(0, channel.json_body["retry_last_ts"])
        self.assertEqual(0, channel.json_body["retry_interval"])
        self.assertIsNone(channel.json_body["failure_ts"])
        self.assertIsNone(channel.json_body["last_successful_stream_ordering"])

    def test_destination_reset_connection(self) -> None:
        """Reset timeouts and wake up destination."""
        self._create_destination("sub0.example.com", 100, 100, 100)

        channel = self.make_request(
            "POST",
            self.url + "/sub0.example.com/reset_connection",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)

        retry_timings = self.get_success(
            self.store.get_destination_retry_timings("sub0.example.com")
        )
        self.assertIsNone(retry_timings)

    def test_destination_reset_connection_not_required(self) -> None:
        """Try to reset timeouts of a destination with no timeouts and get an error."""
        self._create_destination("sub0.example.com", None, 0, 0)

        channel = self.make_request(
            "POST",
            self.url + "/sub0.example.com/reset_connection",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(
            "The retry timing does not need to be reset for this destination.",
            channel.json_body["error"],
        )

    def _create_destination(
        self,
        destination: str,
        failure_ts: Optional[int] = None,
        retry_last_ts: int = 0,
        retry_interval: int = 0,
        last_successful_stream_ordering: Optional[int] = None,
    ) -> None:
        """Create one specific destination

        Args:
            destination: the destination we have successfully sent to
            failure_ts: when the server started failing (ms since epoch)
            retry_last_ts: time of last retry attempt in unix epoch ms
            retry_interval: how long until next retry in ms
            last_successful_stream_ordering: the stream_ordering of the most
                recent successfully-sent PDU
        """
        self.get_success(
            self.store.set_destination_retry_timings(
                destination, failure_ts, retry_last_ts, retry_interval
            )
        )
        if last_successful_stream_ordering is not None:
            self.get_success(
                self.store.set_destination_last_successful_stream_ordering(
                    destination, last_successful_stream_ordering
                )
            )

    def _create_destinations(self, number_destinations: int) -> None:
        """Create a number of destinations

        Args:
            number_destinations: Number of destinations to be created
        """
        for i in range(0, number_destinations):
            dest = f"sub{i}.example.com"
            self._create_destination(dest, 50, 50, 50, 100)

    def _check_fields(self, content: List[JsonDict]) -> None:
        """Checks that the expected destination attributes are present in content

        Args:
            content: List that is checked for content
        """
        for c in content:
            self.assertIn("destination", c)
            self.assertIn("retry_last_ts", c)
            self.assertIn("retry_interval", c)
            self.assertIn("failure_ts", c)
            self.assertIn("last_successful_stream_ordering", c)


class DestinationMembershipTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.dest = "sub0.example.com"
        self.url = f"/_synapse/admin/v1/federation/destinations/{self.dest}/rooms"

        # Record that we successfully contacted a destination in the DB.
        self.get_success(
            self.store.set_destination_retry_timings(self.dest, None, 0, 0)
        )

    def test_requester_is_no_admin(self) -> None:
        """If the user is not a server admin, an error 403 is returned."""

        self.register_user("user", "pass", admin=False)
        other_user_tok = self.login("user", "pass")

        channel = self.make_request(
            "GET",
            self.url,
            access_token=other_user_tok,
        )

        self.assertEqual(HTTPStatus.FORBIDDEN, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_invalid_parameter(self) -> None:
        """If parameters are invalid, an error is returned."""

        # negative limit
        channel = self.make_request(
            "GET",
            self.url + "?limit=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # negative from
        channel = self.make_request(
            "GET",
            self.url + "?from=-5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid search order
        channel = self.make_request(
            "GET",
            self.url + "?dir=bar",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.BAD_REQUEST, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])

        # invalid destination
        channel = self.make_request(
            "GET",
            "/_synapse/admin/v1/federation/destinations/%s/rooms" % ("invalid",),
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.NOT_FOUND, channel.code, msg=channel.json_body)
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_limit(self) -> None:
        """Testing list of destinations with limit"""

        number_rooms = 5
        self._create_destination_rooms(number_rooms)

        channel = self.make_request(
            "GET",
            self.url + "?limit=3",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(len(channel.json_body["rooms"]), 3)
        self.assertEqual(channel.json_body["next_token"], "3")
        self._check_fields(channel.json_body["rooms"])

    def test_from(self) -> None:
        """Testing list of rooms with a defined starting point (from)"""

        number_rooms = 10
        self._create_destination_rooms(number_rooms)

        channel = self.make_request(
            "GET",
            self.url + "?from=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(len(channel.json_body["rooms"]), 5)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["rooms"])

    def test_limit_and_from(self) -> None:
        """Testing list of rooms with a defined starting point and limit"""

        number_rooms = 10
        self._create_destination_rooms(number_rooms)

        channel = self.make_request(
            "GET",
            self.url + "?from=3&limit=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(channel.json_body["next_token"], "8")
        self.assertEqual(len(channel.json_body["rooms"]), 5)
        self._check_fields(channel.json_body["rooms"])

    def test_order_direction(self) -> None:
        """Testing order list with parameter `dir`"""
        number_rooms = 4
        self._create_destination_rooms(number_rooms)

        # get list in forward direction
        channel_asc = self.make_request(
            "GET",
            self.url + "?dir=f",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel_asc.code, msg=channel_asc.json_body)
        self.assertEqual(channel_asc.json_body["total"], number_rooms)
        self.assertEqual(number_rooms, len(channel_asc.json_body["rooms"]))
        self._check_fields(channel_asc.json_body["rooms"])

        # get list in backward direction
        channel_desc = self.make_request(
            "GET",
            self.url + "?dir=b",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel_desc.code, msg=channel_desc.json_body)
        self.assertEqual(channel_desc.json_body["total"], number_rooms)
        self.assertEqual(number_rooms, len(channel_desc.json_body["rooms"]))
        self._check_fields(channel_desc.json_body["rooms"])

        # test that both lists have different directions
        for i in range(0, number_rooms):
            self.assertEqual(
                channel_asc.json_body["rooms"][i]["room_id"],
                channel_desc.json_body["rooms"][number_rooms - 1 - i]["room_id"],
            )

    def test_next_token(self) -> None:
        """Testing that `next_token` appears at the right place"""

        number_rooms = 5
        self._create_destination_rooms(number_rooms)

        #  `next_token` does not appear
        # Number of results is the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=5",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(len(channel.json_body["rooms"]), number_rooms)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does not appear
        # Number of max results is larger than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=6",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(len(channel.json_body["rooms"]), number_rooms)
        self.assertNotIn("next_token", channel.json_body)

        #  `next_token` does appear
        # Number of max results is smaller than the number of entries
        channel = self.make_request(
            "GET",
            self.url + "?limit=4",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(len(channel.json_body["rooms"]), 4)
        self.assertEqual(channel.json_body["next_token"], "4")

        # Check
        # Set `from` to value of `next_token` for request remaining entries
        #  `next_token` does not appear
        channel = self.make_request(
            "GET",
            self.url + "?from=4",
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(len(channel.json_body["rooms"]), 1)
        self.assertNotIn("next_token", channel.json_body)

    def test_destination_rooms(self) -> None:
        """Testing that request the list of rooms is successfully."""
        number_rooms = 3
        self._create_destination_rooms(number_rooms)

        channel = self.make_request(
            "GET",
            self.url,
            access_token=self.admin_user_tok,
        )

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], number_rooms)
        self.assertEqual(number_rooms, len(channel.json_body["rooms"]))
        self._check_fields(channel.json_body["rooms"])

    def _create_destination_rooms(self, number_rooms: int) -> None:
        """Create a number rooms for destination

        Args:
            number_rooms: Number of rooms to be created
        """
        for _ in range(0, number_rooms):
            room_id = self.helper.create_room_as(
                self.admin_user, tok=self.admin_user_tok
            )
            self.get_success(
                self.store.store_destination_rooms_entries((self.dest,), room_id, 1234)
            )

    def _check_fields(self, content: List[JsonDict]) -> None:
        """Checks that the expected room attributes are present in content

        Args:
            content: List that is checked for content
        """
        for c in content:
            self.assertIn("room_id", c)
            self.assertIn("stream_ordering", c)
