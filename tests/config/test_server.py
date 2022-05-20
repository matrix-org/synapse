# Copyright 2019 New Vector Ltd
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

import yaml

from synapse.config._base import ConfigError
from synapse.config.server import ServerConfig, generate_ip_set, is_threepid_reserved

from tests import unittest


class ServerConfigTestCase(unittest.TestCase):
    def test_is_threepid_reserved(self):
        user1 = {"medium": "email", "address": "user1@example.com"}
        user2 = {"medium": "email", "address": "user2@example.com"}
        user3 = {"medium": "email", "address": "user3@example.com"}
        user1_msisdn = {"medium": "msisdn", "address": "447700000000"}
        config = [user1, user2]

        self.assertTrue(is_threepid_reserved(config, user1))
        self.assertFalse(is_threepid_reserved(config, user3))
        self.assertFalse(is_threepid_reserved(config, user1_msisdn))

    def test_unsecure_listener_no_listeners_open_private_ports_false(self):
        conf = yaml.safe_load(
            ServerConfig().generate_config_section(
                "CONFDIR", "/data_dir_path", "che.org", False, None
            )
        )

        expected_listeners = [
            {
                "port": 8008,
                "tls": False,
                "type": "http",
                "x_forwarded": True,
                "bind_addresses": ["::1", "127.0.0.1"],
                "resources": [{"names": ["client", "federation"], "compress": False}],
            }
        ]

        self.assertEqual(conf["listeners"], expected_listeners)

    def test_unsecure_listener_no_listeners_open_private_ports_true(self):
        conf = yaml.safe_load(
            ServerConfig().generate_config_section(
                "CONFDIR", "/data_dir_path", "che.org", True, None
            )
        )

        expected_listeners = [
            {
                "port": 8008,
                "tls": False,
                "type": "http",
                "x_forwarded": True,
                "resources": [{"names": ["client", "federation"], "compress": False}],
            }
        ]

        self.assertEqual(conf["listeners"], expected_listeners)

    def test_listeners_set_correctly_open_private_ports_false(self):
        listeners = [
            {
                "port": 8448,
                "resources": [{"names": ["federation"]}],
                "tls": True,
                "type": "http",
            },
            {
                "port": 443,
                "resources": [{"names": ["client"]}],
                "tls": False,
                "type": "http",
            },
        ]

        conf = yaml.safe_load(
            ServerConfig().generate_config_section(
                "CONFDIR", "/data_dir_path", "this.one.listens", True, listeners
            )
        )

        self.assertEqual(conf["listeners"], listeners)

    def test_listeners_set_correctly_open_private_ports_true(self):
        listeners = [
            {
                "port": 8448,
                "resources": [{"names": ["federation"]}],
                "tls": True,
                "type": "http",
            },
            {
                "port": 443,
                "resources": [{"names": ["client"]}],
                "tls": False,
                "type": "http",
            },
            {
                "port": 1243,
                "resources": [{"names": ["client"]}],
                "tls": False,
                "type": "http",
                "bind_addresses": ["this_one_is_bound"],
            },
        ]

        expected_listeners = listeners.copy()
        expected_listeners[1]["bind_addresses"] = ["::1", "127.0.0.1"]

        conf = yaml.safe_load(
            ServerConfig().generate_config_section(
                "CONFDIR", "/data_dir_path", "this.one.listens", True, listeners
            )
        )

        self.assertEqual(conf["listeners"], expected_listeners)


class GenerateIpSetTestCase(unittest.TestCase):
    def test_empty(self):
        ip_set = generate_ip_set(())
        self.assertFalse(ip_set)

        ip_set = generate_ip_set((), ())
        self.assertFalse(ip_set)

    def test_generate(self):
        """Check adding IPv4 and IPv6 addresses."""
        # IPv4 address
        ip_set = generate_ip_set(("1.2.3.4",))
        self.assertEqual(len(ip_set.iter_cidrs()), 4)

        # IPv4 CIDR
        ip_set = generate_ip_set(("1.2.3.4/24",))
        self.assertEqual(len(ip_set.iter_cidrs()), 4)

        # IPv6 address
        ip_set = generate_ip_set(("2001:db8::8a2e:370:7334",))
        self.assertEqual(len(ip_set.iter_cidrs()), 1)

        # IPv6 CIDR
        ip_set = generate_ip_set(("2001:db8::/104",))
        self.assertEqual(len(ip_set.iter_cidrs()), 1)

        # The addresses can overlap OK.
        ip_set = generate_ip_set(("1.2.3.4", "::1.2.3.4"))
        self.assertEqual(len(ip_set.iter_cidrs()), 4)

    def test_extra(self):
        """Extra IP addresses are treated the same."""
        ip_set = generate_ip_set((), ("1.2.3.4",))
        self.assertEqual(len(ip_set.iter_cidrs()), 4)

        ip_set = generate_ip_set(("1.1.1.1",), ("1.2.3.4",))
        self.assertEqual(len(ip_set.iter_cidrs()), 8)

        # They can duplicate without error.
        ip_set = generate_ip_set(("1.2.3.4",), ("1.2.3.4",))
        self.assertEqual(len(ip_set.iter_cidrs()), 4)

    def test_bad_value(self):
        """An error should be raised if a bad value is passed in."""
        with self.assertRaises(ConfigError):
            generate_ip_set(("not-an-ip",))

        with self.assertRaises(ConfigError):
            generate_ip_set(("1.2.3.4/128",))

        with self.assertRaises(ConfigError):
            generate_ip_set((":::",))

        # The following get treated as empty data.
        self.assertFalse(generate_ip_set(None))
        self.assertFalse(generate_ip_set({}))
