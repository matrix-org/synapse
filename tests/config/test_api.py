from unittest import TestCase as StdlibTestCase

import yaml

from synapse.config import ConfigError
from synapse.config.api import ApiConfig, StateKeyFilter

DEFAULT_PREJOIN_STATE = {
    "m.room.join_rules": StateKeyFilter.only(""),
    "m.room.canonical_alias": StateKeyFilter.only(""),
    "m.room.avatar": StateKeyFilter.only(""),
    "m.room.encryption": StateKeyFilter.only(""),
    "m.room.name": StateKeyFilter.only(""),
    "m.room.create": StateKeyFilter.only(""),
    "m.room.topic": StateKeyFilter.only(""),
}


class TestRoomPrejoinState(StdlibTestCase):
    def test_state_key_filter(self) -> None:
        """Sanity check the StateKeyFilter class."""
        s = StateKeyFilter.only("foo")
        self.assertIn("foo", s)
        self.assertNotIn("bar", s)
        self.assertNotIn("baz", s)
        s.add("bar")
        self.assertIn("foo", s)
        self.assertIn("bar", s)
        self.assertNotIn("baz", s)

        s = StateKeyFilter.any()
        self.assertIn("foo", s)
        self.assertIn("bar", s)
        self.assertIn("baz", s)
        s.add("bar")
        self.assertIn("foo", s)
        self.assertIn("bar", s)
        self.assertIn("baz", s)

    def read_config(self, source: str) -> ApiConfig:
        config = ApiConfig()
        config.read_config(yaml.safe_load(source))
        return config

    def test_no_prejoin_state(self) -> None:
        config = self.read_config("foo: bar")
        self.assertEqual(config.room_prejoin_state, DEFAULT_PREJOIN_STATE)

    def test_disable_default_event_types(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
        """
        )
        self.assertEqual(config.room_prejoin_state, {})

    def test_event_without_state_key(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - foo
        """
        )
        self.assertEqual(config.room_prejoin_state, {"foo": StateKeyFilter.any()})

    def test_event_with_specific_state_key(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - [foo, bar]
        """
        )
        self.assertEqual(config.room_prejoin_state, {"foo": StateKeyFilter.only("bar")})

    def test_repeated_event_with_specific_state_key(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - [foo, bar]
        - [foo, baz]
        """
        )
        self.assertEqual(
            config.room_prejoin_state, {"foo": StateKeyFilter({"bar", "baz"})}
        )

    def test_no_specific_state_key_overrides_specific_state_key(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - [foo, bar]
        - foo
        """
        )
        self.assertEqual(config.room_prejoin_state, {"foo": StateKeyFilter.any()})

        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - foo
        - [foo, bar]
        """
        )
        self.assertEqual(config.room_prejoin_state, {"foo": StateKeyFilter.any()})

    def test_bad_event_type_entry_raises(self) -> None:
        with self.assertRaises(ConfigError):
            self.read_config(
                """
room_prejoin_state:
    additional_event_types:
        - []
            """
            )

        with self.assertRaises(ConfigError):
            self.read_config(
                """
room_prejoin_state:
    additional_event_types:
        - [a]
            """
            )

        with self.assertRaises(ConfigError):
            self.read_config(
                """
room_prejoin_state:
    additional_event_types:
        - [a, b, c]
            """
            )

        with self.assertRaises(ConfigError):
            self.read_config(
                """
room_prejoin_state:
    additional_event_types:
        - [true, 1.23]
            """
            )
