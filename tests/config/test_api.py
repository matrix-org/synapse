from unittest import TestCase as StdlibTestCase

import yaml

from synapse.config import ConfigError
from synapse.config.api import ApiConfig
from synapse.types.state import StateFilter

DEFAULT_PREJOIN_STATE_PAIRS = {
    ("m.room.join_rules", ""),
    ("m.room.canonical_alias", ""),
    ("m.room.avatar", ""),
    ("m.room.encryption", ""),
    ("m.room.name", ""),
    ("m.room.create", ""),
    ("m.room.topic", ""),
}


class TestRoomPrejoinState(StdlibTestCase):
    def read_config(self, source: str) -> ApiConfig:
        config = ApiConfig()
        config.read_config(yaml.safe_load(source))
        return config

    def test_no_prejoin_state(self) -> None:
        config = self.read_config("foo: bar")
        self.assertFalse(config.room_prejoin_state.has_wildcards())
        self.assertEqual(
            set(config.room_prejoin_state.concrete_types()), DEFAULT_PREJOIN_STATE_PAIRS
        )

    def test_disable_default_event_types(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
        """
        )
        self.assertEqual(config.room_prejoin_state, StateFilter.none())

    def test_event_without_state_key(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - foo
        """
        )
        self.assertEqual(config.room_prejoin_state.wildcard_types(), ["foo"])
        self.assertEqual(config.room_prejoin_state.concrete_types(), [])

    def test_event_with_specific_state_key(self) -> None:
        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - [foo, bar]
        """
        )
        self.assertFalse(config.room_prejoin_state.has_wildcards())
        self.assertEqual(
            set(config.room_prejoin_state.concrete_types()),
            {("foo", "bar")},
        )

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
        self.assertFalse(config.room_prejoin_state.has_wildcards())
        self.assertEqual(
            set(config.room_prejoin_state.concrete_types()),
            {("foo", "bar"), ("foo", "baz")},
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
        self.assertEqual(config.room_prejoin_state.wildcard_types(), ["foo"])
        self.assertEqual(config.room_prejoin_state.concrete_types(), [])

        config = self.read_config(
            """
room_prejoin_state:
    disable_default_event_types: true
    additional_event_types:
        - foo
        - [foo, bar]
        """
        )
        self.assertEqual(config.room_prejoin_state.wildcard_types(), ["foo"])
        self.assertEqual(config.room_prejoin_state.concrete_types(), [])

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
