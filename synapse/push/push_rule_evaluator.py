# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
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

import logging
import re
from typing import Any, Dict, List, Pattern, Union

from synapse.events import EventBase
from synapse.types import UserID
from synapse.util.caches import register_cache
from synapse.util.caches.lrucache import LruCache

logger = logging.getLogger(__name__)


GLOB_REGEX = re.compile(r"\\\[(\\\!|)(.*)\\\]")
IS_GLOB = re.compile(r"[\?\*\[\]]")
INEQUALITY_EXPR = re.compile("^([=<>]*)([0-9]*)$")


def _room_member_count(ev, condition, room_member_count):
    return _test_ineq_condition(condition, room_member_count)


def _sender_notification_permission(ev, condition, sender_power_level, power_levels):
    notif_level_key = condition.get("key")
    if notif_level_key is None:
        return False

    notif_levels = power_levels.get("notifications", {})
    room_notif_level = notif_levels.get(notif_level_key, 50)

    return sender_power_level >= room_notif_level


def _test_ineq_condition(condition, number):
    if "is" not in condition:
        return False
    m = INEQUALITY_EXPR.match(condition["is"])
    if not m:
        return False
    ineq = m.group(1)
    rhs = m.group(2)
    if not rhs.isdigit():
        return False
    rhs_int = int(rhs)

    if ineq == "" or ineq == "==":
        return number == rhs_int
    elif ineq == "<":
        return number < rhs_int
    elif ineq == ">":
        return number > rhs_int
    elif ineq == ">=":
        return number >= rhs_int
    elif ineq == "<=":
        return number <= rhs_int
    else:
        return False


def tweaks_for_actions(actions: List[Union[str, Dict]]) -> Dict[str, Any]:
    """
    Converts a list of actions into a `tweaks` dict (which can then be passed to
        the push gateway).

    This function ignores all actions other than `set_tweak` actions, and treats
    absent `value`s as `True`, which agrees with the only spec-defined treatment
    of absent `value`s (namely, for `highlight` tweaks).

    Args:
        actions: list of actions
            e.g. [
                {"set_tweak": "a", "value": "AAA"},
                {"set_tweak": "b", "value": "BBB"},
                {"set_tweak": "highlight"},
                "notify"
            ]

    Returns:
        dictionary of tweaks for those actions
            e.g. {"a": "AAA", "b": "BBB", "highlight": True}
    """
    tweaks = {}
    for a in actions:
        if not isinstance(a, dict):
            continue
        if "set_tweak" in a:
            # value is allowed to be absent in which case the value assumed
            # should be True.
            tweaks[a["set_tweak"]] = a.get("value", True)
    return tweaks


class PushRuleEvaluatorForEvent:
    def __init__(
        self,
        event: EventBase,
        room_member_count: int,
        sender_power_level: int,
        power_levels: dict,
    ):
        self._event = event
        self._room_member_count = room_member_count
        self._sender_power_level = sender_power_level
        self._power_levels = power_levels

        # Maps strings of e.g. 'content.body' -> event["content"]["body"]
        self._value_cache = _flatten_dict(event)

    def matches(self, condition: dict, user_id: str, display_name: str) -> bool:
        if condition["kind"] == "event_match":
            return self._event_match(condition, user_id)
        elif condition["kind"] == "contains_display_name":
            return self._contains_display_name(display_name)
        elif condition["kind"] == "room_member_count":
            return _room_member_count(self._event, condition, self._room_member_count)
        elif condition["kind"] == "sender_notification_permission":
            return _sender_notification_permission(
                self._event, condition, self._sender_power_level, self._power_levels
            )
        else:
            return True

    def _event_match(self, condition: dict, user_id: str) -> bool:
        pattern = condition.get("pattern", None)

        if not pattern:
            pattern_type = condition.get("pattern_type", None)
            if pattern_type == "user_id":
                pattern = user_id
            elif pattern_type == "user_localpart":
                pattern = UserID.from_string(user_id).localpart

        if not pattern:
            logger.warning("event_match condition with no pattern")
            return False

        # XXX: optimisation: cache our pattern regexps
        if condition["key"] == "content.body":
            body = self._event.content.get("body", None)
            if not body or not isinstance(body, str):
                return False

            return _glob_matches(pattern, body, word_boundary=True)
        else:
            haystack = self._get_value(condition["key"])
            if haystack is None:
                return False

            return _glob_matches(pattern, haystack)

    def _contains_display_name(self, display_name: str) -> bool:
        if not display_name:
            return False

        body = self._event.content.get("body", None)
        if not body or not isinstance(body, str):
            return False

        # Similar to _glob_matches, but do not treat display_name as a glob.
        r = regex_cache.get((display_name, False, True), None)
        if not r:
            r = re.escape(display_name)
            r = _re_word_boundary(r)
            r = re.compile(r, flags=re.IGNORECASE)
            regex_cache[(display_name, False, True)] = r

        return r.search(body)

    def _get_value(self, dotted_key: str) -> str:
        return self._value_cache.get(dotted_key, None)


# Caches (string, is_glob, word_boundary) -> regex for push. See _glob_matches
regex_cache = LruCache(50000)
register_cache("cache", "regex_push_cache", regex_cache)


def _glob_matches(glob: str, value: str, word_boundary: bool = False) -> bool:
    """Tests if value matches glob.

    Args:
        glob
        value: String to test against glob.
        word_boundary: Whether to match against word boundaries or entire
            string. Defaults to False.
    """

    try:
        r = regex_cache.get((glob, True, word_boundary), None)
        if not r:
            r = _glob_to_re(glob, word_boundary)
            regex_cache[(glob, True, word_boundary)] = r
        return r.search(value)
    except re.error:
        logger.warning("Failed to parse glob to regex: %r", glob)
        return False


def _glob_to_re(glob: str, word_boundary: bool) -> Pattern:
    """Generates regex for a given glob.

    Args:
        glob
        word_boundary: Whether to match against word boundaries or entire string.
    """
    if IS_GLOB.search(glob):
        r = re.escape(glob)

        r = r.replace(r"\*", ".*?")
        r = r.replace(r"\?", ".")

        # handle [abc], [a-z] and [!a-z] style ranges.
        r = GLOB_REGEX.sub(
            lambda x: (
                "[%s%s]" % (x.group(1) and "^" or "", x.group(2).replace(r"\\\-", "-"))
            ),
            r,
        )
        if word_boundary:
            r = _re_word_boundary(r)

            return re.compile(r, flags=re.IGNORECASE)
        else:
            r = "^" + r + "$"

            return re.compile(r, flags=re.IGNORECASE)
    elif word_boundary:
        r = re.escape(glob)
        r = _re_word_boundary(r)

        return re.compile(r, flags=re.IGNORECASE)
    else:
        r = "^" + re.escape(glob) + "$"
        return re.compile(r, flags=re.IGNORECASE)


def _re_word_boundary(r: str) -> str:
    """
    Adds word boundary characters to the start and end of an
    expression to require that the match occur as a whole word,
    but do so respecting the fact that strings starting or ending
    with non-word characters will change word boundaries.
    """
    # we can't use \b as it chokes on unicode. however \W seems to be okay
    # as shorthand for [^0-9A-Za-z_].
    return r"(^|\W)%s(\W|$)" % (r,)


def _flatten_dict(d, prefix=[], result=None):
    if result is None:
        result = {}
    for key, value in d.items():
        if isinstance(value, str):
            result[".".join(prefix + [key])] = value.lower()
        elif hasattr(value, "items"):
            _flatten_dict(value, prefix=(prefix + [key]), result=result)

    return result
