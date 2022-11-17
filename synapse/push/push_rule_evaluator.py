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
from typing import Any, Dict, List, Mapping, Optional, Pattern, Set, Tuple, Union

from matrix_common.regex import glob_to_regex, to_word_pattern

from synapse.events import EventBase
from synapse.types import UserID
from synapse.util.caches.lrucache import LruCache

logger = logging.getLogger(__name__)


GLOB_REGEX = re.compile(r"\\\[(\\\!|)(.*)\\\]")
IS_GLOB = re.compile(r"[\?\*\[\]]")
INEQUALITY_EXPR = re.compile("^([=<>]*)([0-9]*)$")


def _room_member_count(
    ev: EventBase, condition: Dict[str, Any], room_member_count: int
) -> bool:
    return _test_ineq_condition(condition, room_member_count)


def _sender_notification_permission(
    ev: EventBase,
    condition: Dict[str, Any],
    sender_power_level: int,
    power_levels: Dict[str, Union[int, Dict[str, int]]],
) -> bool:
    notif_level_key = condition.get("key")
    if notif_level_key is None:
        return False

    notif_levels = power_levels.get("notifications", {})
    assert isinstance(notif_levels, dict)
    room_notif_level = notif_levels.get(notif_level_key, 50)

    return sender_power_level >= room_notif_level


def _test_ineq_condition(condition: Dict[str, Any], number: int) -> bool:
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
        power_levels: Dict[str, Union[int, Dict[str, int]]],
        relations: Dict[str, Set[Tuple[str, str]]],
        relations_match_enabled: bool,
    ):
        self._event = event
        self._room_member_count = room_member_count
        self._sender_power_level = sender_power_level
        self._power_levels = power_levels
        self._relations = relations
        self._relations_match_enabled = relations_match_enabled

        # Maps strings of e.g. 'content.body' -> event["content"]["body"]
        self._value_cache = _flatten_dict(event)

        # Maps cache keys to final values.
        self._condition_cache: Dict[str, bool] = {}

    def check_conditions(
        self, conditions: List[dict], uid: str, display_name: Optional[str]
    ) -> bool:
        """
        Returns true if a user's conditions/user ID/display name match the event.

        Args:
            conditions: The user's conditions to match.
            uid: The user's MXID.
            display_name: The display name.

        Returns:
             True if all conditions match the event, False otherwise.
        """
        for cond in conditions:
            _cache_key = cond.get("_cache_key", None)
            if _cache_key:
                res = self._condition_cache.get(_cache_key, None)
                if res is False:
                    return False
                elif res is True:
                    continue

            res = self.matches(cond, uid, display_name)
            if _cache_key:
                self._condition_cache[_cache_key] = bool(res)

            if not res:
                return False

        return True

    def matches(
        self, condition: Dict[str, Any], user_id: str, display_name: Optional[str]
    ) -> bool:
        """
        Returns true if a user's condition/user ID/display name match the event.

        Args:
            condition: The user's condition to match.
            uid: The user's MXID.
            display_name: The display name, or None if there is not one.

        Returns:
             True if the condition matches the event, False otherwise.
        """
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
        elif (
            condition["kind"] == "org.matrix.msc3772.relation_match"
            and self._relations_match_enabled
        ):
            return self._relation_match(condition, user_id)
        else:
            # XXX This looks incorrect -- we have reached an unknown condition
            #     kind and are unconditionally returning that it matches. Note
            #     that it seems possible to provide a condition to the /pushrules
            #     endpoint with an unknown kind, see _rule_tuple_from_request_object.
            return True

    def _event_match(self, condition: dict, user_id: str) -> bool:
        """
        Check an "event_match" push rule condition.

        Args:
            condition: The "event_match" push rule condition to match.
            user_id: The user's MXID.

        Returns:
             True if the condition matches the event, False otherwise.
        """
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
            haystack = self._value_cache.get(condition["key"], None)
            if haystack is None:
                return False

            return _glob_matches(pattern, haystack)

    def _contains_display_name(self, display_name: Optional[str]) -> bool:
        """
        Check an "event_match" push rule condition.

        Args:
            display_name: The display name, or None if there is not one.

        Returns:
             True if the display name is found in the event body, False otherwise.
        """
        if not display_name:
            return False

        body = self._event.content.get("body", None)
        if not body or not isinstance(body, str):
            return False

        # Similar to _glob_matches, but do not treat display_name as a glob.
        r = regex_cache.get((display_name, False, True), None)
        if not r:
            r1 = re.escape(display_name)
            r1 = to_word_pattern(r1)
            r = re.compile(r1, flags=re.IGNORECASE)
            regex_cache[(display_name, False, True)] = r

        return bool(r.search(body))

    def _relation_match(self, condition: dict, user_id: str) -> bool:
        """
        Check an "relation_match" push rule condition.

        Args:
            condition: The "event_match" push rule condition to match.
            user_id: The user's MXID.

        Returns:
             True if the condition matches the event, False otherwise.
        """
        rel_type = condition.get("rel_type")
        if not rel_type:
            logger.warning("relation_match condition missing rel_type")
            return False

        sender_pattern = condition.get("sender")
        if sender_pattern is None:
            sender_type = condition.get("sender_type")
            if sender_type == "user_id":
                sender_pattern = user_id
        type_pattern = condition.get("type")

        # If any other relations matches, return True.
        for sender, event_type in self._relations.get(rel_type, ()):
            if sender_pattern and not _glob_matches(sender_pattern, sender):
                continue
            if type_pattern and not _glob_matches(type_pattern, event_type):
                continue
            # All values must have matched.
            return True

        # No relations matched.
        return False


# Caches (string, is_glob, word_boundary) -> regex for push. See _glob_matches
regex_cache: LruCache[Tuple[str, bool, bool], Pattern] = LruCache(
    50000, "regex_push_cache"
)


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
            r = glob_to_regex(glob, word_boundary=word_boundary)
            regex_cache[(glob, True, word_boundary)] = r
        return bool(r.search(value))
    except re.error:
        logger.warning("Failed to parse glob to regex: %r", glob)
        return False


def _flatten_dict(
    d: Union[EventBase, Mapping[str, Any]],
    prefix: Optional[List[str]] = None,
    result: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    if prefix is None:
        prefix = []
    if result is None:
        result = {}
    for key, value in d.items():
        if isinstance(value, str):
            result[".".join(prefix + [key])] = value.lower()
        elif isinstance(value, Mapping):
            _flatten_dict(value, prefix=(prefix + [key]), result=result)

    return result
