# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.types import UserID
from synapse.util.caches.lrucache import LruCache

logger = logging.getLogger(__name__)


GLOB_REGEX = re.compile(r'\\\[(\\\!|)(.*)\\\]')
IS_GLOB = re.compile(r'[\?\*\[\]]')
INEQUALITY_EXPR = re.compile("^([=<>]*)([0-9]*)$")


def _room_member_count(ev, condition, room_member_count):
    if 'is' not in condition:
        return False
    m = INEQUALITY_EXPR.match(condition['is'])
    if not m:
        return False
    ineq = m.group(1)
    rhs = m.group(2)
    if not rhs.isdigit():
        return False
    rhs = int(rhs)

    if ineq == '' or ineq == '==':
        return room_member_count == rhs
    elif ineq == '<':
        return room_member_count < rhs
    elif ineq == '>':
        return room_member_count > rhs
    elif ineq == '>=':
        return room_member_count >= rhs
    elif ineq == '<=':
        return room_member_count <= rhs
    else:
        return False


def tweaks_for_actions(actions):
    tweaks = {}
    for a in actions:
        if not isinstance(a, dict):
            continue
        if 'set_tweak' in a and 'value' in a:
            tweaks[a['set_tweak']] = a['value']
    return tweaks


class PushRuleEvaluatorForEvent(object):
    def __init__(self, event, room_member_count):
        self._event = event
        self._room_member_count = room_member_count

        # Maps strings of e.g. 'content.body' -> event["content"]["body"]
        self._value_cache = _flatten_dict(event)

    def matches(self, condition, user_id, display_name):
        if condition['kind'] == 'event_match':
            return self._event_match(condition, user_id)
        elif condition['kind'] == 'contains_display_name':
            return self._contains_display_name(display_name)
        elif condition['kind'] == 'room_member_count':
            return _room_member_count(
                self._event, condition, self._room_member_count
            )
        else:
            return True

    def _event_match(self, condition, user_id):
        pattern = condition.get('pattern', None)

        if not pattern:
            pattern_type = condition.get('pattern_type', None)
            if pattern_type == "user_id":
                pattern = user_id
            elif pattern_type == "user_localpart":
                pattern = UserID.from_string(user_id).localpart

        if not pattern:
            logger.warn("event_match condition with no pattern")
            return False

        # XXX: optimisation: cache our pattern regexps
        if condition['key'] == 'content.body':
            body = self._event["content"].get("body", None)
            if not body:
                return False

            return _glob_matches(pattern, body, word_boundary=True)
        else:
            haystack = self._get_value(condition['key'])
            if haystack is None:
                return False

            return _glob_matches(pattern, haystack)

    def _contains_display_name(self, display_name):
        if not display_name:
            return False

        body = self._event["content"].get("body", None)
        if not body:
            return False

        return _glob_matches(display_name, body, word_boundary=True)

    def _get_value(self, dotted_key):
        return self._value_cache.get(dotted_key, None)


def _glob_matches(glob, value, word_boundary=False):
    """Tests if value matches glob.

    Args:
        glob (string)
        value (string): String to test against glob.
        word_boundary (bool): Whether to match against word boundaries or entire
            string. Defaults to False.

    Returns:
        bool
    """
    try:
        if IS_GLOB.search(glob):
            r = re.escape(glob)

            r = r.replace(r'\*', '.*?')
            r = r.replace(r'\?', '.')

            # handle [abc], [a-z] and [!a-z] style ranges.
            r = GLOB_REGEX.sub(
                lambda x: (
                    '[%s%s]' % (
                        x.group(1) and '^' or '',
                        x.group(2).replace(r'\\\-', '-')
                    )
                ),
                r,
            )
            if word_boundary:
                r = r"\b%s\b" % (r,)
                r = _compile_regex(r)

                return r.search(value)
            else:
                r = r + "$"
                r = _compile_regex(r)

                return r.match(value)
        elif word_boundary:
            r = re.escape(glob)
            r = r"\b%s\b" % (r,)
            r = _compile_regex(r)

            return r.search(value)
        else:
            return value.lower() == glob.lower()
    except re.error:
        logger.warn("Failed to parse glob to regex: %r", glob)
        return False


def _flatten_dict(d, prefix=[], result={}):
    for key, value in d.items():
        if isinstance(value, basestring):
            result[".".join(prefix + [key])] = value.lower()
        elif hasattr(value, "items"):
            _flatten_dict(value, prefix=(prefix + [key]), result=result)

    return result


regex_cache = LruCache(5000)


def _compile_regex(regex_str):
    r = regex_cache.get(regex_str, None)
    if r:
        return r

    r = re.compile(regex_str, flags=re.IGNORECASE)
    regex_cache[regex_str] = r
    return r
