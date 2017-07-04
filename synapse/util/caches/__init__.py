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

import synapse.metrics
import os

CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.5))

metrics = synapse.metrics.get_metrics_for("synapse.util.caches")

caches_by_name = {}
# cache_counter = metrics.register_cache(
#     "cache",
#     lambda: {(name,): len(caches_by_name[name]) for name in caches_by_name.keys()},
#     labels=["name"],
# )


def register_cache(name, cache):
    caches_by_name[name] = cache
    return metrics.register_cache(
        "cache",
        lambda: len(cache),
        name,
    )


KNOWN_KEYS = {
    key: key for key in
    (
        "auth_events",
        "content",
        "depth",
        "event_id",
        "hashes",
        "origin",
        "origin_server_ts",
        "prev_events",
        "room_id",
        "sender",
        "signatures",
        "state_key",
        "type",
        "unsigned",
        "user_id",
    )
}


def intern_string(string):
    """Takes a (potentially) unicode string and interns it if it's ascii
    """
    if string is None:
        return None

    try:
        string = string.encode("ascii")
        return intern(string)
    except UnicodeEncodeError:
        return string


def intern_dict(dictionary):
    """Takes a dictionary and interns well known keys and their values
    """
    return {
        KNOWN_KEYS.get(key, key): _intern_known_values(key, value)
        for key, value in dictionary.items()
    }


def _intern_known_values(key, value):
    intern_keys = ("event_id", "room_id", "sender", "user_id", "type", "state_key",)

    if key in intern_keys:
        return intern_string(value)

    return value
