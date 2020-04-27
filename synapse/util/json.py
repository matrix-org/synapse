# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

# Shorthand to use simplejson if it is available.
from canonicaljson import json


def _safe_int(s: str) -> int:
    """
    Parse an integer from a string, but reject integers outside the valid JSON range.

    THe range of valid integers for JSON is defined as [-2 ^ 53 + 1, 2 ^ 53 -1],
    per RFC 7159.
    """
    res = int(s)
    if -2 ** 53 < res < 2 ** 53:
        return res
    raise ValueError("Invalid int literal: %s" % s)


_decoder = json.JSONDecoder(parse_int=_safe_int)


def safe_loads(content_bytes):
    """
    Load a JSON document while abiding by the RFC limitations.

    This should be used for any external JSON parsed by Synapse.
    """
    return _decoder.decode(content_bytes)
