# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

"""This module contains base REST classes for constructing client v1 servlets.
"""

from synapse.api.urls import CLIENT_V2_ALPHA_PREFIX
from synapse.api.errors import SynapseError
import re

import logging
import simplejson


logger = logging.getLogger(__name__)


def client_v2_patterns(path_regex, releases=(0,)):
    """Creates a regex compiled client path with the correct client path
    prefix.

    Args:
        path_regex (str): The regex string to match. This should NOT have a ^
        as this will be prefixed.
    Returns:
        SRE_Pattern
    """
    patterns = [re.compile("^" + CLIENT_V2_ALPHA_PREFIX + path_regex)]
    unstable_prefix = CLIENT_V2_ALPHA_PREFIX.replace("/v2_alpha", "/unstable")
    patterns.append(re.compile("^" + unstable_prefix + path_regex))
    for release in releases:
        new_prefix = CLIENT_V2_ALPHA_PREFIX.replace("/v2_alpha", "/r%d" % release)
        patterns.append(re.compile("^" + new_prefix + path_regex))
    return patterns


def parse_request_allow_empty(request):
    content = request.content.read()
    if content is None or content == '':
        return None
    try:
        return simplejson.loads(content)
    except simplejson.JSONDecodeError:
        raise SynapseError(400, "Content not JSON.")


def parse_json_dict_from_request(request):
    try:
        content = simplejson.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.")
        return content
    except simplejson.JSONDecodeError:
        raise SynapseError(400, "Content not JSON.")
