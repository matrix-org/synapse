# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

import re

from synapse.api.urls import CLIENT_PREFIX


def v1_only_client_path_patterns(path_regex, include_in_unstable=True):
    """Creates a regex compiled client path with the correct client path
    prefix.

    Args:
        path_regex (str): The regex string to match. This should NOT have a ^
        as this will be prefixed.
    Returns:
        list of SRE_Pattern
    """
    patterns = [re.compile("^" + CLIENT_PREFIX + path_regex)]
    if include_in_unstable:
        unstable_prefix = CLIENT_PREFIX.replace("/api/v1", "/unstable")
        patterns.append(re.compile("^" + unstable_prefix + path_regex))
    return patterns
