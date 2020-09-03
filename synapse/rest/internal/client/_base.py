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

"""This module contains base REST classes for constructing client v1 servlets.
"""
import logging
import re
from typing import Iterable, Pattern

from synapse.api.urls import SYNAPSE_CLIENT_API_PREFIX

logger = logging.getLogger(__name__)


def synapse_client_patterns(path_regex: str) -> Iterable[Pattern]:
    """Creates a regex compiled client path with the correct synapse client
    path prefix.

    Args:
        path_regex: The regex string to match. This should NOT have a ^
            as this will be prefixed.
    Returns:
        An iterable of patterns.
    """
    return [re.compile("^" + SYNAPSE_CLIENT_API_PREFIX + path_regex)]
