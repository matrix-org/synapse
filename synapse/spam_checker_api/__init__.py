# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from enum import Enum
from typing import Union

from synapse.api.errors import Codes


class RegistrationBehaviour(Enum):
    """
    Enum to define whether a registration request should be allowed, denied, or shadow-banned.
    """

    ALLOW = "allow"
    SHADOW_BAN = "shadow_ban"
    DENY = "deny"


# We define the following singleton enum rather than a string to be able to
# write `Union[Allow, ..., str]` in some of the callbacks for the spam-checker
# API, where the `str` is required to maintain backwards compatibility with
# previous versions of the API.
class Allow(Enum):
    """
    Singleton to allow events to pass through in SpamChecker APIs.
    """

    ALLOW = "allow"


Decision = Union[Allow, Codes]
"""
Union to define whether a request should be allowed or rejected.

To accept a request, return `ALLOW`.

To reject a request without any specific information, use `Codes.FORBIDDEN`.
"""
