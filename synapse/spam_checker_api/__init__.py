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
from typing import NewType, Union

from synapse.api.errors import Codes


class RegistrationBehaviour(Enum):
    """
    Enum to define whether a registration request should be allowed, denied, or shadow-banned.
    """

    ALLOW = "allow"
    SHADOW_BAN = "shadow_ban"
    DENY = "deny"


# Define a strongly-typed singleton value `ALLOW`.

# Private NewType, to make sure that nobody outside this module
# defines an instance of `Allow`.
_Allow = NewType("_Allow", str)

# Public NewType, to let the rest of the code mention type `Allow`.
Allow = NewType("Allow", _Allow)

ALLOW = Allow(_Allow("Allow"))
"""
Return this constant to allow a message to pass.

This is the ONLY legal value of type `Allow`.
"""

Decision = Union[Allow, Codes]
"""
Union to define whether a request should be allowed or rejected.

To accept a request, return `ALLOW`.

To reject a request without any specific information, use `Codes.FORBIDDEN`.
"""
