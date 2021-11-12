# Copyright 2021 The Matrix.org Foundation C.I.C.
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


class StrEnum(str, Enum):
    """Enum where members are also (and must be) strings

    Similar to `IntEnum` except for strings.
    Comparison and JSON serialization work as expected.
    Interchangeable with regular strings when used as dictionary keys.
    """

    __str__ = str.__str__
    __format__ = str.__format__
