#  Copyright 2020 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import json
import logging
import typing

# Guard against an import loop from synapse.types -> synapse.api.errors -> here.
if typing.TYPE_CHECKING:
    from synapse.types import JsonDict

logger = logging.getLogger(__name__)


def load_bytes(s: bytes) -> "JsonDict":
    """
    Deserialize a bytes containing a JSON document to a Python object.

    This is a compatibility shim since Python 3.5 does NOT support deserializing
    bytes.

    Note that this does not do error handling.

    Raises:
        UnicodeDecodeError if the bytes cannot be converted to UTF-8.
        JSONDecodeError if the data is not a valid JSON document.
    """
    # Decode to Unicode since json on Python 3.5 requires str, not bytes.
    s_str = s.decode("utf8")
    return json.loads(s_str)
