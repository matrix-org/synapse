# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
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
import logging
from typing import Any, Union

from synapse.storage.database import LoggingTransaction  # noqa: F401
from synapse.storage.database import make_in_list_sql_clause  # noqa: F401
from synapse.util import json_decoder

logger = logging.getLogger(__name__)


def db_to_json(db_content: Union[memoryview, bytes, bytearray, str]) -> Any:
    """
    Take some data from a database row and return a JSON-decoded object.

    Args:
        db_content: The JSON-encoded contents from the database.

    Returns:
        The object decoded from JSON.
    """
    # psycopg2 on Python 3 returns memoryview objects, which we need to
    # cast to bytes to decode
    if isinstance(db_content, memoryview):
        db_content = db_content.tobytes()

    # Decode it to a Unicode string before feeding it to the JSON decoder, since
    # Python 3.5 does not support deserializing bytes.
    if isinstance(db_content, (bytes, bytearray)):
        db_content = db_content.decode("utf8")

    try:
        return json_decoder.decode(db_content)
    except Exception:
        logger.warning("Tried to decode '%r' as JSON and failed", db_content)
        raise
