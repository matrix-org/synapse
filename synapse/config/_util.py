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
from functools import lru_cache
from typing import Any, Iterable

import jsonschema
from matrix_common.regex import glob_to_regex

from synapse.config._base import ConfigError
from synapse.types import JsonDict


def validate_config(
    json_schema: JsonDict, config: Any, config_path: Iterable[str]
) -> None:
    """Validates a config setting against a JsonSchema definition

    This can be used to validate a section of the config file against a schema
    definition. If the validation fails, a ConfigError is raised with a textual
    description of the problem.

    Args:
        json_schema: the schema to validate against
        config: the configuration value to be validated
        config_path: the path within the config file. This will be used as a basis
           for the error message.
    """
    try:
        jsonschema.validate(config, json_schema)
    except jsonschema.ValidationError as e:
        raise json_error_to_config_error(e, config_path)


def json_error_to_config_error(
    e: jsonschema.ValidationError, config_path: Iterable[str]
) -> ConfigError:
    """Converts a json validation error to a user-readable ConfigError

    Args:
        e: the exception to be converted
        config_path: the path within the config file. This will be used as a basis
           for the error message.

    Returns:
        a ConfigError
    """
    # copy `config_path` before modifying it.
    path = list(config_path)
    for p in list(e.absolute_path):
        if isinstance(p, int):
            path.append("<item %i>" % p)
        else:
            path.append(str(p))
    return ConfigError(e.message, path)


class DomainGlobSet:
    def __init__(self, globs: list):
        self._globs = []
        for entry in globs:
            try:
                self._globs.append(glob_to_regex(entry.encode("ascii").decode("ascii")))
            except UnicodeEncodeError:
                raise ConfigError("IDNA domain names are not allowed: %s " % (entry,))

    @lru_cache(maxsize=100000)
    def __contains__(self, item: object) -> bool:
        for regex in self._globs:
            if regex.match(str(item)):
                return True
        return False
