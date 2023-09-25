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
from typing import TYPE_CHECKING, Any, Dict, Type, TypeVar

import jsonschema

from synapse._pydantic_compat import HAS_PYDANTIC_V2

if TYPE_CHECKING or HAS_PYDANTIC_V2:
    from pydantic.v1 import BaseModel, ValidationError, parse_obj_as
else:
    from pydantic import BaseModel, ValidationError, parse_obj_as

from synapse.config._base import ConfigError
from synapse.types import JsonDict, StrSequence


def validate_config(
    json_schema: JsonDict, config: Any, config_path: StrSequence
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

    Raises:
        ConfigError, if validation fails.
    """
    try:
        jsonschema.validate(config, json_schema)
    except jsonschema.ValidationError as e:
        raise json_error_to_config_error(e, config_path)


def json_error_to_config_error(
    e: jsonschema.ValidationError, config_path: StrSequence
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


Model = TypeVar("Model", bound=BaseModel)


def parse_and_validate_mapping(
    config: Any,
    model_type: Type[Model],
) -> Dict[str, Model]:
    """Parse `config` as a mapping from strings to a given `Model` type.
    Args:
        config: The configuration data to check
        model_type: The BaseModel to validate and parse against.
    Returns:
        Fully validated and parsed Dict[str, Model].
    Raises:
        ConfigError, if given improper input.
    """
    try:
        # type-ignore: mypy doesn't like constructing `Dict[str, model_type]` because
        # `model_type` is a runtime variable. Pydantic is fine with this.
        instances = parse_obj_as(Dict[str, model_type], config)  # type: ignore[valid-type]
    except ValidationError as e:
        raise ConfigError(str(e)) from e
    return instances
