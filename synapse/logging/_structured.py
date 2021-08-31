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
import os.path
from typing import Any, Dict, Generator, Optional, Tuple

from constantly import NamedConstant, Names

from synapse.config._base import ConfigError


class DrainType(Names):
    CONSOLE = NamedConstant()
    CONSOLE_JSON = NamedConstant()
    CONSOLE_JSON_TERSE = NamedConstant()
    FILE = NamedConstant()
    FILE_JSON = NamedConstant()
    NETWORK_JSON_TERSE = NamedConstant()


DEFAULT_LOGGERS = {"synapse": {"level": "info"}}


def parse_drain_configs(
    drains: dict,
) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
    """
    Parse the drain configurations.

    Args:
        drains (dict): A list of drain configurations.

    Yields:
        dict instances representing a logging handler.

    Raises:
        ConfigError: If any of the drain configuration items are invalid.
    """

    for name, config in drains.items():
        if "type" not in config:
            raise ConfigError("Logging drains require a 'type' key.")

        try:
            logging_type = DrainType.lookupByName(config["type"].upper())
        except ValueError:
            raise ConfigError(
                "%s is not a known logging drain type." % (config["type"],)
            )

        # Either use the default formatter or the tersejson one.
        if logging_type in (
            DrainType.CONSOLE_JSON,
            DrainType.FILE_JSON,
        ):
            formatter = "json"  # type: Optional[str]
        elif logging_type in (
            DrainType.CONSOLE_JSON_TERSE,
            DrainType.NETWORK_JSON_TERSE,
        ):
            formatter = "tersejson"
        else:
            # A formatter of None implies using the default formatter.
            formatter = None

        if logging_type in [
            DrainType.CONSOLE,
            DrainType.CONSOLE_JSON,
            DrainType.CONSOLE_JSON_TERSE,
        ]:
            location = config.get("location")
            if location is None or location not in ["stdout", "stderr"]:
                raise ConfigError(
                    (
                        "The %s drain needs the 'location' key set to "
                        "either 'stdout' or 'stderr'."
                    )
                    % (logging_type,)
                )

            yield name, {
                "class": "logging.StreamHandler",
                "formatter": formatter,
                "stream": "ext://sys." + location,
            }

        elif logging_type in [DrainType.FILE, DrainType.FILE_JSON]:
            if "location" not in config:
                raise ConfigError(
                    "The %s drain needs the 'location' key set." % (logging_type,)
                )

            location = config.get("location")
            if os.path.abspath(location) != location:
                raise ConfigError(
                    "File paths need to be absolute, '%s' is a relative path"
                    % (location,)
                )

            yield name, {
                "class": "logging.FileHandler",
                "formatter": formatter,
                "filename": location,
            }

        elif logging_type in [DrainType.NETWORK_JSON_TERSE]:
            host = config.get("host")
            port = config.get("port")
            maximum_buffer = config.get("maximum_buffer", 1000)

            yield name, {
                "class": "synapse.logging.RemoteHandler",
                "formatter": formatter,
                "host": host,
                "port": port,
                "maximum_buffer": maximum_buffer,
            }

        else:
            raise ConfigError(
                "The %s drain type is currently not implemented."
                % (config["type"].upper(),)
            )


def setup_structured_logging(
    log_config: dict,
) -> dict:
    """
    Convert a legacy structured logging configuration (from Synapse < v1.23.0)
    to one compatible with the new standard library handlers.
    """
    if "drains" not in log_config:
        raise ConfigError("The logging configuration requires a list of drains.")

    new_config = {
        "version": 1,
        "formatters": {
            "json": {"class": "synapse.logging.JsonFormatter"},
            "tersejson": {"class": "synapse.logging.TerseJsonFormatter"},
        },
        "handlers": {},
        "loggers": log_config.get("loggers", DEFAULT_LOGGERS),
        "root": {"handlers": []},
    }

    for handler_name, handler in parse_drain_configs(log_config["drains"]):
        new_config["handlers"][handler_name] = handler

        # Add each handler to the root logger.
        new_config["root"]["handlers"].append(handler_name)

    return new_config
