# Copyright 2017 New Vector Ltd
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

import importlib
import importlib.util
import itertools
from types import ModuleType
from typing import Any, Iterable, Tuple, Type

import jsonschema

from synapse.config._base import ConfigError
from synapse.config._util import json_error_to_config_error


def load_module(provider: dict, config_path: Iterable[str]) -> Tuple[Type, Any]:
    """Loads a synapse module with its config

    Args:
        provider: a dict with keys 'module' (the module name) and 'config'
           (the config dict).
        config_path: the path within the config file. This will be used as a basis
           for any error message.

    Returns
        Tuple of (provider class, parsed config object)
    """

    modulename = provider.get("module")
    if not isinstance(modulename, str):
        raise ConfigError(
            "expected a string", path=itertools.chain(config_path, ("module",))
        )

    # We need to import the module, and then pick the class out of
    # that, so we split based on the last dot.
    module_name, clz = modulename.rsplit(".", 1)
    module = importlib.import_module(module_name)
    provider_class = getattr(module, clz)

    # Load the module config. If None, pass an empty dictionary instead
    module_config = provider.get("config") or {}
    try:
        provider_config = provider_class.parse_config(module_config)
    except jsonschema.ValidationError as e:
        raise json_error_to_config_error(e, itertools.chain(config_path, ("config",)))
    except ConfigError as e:
        raise _wrap_config_error(
            "Failed to parse config for module %r" % (modulename,),
            prefix=itertools.chain(config_path, ("config",)),
            e=e,
        )
    except Exception as e:
        raise ConfigError(
            "Failed to parse config for module %r" % (modulename,),
            path=itertools.chain(config_path, ("config",)),
        ) from e

    return provider_class, provider_config


def load_python_module(location: str) -> ModuleType:
    """Load a python module, and return a reference to its global namespace

    Args:
        location: path to the module

    Returns:
        python module object
    """
    spec = importlib.util.spec_from_file_location(location, location)
    if spec is None:
        raise Exception("Unable to load module at %s" % (location,))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def _wrap_config_error(
    msg: str, prefix: Iterable[str], e: ConfigError
) -> "ConfigError":
    """Wrap a relative ConfigError with a new path

    This is useful when we have a ConfigError with a relative path due to a problem
    parsing part of the config, and we now need to set it in context.
    """
    path = prefix
    if e.path:
        path = itertools.chain(prefix, e.path)

    e1 = ConfigError(msg, path)

    # ideally we would set the 'cause' of the new exception to the original exception;
    # however now that we have merged the path into our own, the stringification of
    # e will be incorrect, so instead we create a new exception with just the "msg"
    # part.

    e1.__cause__ = Exception(e.msg)
    e1.__cause__.__cause__ = e.__cause__
    return e1
