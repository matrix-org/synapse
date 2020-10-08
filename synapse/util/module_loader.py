# -*- coding: utf-8 -*-
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

from synapse.config._base import ConfigError


def load_module(provider):
    """ Loads a synapse module with its config
    Take a dict with keys 'module' (the module name) and 'config'
    (the config dict).

    Returns
        Tuple of (provider class, parsed config object)
    """
    # We need to import the module, and then pick the class out of
    # that, so we split based on the last dot.
    module, clz = provider["module"].rsplit(".", 1)
    module = importlib.import_module(module)
    provider_class = getattr(module, clz)

    try:
        provider_config = provider_class.parse_config(provider.get("config"))
    except Exception as e:
        raise ConfigError("Failed to parse config for %r: %s" % (provider["module"], e))

    return provider_class, provider_config


def load_python_module(location: str):
    """Load a python module, and return a reference to its global namespace

    Args:
        location (str): path to the module

    Returns:
        python module object
    """
    spec = importlib.util.spec_from_file_location(location, location)
    if spec is None:
        raise Exception("Unable to load module at %s" % (location,))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod
