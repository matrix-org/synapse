# -*- coding: utf-8 -*-
# Copyright 2018 Travis Ralston
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

from synapse.util.module_loader import load_module

from ._base import Config


class InternalApiConfig(Config):
    """Internal Api Configuration
    Configuration for the internal API within synapse. This is exposed for modules to
    hook in to the various parts of synapse, reacting to what the server is doing.
    """

    def read_config(self, config):
        self.internal_api_modules = []
        plugin_defs = config.get("internal_api_plugins", [])
        for plugin in plugin_defs:
            self.internal_api_modules.append(load_module(plugin))

    def default_config(self, **kwargs):
        return """
        # Internal Api configuration
        #
        # The internal API can be used by third party modules to react to various
        # things the server is doing. For more information, see docs/internal_api.md
        #
        #internal_api_plugins:
        #- module: "my_custom_project.MyCoolSynapseHook"
        #  config:
        #      example_option: "some_value"
        #- module: "my_custom_project.MyOtherCoolSynapseHook"
        #  config:
        #      example_option: "some_value"
        """
