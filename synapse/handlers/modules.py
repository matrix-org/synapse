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

import logging
from typing import TYPE_CHECKING, Dict

from twisted.web.resource import IResource

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ModulesHandler:
    def __init__(self, hs: "HomeServer"):
        self.modules = []

        module_api = hs.get_module_api()
        for module, config in hs.config.modules.loaded_modules:
            self.modules.append(module(config=config, api=module_api))

        self.hooks_cache: Dict[str, list] = {}

    def get_registered_web_resources(self) -> Dict[str, IResource]:
        """Retrieve the custom resources registered by each module.

        If several modules attempt to register a resource for the same path, the module
        defined the highest in the configuration file takes priority.

        Returns:
            A dictionary associating paths to the resources to attach to them.
        """
        resources = {}

        # We reverse the list of modules so that if two modules try to register the same
        # path the highest one in the configuration file takes priority.
        reversed_module_list = self.modules.copy()
        reversed_module_list.reverse()
        for module in reversed_module_list:
            if hasattr(module, "register_web_resources"):
                resources.update(module.register_web_resources())

        return resources

    def _get_modules_for_hook(self, fn_name: str) -> list:
        """Get the modules implementing a hook (function) with the given name

        Returns:
            A list of modules implementing the given function.
        """
        if fn_name not in self.hooks_cache.keys():
            self.hooks_cache[fn_name] = []

            for module in self.modules:
                if hasattr(module, fn_name):
                    self.hooks_cache[fn_name].append(module)

        return self.hooks_cache[fn_name]
