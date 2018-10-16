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
import logging
import re
import threading

logger = logging.getLogger(__name__)


class InternalApi(object):
    def __init__(self, hs):
        self.hs = hs

        self._plugins = []

        for module, config in hs.config.internal_api_modules:
            try:
                self._plugins.append(module(config=config, api=self))
            except Exception:
                pass

    def raise_event(self, event_name, content):
        """Raises an event to the internal API. Events raised to the internal
        API in this manner may not affect the application flow and are purely
        for communicating information to the 3rd party module.

        Args:
            event_name (string): the name of the event to raise internally. Event
                names should be named_with_underscores.
            content (object): the information to pass along, or None
        """
        if not re.match('^[a-zA-Z][a-zA-Z_]+$', event_name):
            raise ValueError('Event name should be named_with_underscores')
        th = threading.Thread(target=self._async_raise_event, args=[event_name, content])
        th.start()  # Perform async

    def _async_raise_event(self, event_name, content):
        for plugin in self._plugins:
            fn = getattr(plugin, "on_" + event_name, None)
            if fn and callable(fn):
                try:
                    logger.info("Calling %s on %r", event_name, plugin)
                    fn(content)
                except Exception as e:
                    # Don't let plugin errors bubble up to synapse
                    logger.warn("Error calling %s on %r: %r", event_name, plugin, e)
            else:
                logger.warn("Error calling %s on %r: Function not callable",
                            event_name, plugin)
