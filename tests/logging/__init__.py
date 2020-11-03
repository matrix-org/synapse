# -*- coding: utf-8 -*-
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


class LoggerCleanupMixin:
    def get_logger(self, handler):
        """
        Attach a handler to a logger and add clean-ups to remove revert this.
        """
        # Create a logger and add the handler to it.
        logger = logging.getLogger(__name__)
        logger.addHandler(handler)

        # Ensure the logger actually logs something.
        logger.setLevel(logging.INFO)

        # Ensure the logger gets cleaned-up appropriately.
        self.addCleanup(logger.removeHandler, handler)
        self.addCleanup(logger.setLevel, logging.NOTSET)

        return logger
