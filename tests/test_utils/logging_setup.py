# Copyright 2019 New Vector Ltd
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
import os
import sys

import twisted.logger

from synapse.logging.context import LoggingContextFilter


class ToTwistedHandler(logging.Handler):
    """logging handler which sends the logs to the twisted log"""

    tx_log = twisted.logger.Logger()

    def emit(self, record):
        log_entry = self.format(record)
        log_level = record.levelname.lower().replace("warning", "warn")
        self.tx_log.emit(  # type: ignore
            twisted.logger.LogLevel.levelWithName(log_level), "{entry}", entry=log_entry
        )


def setup_logging():
    """Configure the python logging appropriately for the tests.

    Logs will end up in _trial_temp. Exceptions are additionally
    logged to stderr.
    """
    root_logger = logging.getLogger()

    log_format = (
        "%(asctime)s - %(name)s - %(lineno)d - "
        "%(levelname)s - %(request)s - %(message)s"
    )

    to_twisted_handler = ToTwistedHandler()
    formatter = logging.Formatter(log_format)
    to_twisted_handler.setFormatter(formatter)
    to_twisted_handler.addFilter(LoggingContextFilter())
    root_logger.addHandler(to_twisted_handler)

    exception_handler = logging.StreamHandler(sys.stderr)
    exception_handler.setLevel(logging.ERROR)
    exception_handler.setFormatter(formatter)
    root_logger.addHandler(exception_handler)

    log_level = os.environ.get("SYNAPSE_TEST_LOG_LEVEL", "ERROR")
    root_logger.setLevel(log_level)
