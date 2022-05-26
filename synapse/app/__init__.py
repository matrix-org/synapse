# Copyright 2014-2016 OpenMarket Ltd
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
import sys
from typing import Container

from synapse.util import check_dependencies

logger = logging.getLogger(__name__)

try:
    check_dependencies.check_requirements()
except check_dependencies.DependencyException as e:
    sys.stderr.writelines(
        e.message  # noqa: B306, DependencyException.message is a property
    )
    sys.exit(1)


def check_bind_error(
    e: Exception, address: str, bind_addresses: Container[str]
) -> None:
    """
    This method checks an exception occurred while binding on 0.0.0.0.
    If :: is specified in the bind addresses a warning is shown.
    The exception is still raised otherwise.

    Binding on both 0.0.0.0 and :: causes an exception on Linux and macOS
    because :: binds on both IPv4 and IPv6 (as per RFC 3493).
    When binding on 0.0.0.0 after :: this can safely be ignored.

    Args:
        e: Exception that was caught.
        address: Address on which binding was attempted.
        bind_addresses: Addresses on which the service listens.
    """
    if address == "0.0.0.0" and "::" in bind_addresses:
        logger.warning(
            "Failed to listen on 0.0.0.0, continuing because listening on [::]"
        )
    else:
        raise e
