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

"""
Backwards compatibility re-exports of ``synapse.logging.context`` functionality.
"""

from synapse.logging.context import (
    LoggingContext,
    LoggingContextFilter,
    PreserveLoggingContext,
    defer_to_thread,
    make_deferred_yieldable,
    nested_logging_context,
    preserve_fn,
    run_in_background,
)

__all__ = [
    "defer_to_thread",
    "LoggingContext",
    "LoggingContextFilter",
    "make_deferred_yieldable",
    "nested_logging_context",
    "preserve_fn",
    "PreserveLoggingContext",
    "run_in_background",
]
