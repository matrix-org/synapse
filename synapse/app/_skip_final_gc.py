# Copyright 2017 New Vector Ltd
# Copyright 2019-2021 The Matrix.org Foundation C.I.C
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
import atexit
import logging
import os
import sys
from typing import NoReturn

logger = logging.getLogger(__name__)

skip_final_gc_enabled = False


def _maybe_skip_final_gc() -> None:
    """An `atexit` handler that skips any final garbage collection

    By calling `os._exit()` directly, Python's final garbage collection is skipped,
    along with any further `atexit` handlers. This has the potentially undesirable side
    effect of overriding the original exit code, so the skip should be disabled when we
    think the process is terminating abnormally.
    """
    if skip_final_gc_enabled:
        logger.info("Skipping final GC and further exit handlers...")

        # The `logging` module's `atexit` handler is going to be skipped unless we call
        # it manually here. It's responsible for flushing buffers so that any final log
        # messages are not lost.
        logging.shutdown()

        os._exit(0)


# Register our `atexit` handler early-ish, to minimize the number of handlers skipped.
# The `logging.shutdown` handler will have been registered before us unfortunately.
atexit.register(_maybe_skip_final_gc)


_original_sys_excepthook = sys.excepthook
_original_sys_exit = sys.exit


def _sys_exit(arg=None) -> NoReturn:
    """Disable the skip of the final GC if exiting with a non-zero exit code

    Ensures that non-zero exit codes are preserved."""
    global skip_final_gc_enabled
    if arg is None or (type(arg) == int and arg == 0):
        # Exit code is 0
        pass
    else:
        skip_final_gc_enabled = False
    _original_sys_exit(arg)


def _sys_excepthook(*args) -> None:
    """Disable the skip of the final GC when an unhandled exception occurs

    Ensures that the non-zero exit code is preserved."""
    global skip_final_gc_enabled
    skip_final_gc_enabled = False
    _original_sys_excepthook(*args)


sys.excepthook = _sys_excepthook
sys.exit = _sys_exit


def disable_final_gc() -> None:
    """Enable the skip of the final GC when Python exits"""
    global skip_final_gc_enabled
    skip_final_gc_enabled = True
