# Copyright 2016 OpenMarket Ltd
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
import os
import subprocess
from types import ModuleType
from typing import Dict

logger = logging.getLogger(__name__)

version_cache: Dict[ModuleType, str] = {}


def get_version_string(module: ModuleType) -> str:
    """Given a module calculate a git-aware version string for it.

    If called on a module not in a git checkout will return `__version__`.

    Args:
        module: The module to check the version of. Must declare a __version__
            attribute.

    Returns:
        The module version (as a string).
    """

    cached_version = version_cache.get(module)
    if cached_version is not None:
        return cached_version

    # We want this to fail loudly with an AttributeError. Type-ignore this so
    # mypy only considers the happy path.
    version_string = module.__version__  # type: ignore[attr-defined]

    try:
        cwd = os.path.dirname(os.path.abspath(module.__file__))

        def _run_git_command(prefix: str, *params: str) -> str:
            try:
                result = (
                    subprocess.check_output(
                        ["git", *params], stderr=subprocess.DEVNULL, cwd=cwd
                    )
                    .strip()
                    .decode("ascii")
                )
                return prefix + result
            except (subprocess.CalledProcessError, FileNotFoundError):
                return ""

        git_branch = _run_git_command("b=", "rev-parse", "--abbrev-ref", "HEAD")
        git_tag = _run_git_command("t=", "describe", "--exact-match")
        git_commit = _run_git_command("", "rev-parse", "--short", "HEAD")

        dirty_string = "-this_is_a_dirty_checkout"
        is_dirty = _run_git_command("", "describe", "--dirty=" + dirty_string).endswith(
            dirty_string
        )
        git_dirty = "dirty" if is_dirty else ""

        if git_branch or git_tag or git_commit or git_dirty:
            git_version = ",".join(
                s for s in (git_branch, git_tag, git_commit, git_dirty) if s
            )

            version_string = f"{version_string} ({git_version})"
    except Exception as e:
        logger.info("Failed to check for git repository: %s", e)

    version_cache[module] = version_string

    return version_string
