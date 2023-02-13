#! /usr/bin/env python
# Copyright 2022 The Matrix.org Foundation C.I.C.
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
import sys
from pathlib import Path
from typing import Dict, List

import tomli


def main() -> None:
    lockfile_path = Path(__file__).parent.parent.joinpath("poetry.lock")
    with open(lockfile_path, "rb") as lockfile:
        lockfile_content = tomli.load(lockfile)

    # Poetry 1.3+ lockfile format:
    # There's a `files` inline table in each [[package]]
    packages_to_assets: Dict[str, List[Dict[str, str]]] = {
        package["name"]: package["files"] for package in lockfile_content["package"]
    }

    success = True

    for package_name, assets in packages_to_assets.items():
        has_sdist = any(asset["file"].endswith(".tar.gz") for asset in assets)
        if not has_sdist:
            success = False
            print(
                f"Locked package {package_name!r} does not have a source distribution!",
                file=sys.stderr,
            )

    if not success:
        print(
            "\nThere were some problems with the Poetry lockfile (poetry.lock).",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"Poetry lockfile OK. {len(packages_to_assets)} locked packages checked.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
