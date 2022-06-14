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

GROUP_START_PREFIX = "::group::"
PASSING_CI_PREFIX = "✅"
GROUP_END_PREFIX = "::endgroup::"


def main() -> None:
    in_collapsed_block = False
    first_group_name = None
    last_group_name = None
    buffer = []

    def flush_buffer() -> None:
        nonlocal buffer, in_collapsed_block

        sys.stdout.write(f"::group::{first_group_name} ... {last_group_name}\n")
        for buffered_line in buffer:
            sys.stdout.write(buffered_line)

        sys.stdout.write("::endgroup::\n")

        in_collapsed_block = False
        buffer = []

    for line in sys.stdin:
        if line.startswith(GROUP_START_PREFIX):
            group_name = line[len(GROUP_START_PREFIX) :]
            should_skip_block = group_name.startswith(PASSING_CI_PREFIX)

            if in_collapsed_block and not should_skip_block:
                flush_buffer()
            elif in_collapsed_block and should_skip_block:
                last_group_name = group_name
            elif not in_collapsed_block and should_skip_block:
                first_group_name = group_name
                in_collapsed_block = True

        if not in_collapsed_block:
            sys.stdout.write(line)

    flush_buffer()


if __name__ == "__main__":
    main()
