# Copyright 2016 OpenMarket Ltd
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
from typing import Generic, Hashable, List, Set, TypeVar

import attr

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=Hashable)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _Entry(Generic[T]):
    end_key: int
    elements: Set[T] = attr.Factory(set)


class WheelTimer(Generic[T]):
    """Stores arbitrary objects that will be returned after their timers have
    expired.
    """

    def __init__(self, bucket_size: int = 5000) -> None:
        """
        Args:
            bucket_size: Size of buckets in ms. Corresponds roughly to the
                accuracy of the timer.
        """
        self.bucket_size: int = bucket_size
        self.entries: List[_Entry[T]] = []
        self.current_tick: int = 0

    def insert(self, now: int, obj: T, then: int) -> None:
        """Inserts object into timer.

        Args:
            now: Current time in msec
            obj: Object to be inserted
            then: When to return the object strictly after.
        """
        then_key = int(then / self.bucket_size) + 1
        now_key = int(now / self.bucket_size)

        if self.entries:
            min_key = self.entries[0].end_key
            max_key = self.entries[-1].end_key

            if min_key < now_key - 10:
                # If we have ten buckets that are due and still nothing has
                # called `fetch()` then we likely have a bug that is causing a
                # memory leak.
                logger.warning(
                    "Inserting into a wheel timer that hasn't been read from recently. Item: %s",
                    obj,
                )

            if then_key <= max_key:
                # The max here is to protect against inserts for times in the past
                self.entries[max(min_key, then_key) - min_key].elements.add(obj)
                return

        next_key = now_key + 1
        if self.entries:
            last_key = self.entries[-1].end_key
        else:
            last_key = next_key

        # Handle the case when `then` is in the past and `entries` is empty.
        then_key = max(last_key, then_key)

        # Add empty entries between the end of the current list and when we want
        # to insert. This ensures there are no gaps.
        self.entries.extend(_Entry(key) for key in range(last_key, then_key + 1))

        self.entries[-1].elements.add(obj)

    def fetch(self, now: int) -> List[T]:
        """Fetch any objects that have timed out

        Args:
            now (ms): Current time in msec

        Returns:
            list: List of objects that have timed out
        """
        now_key = int(now / self.bucket_size)

        ret: List[T] = []
        while self.entries and self.entries[0].end_key <= now_key:
            ret.extend(self.entries.pop(0).elements)

        return ret

    def __len__(self) -> int:
        return sum(len(entry.elements) for entry in self.entries)
