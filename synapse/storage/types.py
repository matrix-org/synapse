# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import Any, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from typing_extensions import Protocol

"""
Some very basic protocol definitions for the DB-API2 classes specified in PEP-249
"""

_Parameters = Union[Sequence[Any], Mapping[str, Any]]


class Cursor(Protocol):
    def execute(self, sql: str, parameters: _Parameters = ...) -> Any:
        ...

    def executemany(self, sql: str, parameters: Sequence[_Parameters]) -> Any:
        ...

    def fetchone(self) -> Optional[Tuple]:
        ...

    def fetchmany(self, size: Optional[int] = ...) -> List[Tuple]:
        ...

    def fetchall(self) -> List[Tuple]:
        ...

    @property
    def description(
        self,
    ) -> Optional[
        Sequence[
            # Note that this is an approximate typing based on sqlite3 and other
            # drivers, and may not be entirely accurate.
            Tuple[
                str,
                Optional[Any],
                Optional[int],
                Optional[int],
                Optional[int],
                Optional[int],
                Optional[int],
            ]
        ]
    ]:
        ...

    @property
    def rowcount(self) -> int:
        return 0

    def __iter__(self) -> Iterator[Tuple]:
        ...

    def close(self) -> None:
        ...


class Connection(Protocol):
    def cursor(self) -> Cursor:
        ...

    def close(self) -> None:
        ...

    def commit(self) -> None:
        ...

    def rollback(self) -> None:
        ...

    def __enter__(self) -> "Connection":
        ...

    def __exit__(self, exc_type, exc_value, traceback) -> Optional[bool]:
        ...
