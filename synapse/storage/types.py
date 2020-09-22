# -*- coding: utf-8 -*-
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
from typing import Any, Iterable, Iterator, List, Tuple

from typing_extensions import Protocol

"""
Some very basic protocol definitions for the DB-API2 classes specified in PEP-249
"""


class Cursor(Protocol):
    def execute(self, sql: str, parameters: Iterable[Any] = ...) -> Any:
        ...

    def executemany(self, sql: str, parameters: Iterable[Iterable[Any]]) -> Any:
        ...

    def fetchall(self) -> List[Tuple]:
        ...

    def fetchone(self) -> Tuple:
        ...

    @property
    def description(self) -> Any:
        return None

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

    def rollback(self, *args, **kwargs) -> None:
        ...
