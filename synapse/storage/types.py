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
from types import TracebackType
from typing import Any, Iterator, List, Mapping, Optional, Sequence, Tuple, Type, Union

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
            # FWIW, the DBAPI 2 spec is: https://peps.python.org/pep-0249/#description
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

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        ...


class DBAPI2Module(Protocol):
    """The module-level attributes that we use from PEP 249.

    This is NOT a comprehensive stub for the entire DBAPI2."""

    __name__: str

    # Exceptions. See https://peps.python.org/pep-0249/#exceptions

    # For our specific drivers:
    # - Python's sqlite3 module doesn't contains the same descriptions as the
    #   DBAPI2 spec, see https://docs.python.org/3/library/sqlite3.html#exceptions
    # - Psycopg2 maps every Postgres error code onto a unique exception class which
    #   extends from this heirarchy. See
    #     https://docs.python.org/3/library/sqlite3.html?highlight=sqlite3#exceptions
    #     https://www.postgresql.org/docs/current/errcodes-appendix.html#ERRCODES-TABLE
    Warning: Type[Exception]
    Error: Type[Exception]

    # Errors are divided into InterfaceErrors (something went wrong in the DB driver)
    # and DatabaseErrors (something went wrong in the DB). These are both subclasses of
    # Error, but we can't currently express this in type annotations due to
    # https://github.com/python/mypy/issues/8397
    InterfaceError: Type[Exception]
    DatabaseError: Type[Exception]

    # Everything below is a subclass of `DatabaseError`.

    # Roughly: the DB rejected a nonsensical value. Examples:
    # - integer too big for its data type
    # - invalid date time format
    # - strings containing null code points
    DataError: Type[Exception]

    # Roughly: something went wrong in the DB, but it's not within the application
    # programmer's control. Examples:
    # - we failed to establish connection to the DB
    # - we lost connection to the DB
    # - deadlock detected
    # - serialisation failure
    # - the DB ran out of resources (storage, ram, connections...)
    # - the DB encountered an error from the OS
    OperationalError: Type[Exception]

    # Roughly: you've given the DB data which breaks a rule you asked it to enforce.
    # Examples:
    # - Stop, criminal scum! You violated the foreign key constraint
    # - Also check constraints, non-null constraints, etc.
    IntegrityError: Type[Exception]

    # Roughly: something went wrong within the DB server itself.
    InternalError: Type[Exception]

    # Roughly: your application did something silly that you need to fix. Examples:
    # - You don't have permissions to do something.
    # - You tried to create a table with duplicate column names.
    # - You tried to use a reserved name.
    # - You referred to a column that doesn't exist.
    ProgrammingError: Type[Exception]

    # Roughly: you've tried to do something that this DB doesn't support.
    NotSupportedError: Type[Exception]

    def connect(self, **parameters: object) -> Connection:
        ...


__all__ = ["Cursor", "Connection", "DBAPI2Module"]
