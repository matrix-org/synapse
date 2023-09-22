# Copyright 2015, 2016 OpenMarket Ltd
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
from typing import Any, Mapping, NoReturn, cast

from ._base import BaseDatabaseEngine, IncorrectDatabaseSetup
from .postgres import PostgresEngine


# The classes `PostgresEngine` and `Sqlite3Engine` must always be importable, because
# we use `isinstance(engine, PostgresEngine)` to write different queries for postgres
# and sqlite. But the database driver modules are both optional: they may not be
# installed. To account for this, create dummy classes on import failure so we can
# still run `isinstance()` checks.
def dummy_engine(name: str, module: str) -> BaseDatabaseEngine:
    class Engine(BaseDatabaseEngine):
        def __new__(cls, *args: object, **kwargs: object) -> NoReturn:
            raise RuntimeError(
                f"Cannot create {name} -- {module} module is not installed"
            )

    return cast(BaseDatabaseEngine, Engine)


try:
    from .psycopg2 import Psycopg2Engine
except ImportError:
    Psycopg2Engine = dummy_engine("Psycopg2Engine", "psycopg2")  # type: ignore[misc,assignment]

try:
    from .psycopg import PsycopgEngine
except ImportError:
    PsycopgEngine = dummy_engine("PsycopgEngine", "psycopg")  # type: ignore[misc,assignment]

try:
    from .sqlite import Sqlite3Engine
except ImportError:
    Sqlite3Engine = dummy_engine("Sqlite3Engine", "sqlite3")  # type: ignore[misc,assignment]


def create_engine(database_config: Mapping[str, Any]) -> BaseDatabaseEngine:
    name = database_config["name"]

    if name == "sqlite3":
        return Sqlite3Engine(database_config)

    if name == "psycopg2":
        return Psycopg2Engine(database_config)

    if name == "psycopg":
        return PsycopgEngine(database_config)

    raise RuntimeError("Unsupported database engine '%s'" % (name,))


__all__ = [
    "create_engine",
    "BaseDatabaseEngine",
    "PostgresEngine",
    "Sqlite3Engine",
    "IncorrectDatabaseSetup",
]
