# -*- coding: utf-8 -*-
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
import abc


class IncorrectDatabaseSetup(RuntimeError):
    pass


class BaseDatabaseEngine(metaclass=abc.ABCMeta):
    def __init__(self, module, database_config: dict):
        self.module = module

    @abc.abstractmethod
    @property
    def single_threaded(self) -> bool:
        ...

    @abc.abstractmethod
    @property
    def can_native_upsert(self) -> bool:
        """
        Do we support native UPSERTs?
        """
        ...

    @abc.abstractmethod
    @property
    def supports_tuple_comparison(self) -> bool:
        """
        Do we support comparing tuples, i.e. `(a, b) > (c, d)`?
        """
        ...

    @abc.abstractmethod
    @property
    def supports_using_any_list(self) -> bool:
        """
        Do we support using `a = ANY(?)` and passing a list
        """
        ...

    @abc.abstractmethod
    def check_database(self, db_conn, allow_outdated_version: bool = False) -> None:
        ...

    @abc.abstractmethod
    def check_new_database(self, txn) -> None:
        """Gets called when setting up a brand new database. This allows us to
        apply stricter checks on new databases versus existing database.
        """
        ...

    @abc.abstractmethod
    def convert_param_style(self, sql: str) -> str:
        ...

    @abc.abstractmethod
    def on_new_connection(self, db_conn) -> None:
        ...

    @abc.abstractmethod
    def is_deadlock(self, error: Exception) -> bool:
        ...

    @abc.abstractmethod
    def is_connection_closed(self, conn) -> bool:
        ...

    @abc.abstractmethod
    def lock_table(self, txn, table: str) -> None:
        ...

    @abc.abstractmethod
    def get_next_state_group_id(self, txn) -> int:
        """Returns an int that can be used as a new state_group ID
        """
        ...

    @abc.abstractmethod
    @property
    def server_version(self) -> str:
        """Gets a string giving the server version. For example: '3.22.0'
        """
        ...
