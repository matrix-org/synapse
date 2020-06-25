# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

import imp
import logging
import os
import re
from collections import Counter
from typing import TextIO

import attr

from synapse.storage.engines.postgres import PostgresEngine
from synapse.storage.types import Cursor

logger = logging.getLogger(__name__)


# Remember to update this number every time a change is made to database
# schema files, so the users will be informed on server restarts.
# XXX: If you're about to bump this to 59 (or higher) please create an update
# that drops the unused `cache_invalidation_stream` table, as per #7436!
# XXX: Also add an update to drop `account_data_max_stream_id` as per #7656!
SCHEMA_VERSION = 58

dir_path = os.path.abspath(os.path.dirname(__file__))


class PrepareDatabaseException(Exception):
    pass


class UpgradeDatabaseException(PrepareDatabaseException):
    pass


def prepare_database(db_conn, database_engine, config, data_stores=["main", "state"]):
    """Prepares a database for usage. Will either create all necessary tables
    or upgrade from an older schema version.

    If `config` is None then prepare_database will assert that no upgrade is
    necessary, *or* will create a fresh database if the database is empty.

    Args:
        db_conn:
        database_engine:
        config (synapse.config.homeserver.HomeServerConfig|None):
            application config, or None if we are connecting to an existing
            database which we expect to be configured already
        data_stores (list[str]): The name of the data stores that will be used
            with this database. Defaults to all data stores.
    """

    try:
        cur = db_conn.cursor()
        version_info = _get_or_create_schema_state(cur, database_engine)

        if version_info:
            user_version, delta_files, upgraded = version_info

            if config is None:
                if user_version != SCHEMA_VERSION:
                    # If we don't pass in a config file then we are expecting to
                    # have already upgraded the DB.
                    raise UpgradeDatabaseException(
                        "Expected database schema version %i but got %i"
                        % (SCHEMA_VERSION, user_version)
                    )
            else:
                _upgrade_existing_database(
                    cur,
                    user_version,
                    delta_files,
                    upgraded,
                    database_engine,
                    config,
                    data_stores=data_stores,
                )
        else:
            _setup_new_database(cur, database_engine, data_stores=data_stores)

        # check if any of our configured dynamic modules want a database
        if config is not None:
            _apply_module_schemas(cur, database_engine, config)

        cur.close()
        db_conn.commit()
    except Exception:
        db_conn.rollback()
        raise


def _setup_new_database(cur, database_engine, data_stores):
    """Sets up the database by finding a base set of "full schemas" and then
    applying any necessary deltas, including schemas from the given data
    stores.

    The "full_schemas" directory has subdirectories named after versions. This
    function searches for the highest version less than or equal to
    `SCHEMA_VERSION` and executes all .sql files in that directory.

    The function will then apply all deltas for all versions after the base
    version.

    Example directory structure:

        schema/
            delta/
                ...
            full_schemas/
                3/
                    test.sql
                    ...
                11/
                    foo.sql
                    bar.sql
                ...

    In the example foo.sql and bar.sql would be run, and then any delta files
    for versions strictly greater than 11.

    Note: we apply the full schemas and deltas from the top level `schema/`
    folder as well those in the data stores specified.

    Args:
        cur (Cursor): a database cursor
        database_engine (DatabaseEngine)
        data_stores (list[str]): The names of the data stores to instantiate
            on the given database.
    """

    # We're about to set up a brand new database so we check that its
    # configured to our liking.
    database_engine.check_new_database(cur)

    current_dir = os.path.join(dir_path, "schema", "full_schemas")
    directory_entries = os.listdir(current_dir)

    # First we find the highest full schema version we have
    valid_versions = []

    for filename in directory_entries:
        try:
            ver = int(filename)
        except ValueError:
            continue

        if ver <= SCHEMA_VERSION:
            valid_versions.append(ver)

    if not valid_versions:
        raise PrepareDatabaseException(
            "Could not find a suitable base set of full schemas"
        )

    max_current_ver = max(valid_versions)

    logger.debug("Initialising schema v%d", max_current_ver)

    # Now lets find all the full schema files, both in the global schema and
    # in data store schemas.
    directories = [os.path.join(current_dir, str(max_current_ver))]
    directories.extend(
        os.path.join(
            dir_path,
            "data_stores",
            data_store,
            "schema",
            "full_schemas",
            str(max_current_ver),
        )
        for data_store in data_stores
    )

    directory_entries = []
    for directory in directories:
        directory_entries.extend(
            _DirectoryListing(file_name, os.path.join(directory, file_name))
            for file_name in os.listdir(directory)
        )

    if isinstance(database_engine, PostgresEngine):
        specific = "postgres"
    else:
        specific = "sqlite"

    directory_entries.sort()
    for entry in directory_entries:
        if entry.file_name.endswith(".sql") or entry.file_name.endswith(
            ".sql." + specific
        ):
            logger.debug("Applying schema %s", entry.absolute_path)
            executescript(cur, entry.absolute_path)

    cur.execute(
        database_engine.convert_param_style(
            "INSERT INTO schema_version (version, upgraded) VALUES (?,?)"
        ),
        (max_current_ver, False),
    )

    _upgrade_existing_database(
        cur,
        current_version=max_current_ver,
        applied_delta_files=[],
        upgraded=False,
        database_engine=database_engine,
        config=None,
        data_stores=data_stores,
        is_empty=True,
    )


def _upgrade_existing_database(
    cur,
    current_version,
    applied_delta_files,
    upgraded,
    database_engine,
    config,
    data_stores,
    is_empty=False,
):
    """Upgrades an existing database.

    Delta files can either be SQL stored in *.sql files, or python modules
    in *.py.

    There can be multiple delta files per version. Synapse will keep track of
    which delta files have been applied, and will apply any that haven't been
    even if there has been no version bump. This is useful for development
    where orthogonal schema changes may happen on separate branches.

    Different delta files for the same version *must* be orthogonal and give
    the same result when applied in any order. No guarantees are made on the
    order of execution of these scripts.

    This is a no-op of current_version == SCHEMA_VERSION.

    Example directory structure:

        schema/
            delta/
                11/
                    foo.sql
                    ...
                12/
                    foo.sql
                    bar.py
                ...
            full_schemas/
                ...

    In the example, if current_version is 11, then foo.sql will be run if and
    only if `upgraded` is True. Then `foo.sql` and `bar.py` would be run in
    some arbitrary order.

    Note: we apply the delta files from the specified data stores as well as
    those in the top-level schema. We apply all delta files across data stores
    for a version before applying those in the next version.

    Args:
        cur (Cursor)
        current_version (int): The current version of the schema.
        applied_delta_files (list): A list of deltas that have already been
            applied.
        upgraded (bool): Whether the current version was generated by having
            applied deltas or from full schema file. If `True` the function
            will never apply delta files for the given `current_version`, since
            the current_version wasn't generated by applying those delta files.
        database_engine (DatabaseEngine)
        config (synapse.config.homeserver.HomeServerConfig|None):
            None if we are initialising a blank database, otherwise the application
            config
        data_stores (list[str]): The names of the data stores to instantiate
            on the given database.
        is_empty (bool): Is this a blank database? I.e. do we need to run the
            upgrade portions of the delta scripts.
    """
    if is_empty:
        assert not applied_delta_files
    else:
        assert config

    if current_version > SCHEMA_VERSION:
        raise ValueError(
            "Cannot use this database as it is too "
            + "new for the server to understand"
        )

    # some of the deltas assume that config.server_name is set correctly, so now
    # is a good time to run the sanity check.
    if not is_empty and "main" in data_stores:
        from synapse.storage.data_stores.main import check_database_before_upgrade

        check_database_before_upgrade(cur, database_engine, config)

    start_ver = current_version
    if not upgraded:
        start_ver += 1

    logger.debug("applied_delta_files: %s", applied_delta_files)

    if isinstance(database_engine, PostgresEngine):
        specific_engine_extension = ".postgres"
    else:
        specific_engine_extension = ".sqlite"

    specific_engine_extensions = (".sqlite", ".postgres")

    for v in range(start_ver, SCHEMA_VERSION + 1):
        logger.info("Upgrading schema to v%d", v)

        # We need to search both the global and per data store schema
        # directories for schema updates.

        # First we find the directories to search in
        delta_dir = os.path.join(dir_path, "schema", "delta", str(v))
        directories = [delta_dir]
        for data_store in data_stores:
            directories.append(
                os.path.join(
                    dir_path, "data_stores", data_store, "schema", "delta", str(v)
                )
            )

        # Used to check if we have any duplicate file names
        file_name_counter = Counter()

        # Now find which directories have anything of interest.
        directory_entries = []
        for directory in directories:
            logger.debug("Looking for schema deltas in %s", directory)
            try:
                file_names = os.listdir(directory)
                directory_entries.extend(
                    _DirectoryListing(file_name, os.path.join(directory, file_name))
                    for file_name in file_names
                )

                for file_name in file_names:
                    file_name_counter[file_name] += 1
            except FileNotFoundError:
                # Data stores can have empty entries for a given version delta.
                pass
            except OSError:
                raise UpgradeDatabaseException(
                    "Could not open delta dir for version %d: %s" % (v, directory)
                )

        duplicates = {
            file_name for file_name, count in file_name_counter.items() if count > 1
        }
        if duplicates:
            # We don't support using the same file name in the same delta version.
            raise PrepareDatabaseException(
                "Found multiple delta files with the same name in v%d: %s"
                % (v, duplicates,)
            )

        # We sort to ensure that we apply the delta files in a consistent
        # order (to avoid bugs caused by inconsistent directory listing order)
        directory_entries.sort()
        for entry in directory_entries:
            file_name = entry.file_name
            relative_path = os.path.join(str(v), file_name)
            absolute_path = entry.absolute_path

            logger.debug("Found file: %s (%s)", relative_path, absolute_path)
            if relative_path in applied_delta_files:
                continue

            root_name, ext = os.path.splitext(file_name)
            if ext == ".py":
                # This is a python upgrade module. We need to import into some
                # package and then execute its `run_upgrade` function.
                module_name = "synapse.storage.v%d_%s" % (v, root_name)
                with open(absolute_path) as python_file:
                    module = imp.load_source(module_name, absolute_path, python_file)
                logger.info("Running script %s", relative_path)
                module.run_create(cur, database_engine)
                if not is_empty:
                    module.run_upgrade(cur, database_engine, config=config)
            elif ext == ".pyc" or file_name == "__pycache__":
                # Sometimes .pyc files turn up anyway even though we've
                # disabled their generation; e.g. from distribution package
                # installers. Silently skip it
                continue
            elif ext == ".sql":
                # A plain old .sql file, just read and execute it
                logger.info("Applying schema %s", relative_path)
                executescript(cur, absolute_path)
            elif ext == specific_engine_extension and root_name.endswith(".sql"):
                # A .sql file specific to our engine; just read and execute it
                logger.info("Applying engine-specific schema %s", relative_path)
                executescript(cur, absolute_path)
            elif ext in specific_engine_extensions and root_name.endswith(".sql"):
                # A .sql file for a different engine; skip it.
                continue
            else:
                # Not a valid delta file.
                logger.warning(
                    "Found directory entry that did not end in .py or .sql: %s",
                    relative_path,
                )
                continue

            # Mark as done.
            cur.execute(
                database_engine.convert_param_style(
                    "INSERT INTO applied_schema_deltas (version, file) VALUES (?,?)"
                ),
                (v, relative_path),
            )

            cur.execute("DELETE FROM schema_version")
            cur.execute(
                database_engine.convert_param_style(
                    "INSERT INTO schema_version (version, upgraded) VALUES (?,?)"
                ),
                (v, True),
            )


def _apply_module_schemas(txn, database_engine, config):
    """Apply the module schemas for the dynamic modules, if any

    Args:
        cur: database cursor
        database_engine: synapse database engine class
        config (synapse.config.homeserver.HomeServerConfig):
            application config
    """
    for (mod, _config) in config.password_providers:
        if not hasattr(mod, "get_db_schema_files"):
            continue
        modname = ".".join((mod.__module__, mod.__name__))
        _apply_module_schema_files(
            txn, database_engine, modname, mod.get_db_schema_files()
        )


def _apply_module_schema_files(cur, database_engine, modname, names_and_streams):
    """Apply the module schemas for a single module

    Args:
        cur: database cursor
        database_engine: synapse database engine class
        modname (str): fully qualified name of the module
        names_and_streams (Iterable[(str, file)]): the names and streams of
            schemas to be applied
    """
    cur.execute(
        database_engine.convert_param_style(
            "SELECT file FROM applied_module_schemas WHERE module_name = ?"
        ),
        (modname,),
    )
    applied_deltas = {d for d, in cur}
    for (name, stream) in names_and_streams:
        if name in applied_deltas:
            continue

        root_name, ext = os.path.splitext(name)
        if ext != ".sql":
            raise PrepareDatabaseException(
                "only .sql files are currently supported for module schemas"
            )

        logger.info("applying schema %s for %s", name, modname)
        execute_statements_from_stream(cur, stream)

        # Mark as done.
        cur.execute(
            database_engine.convert_param_style(
                "INSERT INTO applied_module_schemas (module_name, file) VALUES (?,?)"
            ),
            (modname, name),
        )


def get_statements(f):
    statement_buffer = ""
    in_comment = False  # If we're in a /* ... */ style comment

    for line in f:
        line = line.strip()

        if in_comment:
            # Check if this line contains an end to the comment
            comments = line.split("*/", 1)
            if len(comments) == 1:
                continue
            line = comments[1]
            in_comment = False

        # Remove inline block comments
        line = re.sub(r"/\*.*\*/", " ", line)

        # Does this line start a comment?
        comments = line.split("/*", 1)
        if len(comments) > 1:
            line = comments[0]
            in_comment = True

        # Deal with line comments
        line = line.split("--", 1)[0]
        line = line.split("//", 1)[0]

        # Find *all* semicolons. We need to treat first and last entry
        # specially.
        statements = line.split(";")

        # We must prepend statement_buffer to the first statement
        first_statement = "%s %s" % (statement_buffer.strip(), statements[0].strip())
        statements[0] = first_statement

        # Every entry, except the last, is a full statement
        for statement in statements[:-1]:
            yield statement.strip()

        # The last entry did *not* end in a semicolon, so we store it for the
        # next semicolon we find
        statement_buffer = statements[-1].strip()


def executescript(txn, schema_path):
    with open(schema_path, "r") as f:
        execute_statements_from_stream(txn, f)


def execute_statements_from_stream(cur: Cursor, f: TextIO):
    for statement in get_statements(f):
        cur.execute(statement)


def _get_or_create_schema_state(txn, database_engine):
    # Bluntly try creating the schema_version tables.
    schema_path = os.path.join(dir_path, "schema", "schema_version.sql")
    executescript(txn, schema_path)

    txn.execute("SELECT version, upgraded FROM schema_version")
    row = txn.fetchone()
    current_version = int(row[0]) if row else None
    upgraded = bool(row[1]) if row else None

    if current_version:
        txn.execute(
            database_engine.convert_param_style(
                "SELECT file FROM applied_schema_deltas WHERE version >= ?"
            ),
            (current_version,),
        )
        applied_deltas = [d for d, in txn]
        return current_version, applied_deltas, upgraded

    return None


@attr.s()
class _DirectoryListing(object):
    """Helper class to store schema file name and the
    absolute path to it.

    These entries get sorted, so for consistency we want to ensure that
    `file_name` attr is kept first.
    """

    file_name = attr.ib()
    absolute_path = attr.ib()
