from synapse.storage.database import LoggingTransaction
from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine


def run_create(cur: LoggingTransaction, database_engine: BaseDatabaseEngine) -> None:
    """
    Update to drop the NOT NULL constraint on column user_id so that we can cease to
    write to it without inserts to other columns triggering the constraint
    """

    if isinstance(database_engine, PostgresEngine):
        drop_sql = """
        ALTER TABLE profiles ALTER COLUMN user_id DROP NOT NULL
        """
        cur.execute(drop_sql)
    else:
        # irritatingly in SQLite we need to rewrite the table to drop the constraint.
        cur.execute("DROP TABLE IF EXISTS temp_profiles")

        create_sql = """
        CREATE TABLE temp_profiles (
            full_user_id text NOT NULL,
            user_id text,
            displayname text,
            avatar_url text,
            UNIQUE (full_user_id),
            UNIQUE (user_id)
        )
        """
        cur.execute(create_sql)

        copy_sql = """
        INSERT INTO temp_profiles (
            user_id,
            displayname,
            avatar_url,
            full_user_id)
            SELECT user_id, displayname, avatar_url, full_user_id FROM profiles
        """
        cur.execute(copy_sql)

        drop_sql = """
        DROP TABLE profiles
        """
        cur.execute(drop_sql)

        rename_sql = """
        ALTER TABLE temp_profiles RENAME to profiles
        """
        cur.execute(rename_sql)
