import logging

from synapse.storage.engines import PostgresEngine

logger = logging.getLogger(__name__)


"""
This migration updates the user_filters table as follows:

 - drops any (user_id, filter_id) duplicates
 - makes the columns NON-NULLable
 - turns the index into a UNIQUE index
"""


def run_upgrade(cur, database_engine, *args, **kwargs):
    pass


def run_create(cur, database_engine, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        select_clause = """
            SELECT DISTINCT ON (user_id, filter_id) user_id, filter_id, filter_json
            FROM user_filters
        """
    else:
        select_clause = """
            SELECT * FROM user_filters GROUP BY user_id, filter_id
        """
    sql = """
            DROP TABLE IF EXISTS user_filters_migration;
            DROP INDEX IF EXISTS user_filters_unique;
            CREATE TABLE user_filters_migration (
                user_id TEXT NOT NULL,
                filter_id BIGINT NOT NULL,
                filter_json BYTEA NOT NULL
            );
            INSERT INTO user_filters_migration (user_id, filter_id, filter_json)
                %s;
            CREATE UNIQUE INDEX user_filters_unique ON user_filters_migration
                (user_id, filter_id);
            DROP TABLE user_filters;
            ALTER TABLE user_filters_migration RENAME TO user_filters;
        """ % (
        select_clause,
    )

    if isinstance(database_engine, PostgresEngine):
        cur.execute(sql)
    else:
        cur.executescript(sql)
