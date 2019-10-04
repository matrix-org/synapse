import logging

from synapse.storage.engines import PostgresEngine

logger = logging.getLogger(__name__)


def run_upgrade(cur, database_engine, *args, **kwargs):
    if isinstance(database_engine, PostgresEngine):
        select_clause = """
        CREATE TABLE user_filters_migration AS
            SELECT DISTINCT ON (user_id, filter_id) user_id, filter_id, filter_json
            FROM user_filters;
        """
    else:
        select_clause = """
        CREATE TABLE user_filters_migration AS
            SELECT * FROM user_filters GROUP BY user_id, filter_id;
        """
    sql = (
        """
        BEGIN;
            %s
            DROP INDEX user_filters_by_user_id_filter_id;
            DELETE FROM user_filters;
            INSERT INTO user_filters(user_id, filter_id, filter_json)
                SELECT * FROM user_filters_migration;
            DROP TABLE user_filters_migration;
            CREATE UNIQUE INDEX user_filters_by_user_id_filter_id_unique
                ON user_filters(user_id, filter_id);
        END;
    """
        % select_clause
    )
    if isinstance(database_engine, PostgresEngine):
        cur.execute(sql)
    else:
        cur.executescript(sql)


def run_create(cur, database_engine, *args, **kwargs):
    pass
