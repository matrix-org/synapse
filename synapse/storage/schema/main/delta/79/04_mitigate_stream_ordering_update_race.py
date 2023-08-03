#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


from synapse.storage.database import LoggingTransaction
from synapse.storage.engines import BaseDatabaseEngine, PostgresEngine


def run_create(
    cur: LoggingTransaction,
    database_engine: BaseDatabaseEngine,
) -> None:
    """
    An attempt to mitigate a painful race between foreground and background updates
    touching the `stream_ordering` column of the events table. More info can be found
    at https://github.com/matrix-org/synapse/issues/15677.
    """

    # technically the bg update we're concerned with below should only have been added in
    # postgres but it doesn't hurt to be extra careful
    if isinstance(database_engine, PostgresEngine):
        select_sql = """
            SELECT 1 FROM background_updates
                WHERE update_name = 'replace_stream_ordering_column'
        """
        cur.execute(select_sql)
        res = cur.fetchone()

        # if the background update `replace_stream_ordering_column` is still pending, we need
        # to drop the indexes added in 7403, and re-add them to the column `stream_ordering2`
        # with the idea that they will be preserved when the column is renamed `stream_ordering`
        # after the background update has finished
        if res:
            drop_cse_sql = """
            ALTER TABLE current_state_events DROP CONSTRAINT IF EXISTS event_stream_ordering_fkey
            """
            cur.execute(drop_cse_sql)

            drop_lcm_sql = """
            ALTER TABLE local_current_membership DROP CONSTRAINT IF EXISTS event_stream_ordering_fkey
            """
            cur.execute(drop_lcm_sql)

            drop_rm_sql = """
            ALTER TABLE room_memberships DROP CONSTRAINT IF EXISTS event_stream_ordering_fkey
            """
            cur.execute(drop_rm_sql)

            add_cse_sql = """
            ALTER TABLE current_state_events ADD CONSTRAINT event_stream_ordering_fkey
            FOREIGN KEY (event_stream_ordering) REFERENCES events(stream_ordering2) NOT VALID;
            """
            cur.execute(add_cse_sql)

            add_lcm_sql = """
            ALTER TABLE local_current_membership ADD CONSTRAINT event_stream_ordering_fkey
            FOREIGN KEY (event_stream_ordering) REFERENCES events(stream_ordering2) NOT VALID;
            """
            cur.execute(add_lcm_sql)

            add_rm_sql = """
            ALTER TABLE room_memberships ADD CONSTRAINT event_stream_ordering_fkey
            FOREIGN KEY (event_stream_ordering) REFERENCES events(stream_ordering2) NOT VALID;
            """
            cur.execute(add_rm_sql)
