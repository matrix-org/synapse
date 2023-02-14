# Copyright 2022 Beeper
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


"""
Forces through the `current_state_events_membership` background job so checks
for its completion can be removed.

Note the background job must still remain defined in the database class.
"""


def run_upgrade(cur, database_engine, *args, **kwargs):
    cur.execute("SELECT update_name FROM background_updates")
    rows = cur.fetchall()
    for row in rows:
        if row[0] == "current_state_events_membership":
            break
    # No pending background job so nothing to do here
    else:
        return

    # Populate membership field for all current_state_events, this may take
    # a while but was originally handled via a background update in 2019.
    cur.execute(
        """
        UPDATE current_state_events
        SET membership = (
            SELECT membership FROM room_memberships
            WHERE event_id = current_state_events.event_id
        )
        """
    )

    # Finally, delete the background job because we've handled it above
    cur.execute(
        """
        DELETE FROM background_updates
        WHERE update_name = 'current_state_events_membership'
        """
    )
