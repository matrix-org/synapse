# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

"""A federation sender that forwards things to be sent across replication to
a worker process.

It assumes there is a single worker process feeding off of it.

Each row in the replication stream consists of a type and some json, where the
types indicate whether they are presence, or edus, etc.

Ephemeral or non-event data are queued up in-memory. When the worker requests
updates since a particular point, all in-memory data since before that point is
dropped. We also expire things in the queue after 5 minutes, to ensure that a
dead worker doesn't cause the queues to grow limitlessly.

Events are replicated via a separate events stream.
"""

from .units import Edu

from synapse.util.metrics import Measure
import synapse.metrics

from blist import sorteddict
import ujson


metrics = synapse.metrics.get_metrics_for(__name__)


PRESENCE_TYPE = "p"
KEYED_EDU_TYPE = "k"
EDU_TYPE = "e"
FAILURE_TYPE = "f"
DEVICE_MESSAGE_TYPE = "d"


class FederationRemoteSendQueue(object):
    """A drop in replacement for TransactionQueue"""

    def __init__(self, hs):
        self.server_name = hs.hostname
        self.clock = hs.get_clock()

        self.presence_map = {}
        self.presence_changed = sorteddict()

        self.keyed_edu = {}
        self.keyed_edu_changed = sorteddict()

        self.edus = sorteddict()

        self.failures = sorteddict()

        self.device_messages = sorteddict()

        self.pos = 1
        self.pos_time = sorteddict()

        # EVERYTHING IS SAD. In particular, python only makes new scopes when
        # we make a new function, so we need to make a new function so the inner
        # lambda binds to the queue rather than to the name of the queue which
        # changes. ARGH.
        def register(name, queue):
            metrics.register_callback(
                queue_name + "_size",
                lambda: len(queue),
            )

        for queue_name in [
            "presence_map", "presence_changed", "keyed_edu", "keyed_edu_changed",
            "edus", "failures", "device_messages", "pos_time",
        ]:
            register(queue_name, getattr(self, queue_name))

        self.clock.looping_call(self._clear_queue, 30 * 1000)

    def _next_pos(self):
        pos = self.pos
        self.pos += 1
        self.pos_time[self.clock.time_msec()] = pos
        return pos

    def _clear_queue(self):
        """Clear the queues for anything older than N minutes"""

        FIVE_MINUTES_AGO = 5 * 60 * 1000
        now = self.clock.time_msec()

        keys = self.pos_time.keys()
        time = keys.bisect_left(now - FIVE_MINUTES_AGO)
        if not keys[:time]:
            return

        position_to_delete = max(keys[:time])
        for key in keys[:time]:
            del self.pos_time[key]

        self._clear_queue_before_pos(position_to_delete)

    def _clear_queue_before_pos(self, position_to_delete):
        """Clear all the queues from before a given position"""
        with Measure(self.clock, "send_queue._clear"):
            # Delete things out of presence maps
            keys = self.presence_changed.keys()
            i = keys.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.presence_changed[key]

            user_ids = set(
                user_id for uids in self.presence_changed.values() for _, user_id in uids
            )

            to_del = [
                user_id for user_id in self.presence_map if user_id not in user_ids
            ]
            for user_id in to_del:
                del self.presence_map[user_id]

            # Delete things out of keyed edus
            keys = self.keyed_edu_changed.keys()
            i = keys.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.keyed_edu_changed[key]

            live_keys = set()
            for edu_key in self.keyed_edu_changed.values():
                live_keys.add(edu_key)

            to_del = [edu_key for edu_key in self.keyed_edu if edu_key not in live_keys]
            for edu_key in to_del:
                del self.keyed_edu[edu_key]

            # Delete things out of edu map
            keys = self.edus.keys()
            i = keys.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.edus[key]

            # Delete things out of failure map
            keys = self.failures.keys()
            i = keys.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.failures[key]

            # Delete things out of device map
            keys = self.device_messages.keys()
            i = keys.bisect_left(position_to_delete)
            for key in keys[:i]:
                del self.device_messages[key]

    def notify_new_events(self, current_id):
        """As per TransactionQueue"""
        # We don't need to replicate this as it gets sent down a different
        # stream.
        pass

    def send_edu(self, destination, edu_type, content, key=None):
        """As per TransactionQueue"""
        pos = self._next_pos()

        edu = Edu(
            origin=self.server_name,
            destination=destination,
            edu_type=edu_type,
            content=content,
        )

        if key:
            assert isinstance(key, tuple)
            self.keyed_edu[(destination, key)] = edu
            self.keyed_edu_changed[pos] = (destination, key)
        else:
            self.edus[pos] = edu

    def send_presence(self, destination, states):
        """As per TransactionQueue"""
        pos = self._next_pos()

        self.presence_map.update({
            state.user_id: state
            for state in states
        })

        self.presence_changed[pos] = [
            (destination, state.user_id) for state in states
        ]

    def send_failure(self, failure, destination):
        """As per TransactionQueue"""
        pos = self._next_pos()

        self.failures[pos] = (destination, str(failure))

    def send_device_messages(self, destination):
        """As per TransactionQueue"""
        pos = self._next_pos()
        self.device_messages[pos] = destination

    def get_current_token(self):
        return self.pos - 1

    def get_replication_rows(self, token, limit, federation_ack=None):
        """
        Args:
            token (int)
            limit (int)
            federation_ack (int): Optional. The position where the worker is
                explicitly acknowledged it has handled. Allows us to drop
                data from before that point
        """
        # TODO: Handle limit.

        # To handle restarts where we wrap around
        if token > self.pos:
            token = -1

        rows = []

        # There should be only one reader, so lets delete everything its
        # acknowledged its seen.
        if federation_ack:
            self._clear_queue_before_pos(federation_ack)

        # Fetch changed presence
        keys = self.presence_changed.keys()
        i = keys.bisect_right(token)
        dest_user_ids = set(
            (pos, dest_user_id)
            for pos in keys[i:]
            for dest_user_id in self.presence_changed[pos]
        )

        for (key, (dest, user_id)) in dest_user_ids:
            rows.append((key, PRESENCE_TYPE, ujson.dumps({
                "destination": dest,
                "state": self.presence_map[user_id].as_dict(),
            })))

        # Fetch changes keyed edus
        keys = self.keyed_edu_changed.keys()
        i = keys.bisect_right(token)
        keyed_edus = set((k, self.keyed_edu_changed[k]) for k in keys[i:])

        for (pos, (destination, edu_key)) in keyed_edus:
            rows.append(
                (pos, KEYED_EDU_TYPE, ujson.dumps({
                    "key": edu_key,
                    "edu": self.keyed_edu[(destination, edu_key)].get_internal_dict(),
                }))
            )

        # Fetch changed edus
        keys = self.edus.keys()
        i = keys.bisect_right(token)
        edus = set((k, self.edus[k]) for k in keys[i:])

        for (pos, edu) in edus:
            rows.append((pos, EDU_TYPE, ujson.dumps(edu.get_internal_dict())))

        # Fetch changed failures
        keys = self.failures.keys()
        i = keys.bisect_right(token)
        failures = set((k, self.failures[k]) for k in keys[i:])

        for (pos, (destination, failure)) in failures:
            rows.append((pos, FAILURE_TYPE, ujson.dumps({
                "destination": destination,
                "failure": failure,
            })))

        # Fetch changed device messages
        keys = self.device_messages.keys()
        i = keys.bisect_right(token)
        device_messages = set((k, self.device_messages[k]) for k in keys[i:])

        for (pos, destination) in device_messages:
            rows.append((pos, DEVICE_MESSAGE_TYPE, ujson.dumps({
                "destination": destination,
            })))

        # Sort rows based on pos
        rows.sort()

        return rows
