# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 New Vector Ltd
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
import logging
import urllib.parse
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Union

from prometheus_client import Counter

from twisted.internet.error import AlreadyCalled, AlreadyCancelled
from twisted.internet.interfaces import IDelayedCall

from synapse.api.constants import EventTypes
from synapse.events import EventBase
from synapse.logging import opentracing
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.push import Pusher, PusherConfig, PusherConfigException

from . import push_rule_evaluator, push_tools

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

http_push_processed_counter = Counter(
    "synapse_http_httppusher_http_pushes_processed",
    "Number of push notifications successfully sent",
)

http_push_failed_counter = Counter(
    "synapse_http_httppusher_http_pushes_failed",
    "Number of push notifications which failed",
)

http_badges_processed_counter = Counter(
    "synapse_http_httppusher_badge_updates_processed",
    "Number of badge updates successfully sent",
)

http_badges_failed_counter = Counter(
    "synapse_http_httppusher_badge_updates_failed",
    "Number of badge updates which failed",
)


class HttpPusher(Pusher):
    INITIAL_BACKOFF_SEC = 1  # in seconds because that's what Twisted takes
    MAX_BACKOFF_SEC = 60 * 60

    # This one's in ms because we compare it against the clock
    GIVE_UP_AFTER_MS = 24 * 60 * 60 * 1000

    def __init__(self, hs: "HomeServer", pusher_config: PusherConfig):
        super().__init__(hs, pusher_config)
        self.storage = self.hs.get_storage()
        self.app_display_name = pusher_config.app_display_name
        self.device_display_name = pusher_config.device_display_name
        self.pushkey_ts = pusher_config.ts
        self.data = pusher_config.data
        self.backoff_delay = HttpPusher.INITIAL_BACKOFF_SEC
        self.failing_since = pusher_config.failing_since
        self.timed_call = None  # type: Optional[IDelayedCall]
        self._is_processing = False
        self._group_unread_count_by_room = hs.config.push_group_unread_count_by_room
        self._pusherpool = hs.get_pusherpool()

        self.data = pusher_config.data
        if self.data is None:
            raise PusherConfigException("'data' key can not be null for HTTP pusher")

        self.name = "%s/%s/%s" % (
            pusher_config.user_name,
            pusher_config.app_id,
            pusher_config.pushkey,
        )

        # Validate that there's a URL and it is of the proper form.
        if "url" not in self.data:
            raise PusherConfigException("'url' required in data for HTTP pusher")

        url = self.data["url"]
        if not isinstance(url, str):
            raise PusherConfigException("'url' must be a string")
        url_parts = urllib.parse.urlparse(url)
        # Note that the specification also says the scheme must be HTTPS, but
        # it isn't up to the homeserver to verify that.
        if url_parts.path != "/_matrix/push/v1/notify":
            raise PusherConfigException(
                "'url' must have a path of '/_matrix/push/v1/notify'"
            )

        self.url = url
        self.http_client = hs.get_proxied_blacklisted_http_client()
        self.data_minus_url = {}
        self.data_minus_url.update(self.data)
        del self.data_minus_url["url"]

    def on_started(self, should_check_for_notifs: bool) -> None:
        """Called when this pusher has been started.

        Args:
            should_check_for_notifs: Whether we should immediately
                check for push to send. Set to False only if it's known there
                is nothing to send
        """
        if should_check_for_notifs:
            self._start_processing()

    def on_new_receipts(self, min_stream_id: int, max_stream_id: int) -> None:
        # Note that the min here shouldn't be relied upon to be accurate.

        # We could check the receipts are actually m.read receipts here,
        # but currently that's the only type of receipt anyway...
        run_as_background_process("http_pusher.on_new_receipts", self._update_badge)

    async def _update_badge(self) -> None:
        # XXX as per https://github.com/matrix-org/matrix-doc/issues/2627, this seems
        # to be largely redundant. perhaps we can remove it.
        badge = await push_tools.get_badge_count(
            self.hs.get_datastore(),
            self.user_id,
            group_by_room=self._group_unread_count_by_room,
        )
        await self._send_badge(badge)

    def on_timer(self) -> None:
        self._start_processing()

    def on_stop(self) -> None:
        if self.timed_call:
            try:
                self.timed_call.cancel()
            except (AlreadyCalled, AlreadyCancelled):
                pass
            self.timed_call = None

    def _start_processing(self) -> None:
        if self._is_processing:
            return

        run_as_background_process("httppush.process", self._process)

    async def _process(self) -> None:
        # we should never get here if we are already processing
        assert not self._is_processing

        try:
            self._is_processing = True
            # if the max ordering changes while we're running _unsafe_process,
            # call it again, and so on until we've caught up.
            while True:
                starting_max_ordering = self.max_stream_ordering
                try:
                    await self._unsafe_process()
                except Exception:
                    logger.exception("Exception processing notifs")
                if self.max_stream_ordering == starting_max_ordering:
                    break
        finally:
            self._is_processing = False

    async def _unsafe_process(self) -> None:
        """
        Looks for unset notifications and dispatch them, in order
        Never call this directly: use _process which will only allow this to
        run once per pusher.
        """
        unprocessed = (
            await self.store.get_unread_push_actions_for_user_in_range_for_http(
                self.user_id, self.last_stream_ordering, self.max_stream_ordering
            )
        )

        logger.info(
            "Processing %i unprocessed push actions for %s starting at "
            "stream_ordering %s",
            len(unprocessed),
            self.name,
            self.last_stream_ordering,
        )

        for push_action in unprocessed:
            with opentracing.start_active_span(
                "http-push",
                tags={
                    "authenticated_entity": self.user_id,
                    "event_id": push_action["event_id"],
                    "app_id": self.app_id,
                    "app_display_name": self.app_display_name,
                },
            ):
                processed = await self._process_one(push_action)

            if processed:
                http_push_processed_counter.inc()
                self.backoff_delay = HttpPusher.INITIAL_BACKOFF_SEC
                self.last_stream_ordering = push_action["stream_ordering"]
                pusher_still_exists = (
                    await self.store.update_pusher_last_stream_ordering_and_success(
                        self.app_id,
                        self.pushkey,
                        self.user_id,
                        self.last_stream_ordering,
                        self.clock.time_msec(),
                    )
                )
                if not pusher_still_exists:
                    # The pusher has been deleted while we were processing, so
                    # lets just stop and return.
                    self.on_stop()
                    return

                if self.failing_since:
                    self.failing_since = None
                    await self.store.update_pusher_failing_since(
                        self.app_id, self.pushkey, self.user_id, self.failing_since
                    )
            else:
                http_push_failed_counter.inc()
                if not self.failing_since:
                    self.failing_since = self.clock.time_msec()
                    await self.store.update_pusher_failing_since(
                        self.app_id, self.pushkey, self.user_id, self.failing_since
                    )

                if (
                    self.failing_since
                    and self.failing_since
                    < self.clock.time_msec() - HttpPusher.GIVE_UP_AFTER_MS
                ):
                    # we really only give up so that if the URL gets
                    # fixed, we don't suddenly deliver a load
                    # of old notifications.
                    logger.warning(
                        "Giving up on a notification to user %s, pushkey %s",
                        self.user_id,
                        self.pushkey,
                    )
                    self.backoff_delay = HttpPusher.INITIAL_BACKOFF_SEC
                    self.last_stream_ordering = push_action["stream_ordering"]
                    await self.store.update_pusher_last_stream_ordering(
                        self.app_id,
                        self.pushkey,
                        self.user_id,
                        self.last_stream_ordering,
                    )

                    self.failing_since = None
                    await self.store.update_pusher_failing_since(
                        self.app_id, self.pushkey, self.user_id, self.failing_since
                    )
                else:
                    logger.info("Push failed: delaying for %ds", self.backoff_delay)
                    self.timed_call = self.hs.get_reactor().callLater(
                        self.backoff_delay, self.on_timer
                    )
                    self.backoff_delay = min(
                        self.backoff_delay * 2, self.MAX_BACKOFF_SEC
                    )
                    break

    async def _process_one(self, push_action: dict) -> bool:
        if "notify" not in push_action["actions"]:
            return True

        tweaks = push_rule_evaluator.tweaks_for_actions(push_action["actions"])
        badge = await push_tools.get_badge_count(
            self.hs.get_datastore(),
            self.user_id,
            group_by_room=self._group_unread_count_by_room,
        )

        event = await self.store.get_event(push_action["event_id"], allow_none=True)
        if event is None:
            return True  # It's been redacted
        rejected = await self.dispatch_push(event, tweaks, badge)
        if rejected is False:
            return False

        if isinstance(rejected, (list, tuple)):
            for pk in rejected:
                if pk != self.pushkey:
                    # for sanity, we only remove the pushkey if it
                    # was the one we actually sent...
                    logger.warning(
                        ("Ignoring rejected pushkey %s because we didn't send it"),
                        pk,
                    )
                else:
                    logger.info("Pushkey %s was rejected: removing", pk)
                    await self._pusherpool.remove_pusher(self.app_id, pk, self.user_id)
        return True

    async def _build_notification_dict(
        self, event: EventBase, tweaks: Dict[str, bool], badge: int
    ) -> Dict[str, Any]:
        priority = "low"
        if (
            event.type == EventTypes.Encrypted
            or tweaks.get("highlight")
            or tweaks.get("sound")
        ):
            # HACK send our push as high priority only if it generates a sound, highlight
            #  or may do so (i.e. is encrypted so has unknown effects).
            priority = "high"

        # This was checked in the __init__, but mypy doesn't seem to know that.
        assert self.data is not None
        if self.data.get("format") == "event_id_only":
            d = {
                "notification": {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "counts": {"unread": badge},
                    "prio": priority,
                    "devices": [
                        {
                            "app_id": self.app_id,
                            "pushkey": self.pushkey,
                            "pushkey_ts": int(self.pushkey_ts / 1000),
                            "data": self.data_minus_url,
                        }
                    ],
                }
            }
            return d

        ctx = await push_tools.get_context_for_event(self.storage, event, self.user_id)

        d = {
            "notification": {
                "id": event.event_id,  # deprecated: remove soon
                "event_id": event.event_id,
                "room_id": event.room_id,
                "type": event.type,
                "sender": event.user_id,
                "prio": priority,
                "counts": {
                    "unread": badge,
                    # 'missed_calls': 2
                },
                "devices": [
                    {
                        "app_id": self.app_id,
                        "pushkey": self.pushkey,
                        "pushkey_ts": int(self.pushkey_ts / 1000),
                        "data": self.data_minus_url,
                        "tweaks": tweaks,
                    }
                ],
            }
        }
        if event.type == "m.room.member" and event.is_state():
            d["notification"]["membership"] = event.content["membership"]
            d["notification"]["user_is_target"] = event.state_key == self.user_id
        if self.hs.config.push_include_content and event.content:
            d["notification"]["content"] = event.content

        # We no longer send aliases separately, instead, we send the human
        # readable name of the room, which may be an alias.
        if "sender_display_name" in ctx and len(ctx["sender_display_name"]) > 0:
            d["notification"]["sender_display_name"] = ctx["sender_display_name"]
        if "name" in ctx and len(ctx["name"]) > 0:
            d["notification"]["room_name"] = ctx["name"]

        return d

    async def dispatch_push(
        self, event: EventBase, tweaks: Dict[str, bool], badge: int
    ) -> Union[bool, Iterable[str]]:
        notification_dict = await self._build_notification_dict(event, tweaks, badge)
        if not notification_dict:
            return []
        try:
            resp = await self.http_client.post_json_get_json(
                self.url, notification_dict
            )
        except Exception as e:
            logger.warning(
                "Failed to push event %s to %s: %s %s",
                event.event_id,
                self.name,
                type(e),
                e,
            )
            return False
        rejected = []
        if "rejected" in resp:
            rejected = resp["rejected"]
        return rejected

    async def _send_badge(self, badge):
        """
        Args:
            badge (int): number of unread messages
        """
        logger.debug("Sending updated badge count %d to %s", badge, self.name)
        d = {
            "notification": {
                "id": "",
                "type": None,
                "sender": "",
                "counts": {"unread": badge},
                "devices": [
                    {
                        "app_id": self.app_id,
                        "pushkey": self.pushkey,
                        "pushkey_ts": int(self.pushkey_ts / 1000),
                        "data": self.data_minus_url,
                    }
                ],
            }
        }
        try:
            await self.http_client.post_json_get_json(self.url, d)
            http_badges_processed_counter.inc()
        except Exception as e:
            logger.warning(
                "Failed to send badge count to %s: %s %s", self.name, type(e), e
            )
            http_badges_failed_counter.inc()
