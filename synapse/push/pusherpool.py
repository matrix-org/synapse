#!/usr/bin/env python
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

import logging
from typing import TYPE_CHECKING, Dict, Iterable, Optional

from prometheus_client import Gauge

from synapse.api.errors import Codes, SynapseError
from synapse.metrics.background_process_metrics import (
    run_as_background_process,
    wrap_as_background_process,
)
from synapse.push import Pusher, PusherConfig, PusherConfigException
from synapse.push.pusher import PusherFactory
from synapse.replication.http.push import ReplicationRemovePusherRestServlet
from synapse.types import JsonDict, RoomStreamToken
from synapse.util.async_helpers import concurrently_execute

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


synapse_pushers = Gauge(
    "synapse_pushers", "Number of active synapse pushers", ["kind", "app_id"]
)


class PusherPool:
    """
    The pusher pool. This is responsible for dispatching notifications of new events to
    the http and email pushers.

    It provides three methods which are designed to be called by the rest of the
    application: `start`, `on_new_notifications`, and `on_new_receipts`: each of these
    delegates to each of the relevant pushers.

    Note that it is expected that each pusher will have its own 'processing' loop which
    will send out the notifications in the background, rather than blocking until the
    notifications are sent; accordingly Pusher.on_started, Pusher.on_new_notifications and
    Pusher.on_new_receipts are not expected to return awaitables.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.pusher_factory = PusherFactory(hs)
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()

        self._account_validity = hs.config.account_validity

        # We shard the handling of push notifications by user ID.
        self._pusher_shard_config = hs.config.push.pusher_shard_config
        self._instance_name = hs.get_instance_name()
        self._should_start_pushers = (
            self._instance_name in self._pusher_shard_config.instances
        )

        # We can only delete pushers on master.
        self._remove_pusher_client = None
        if hs.config.worker.worker_app:
            self._remove_pusher_client = ReplicationRemovePusherRestServlet.make_client(
                hs
            )

        # Record the last stream ID that we were poked about so we can get
        # changes since then. We set this to the current max stream ID on
        # startup as every individual pusher will have checked for changes on
        # startup.
        self._last_room_stream_id_seen = self.store.get_room_max_stream_ordering()

        # map from user id to app_id:pushkey to pusher
        self.pushers = {}  # type: Dict[str, Dict[str, Pusher]]

    def start(self) -> None:
        """Starts the pushers off in a background process."""
        if not self._should_start_pushers:
            logger.info("Not starting pushers because they are disabled in the config")
            return
        run_as_background_process("start_pushers", self._start_pushers)

    async def add_pusher(
        self,
        user_id: str,
        access_token: Optional[int],
        kind: str,
        app_id: str,
        app_display_name: str,
        device_display_name: str,
        pushkey: str,
        lang: Optional[str],
        data: JsonDict,
        profile_tag: str = "",
    ) -> Optional[Pusher]:
        """Creates a new pusher and adds it to the pool

        Returns:
            The newly created pusher.
        """

        if kind == "email":
            email_owner = await self.store.get_user_id_by_threepid("email", pushkey)
            if email_owner != user_id:
                raise SynapseError(400, "Email not found", Codes.THREEPID_NOT_FOUND)

        time_now_msec = self.clock.time_msec()

        # create the pusher setting last_stream_ordering to the current maximum
        # stream ordering, so it will process pushes from this point onwards.
        last_stream_ordering = self.store.get_room_max_stream_ordering()

        # we try to create the pusher just to validate the config: it
        # will then get pulled out of the database,
        # recreated, added and started: this means we have only one
        # code path adding pushers.
        self.pusher_factory.create_pusher(
            PusherConfig(
                id=None,
                user_name=user_id,
                access_token=access_token,
                profile_tag=profile_tag,
                kind=kind,
                app_id=app_id,
                app_display_name=app_display_name,
                device_display_name=device_display_name,
                pushkey=pushkey,
                ts=time_now_msec,
                lang=lang,
                data=data,
                last_stream_ordering=last_stream_ordering,
                last_success=None,
                failing_since=None,
            )
        )

        await self.store.add_pusher(
            user_id=user_id,
            access_token=access_token,
            kind=kind,
            app_id=app_id,
            app_display_name=app_display_name,
            device_display_name=device_display_name,
            pushkey=pushkey,
            pushkey_ts=time_now_msec,
            lang=lang,
            data=data,
            last_stream_ordering=last_stream_ordering,
            profile_tag=profile_tag,
        )
        pusher = await self.start_pusher_by_id(app_id, pushkey, user_id)

        return pusher

    async def remove_pushers_by_app_id_and_pushkey_not_user(
        self, app_id: str, pushkey: str, not_user_id: str
    ) -> None:
        to_remove = await self.store.get_pushers_by_app_id_and_pushkey(app_id, pushkey)
        for p in to_remove:
            if p.user_name != not_user_id:
                logger.info(
                    "Removing pusher for app id %s, pushkey %s, user %s",
                    app_id,
                    pushkey,
                    p.user_name,
                )
                await self.remove_pusher(p.app_id, p.pushkey, p.user_name)

    async def remove_pushers_by_access_token(
        self, user_id: str, access_tokens: Iterable[int]
    ) -> None:
        """Remove the pushers for a given user corresponding to a set of
        access_tokens.

        Args:
            user_id: user to remove pushers for
            access_tokens: access token *ids* to remove pushers for
        """
        tokens = set(access_tokens)
        for p in await self.store.get_pushers_by_user_id(user_id):
            if p.access_token in tokens:
                logger.info(
                    "Removing pusher for app id %s, pushkey %s, user %s",
                    p.app_id,
                    p.pushkey,
                    p.user_name,
                )
                await self.remove_pusher(p.app_id, p.pushkey, p.user_name)

    def on_new_notifications(self, max_token: RoomStreamToken) -> None:
        if not self.pushers:
            # nothing to do here.
            return

        # We just use the minimum stream ordering and ignore the vector clock
        # component. This is safe to do as long as we *always* ignore the vector
        # clock components.
        max_stream_id = max_token.stream

        if max_stream_id < self._last_room_stream_id_seen:
            # Nothing to do
            return

        # We only start a new background process if necessary rather than
        # optimistically (to cut down on overhead).
        self._on_new_notifications(max_token)

    @wrap_as_background_process("on_new_notifications")
    async def _on_new_notifications(self, max_token: RoomStreamToken) -> None:
        # We just use the minimum stream ordering and ignore the vector clock
        # component. This is safe to do as long as we *always* ignore the vector
        # clock components.
        max_stream_id = max_token.stream

        prev_stream_id = self._last_room_stream_id_seen
        self._last_room_stream_id_seen = max_stream_id

        try:
            users_affected = await self.store.get_push_action_users_in_range(
                prev_stream_id, max_stream_id
            )

            for u in users_affected:
                # Don't push if the user account has expired
                if self._account_validity.enabled:
                    expired = await self.store.is_account_expired(
                        u, self.clock.time_msec()
                    )
                    if expired:
                        continue

                if u in self.pushers:
                    for p in self.pushers[u].values():
                        p.on_new_notifications(max_token)

        except Exception:
            logger.exception("Exception in pusher on_new_notifications")

    async def on_new_receipts(
        self, min_stream_id: int, max_stream_id: int, affected_room_ids: Iterable[str]
    ) -> None:
        if not self.pushers:
            # nothing to do here.
            return

        try:
            # Need to subtract 1 from the minimum because the lower bound here
            # is not inclusive
            users_affected = await self.store.get_users_sent_receipts_between(
                min_stream_id - 1, max_stream_id
            )

            for u in users_affected:
                # Don't push if the user account has expired
                if self._account_validity.enabled:
                    expired = await self.store.is_account_expired(
                        u, self.clock.time_msec()
                    )
                    if expired:
                        continue

                if u in self.pushers:
                    for p in self.pushers[u].values():
                        p.on_new_receipts(min_stream_id, max_stream_id)

        except Exception:
            logger.exception("Exception in pusher on_new_receipts")

    async def start_pusher_by_id(
        self, app_id: str, pushkey: str, user_id: str
    ) -> Optional[Pusher]:
        """Look up the details for the given pusher, and start it

        Returns:
            The pusher started, if any
        """
        if not self._should_start_pushers:
            return None

        if not self._pusher_shard_config.should_handle(self._instance_name, user_id):
            return None

        resultlist = await self.store.get_pushers_by_app_id_and_pushkey(app_id, pushkey)

        pusher_config = None
        for r in resultlist:
            if r.user_name == user_id:
                pusher_config = r

        pusher = None
        if pusher_config:
            pusher = await self._start_pusher(pusher_config)

        return pusher

    async def _start_pushers(self) -> None:
        """Start all the pushers"""
        pushers = await self.store.get_all_pushers()

        # Stagger starting up the pushers so we don't completely drown the
        # process on start up.
        await concurrently_execute(self._start_pusher, pushers, 10)

        logger.info("Started pushers")

    async def _start_pusher(self, pusher_config: PusherConfig) -> Optional[Pusher]:
        """Start the given pusher

        Args:
            pusher_config: The pusher configuration with the values pulled from the db table

        Returns:
            The newly created pusher or None.
        """
        if not self._pusher_shard_config.should_handle(
            self._instance_name, pusher_config.user_name
        ):
            return None

        try:
            p = self.pusher_factory.create_pusher(pusher_config)
        except PusherConfigException as e:
            logger.warning(
                "Pusher incorrectly configured id=%i, user=%s, appid=%s, pushkey=%s: %s",
                pusher_config.id,
                pusher_config.user_name,
                pusher_config.app_id,
                pusher_config.pushkey,
                e,
            )
            return None
        except Exception:
            logger.exception(
                "Couldn't start pusher id %i: caught Exception",
                pusher_config.id,
            )
            return None

        if not p:
            return None

        appid_pushkey = "%s:%s" % (pusher_config.app_id, pusher_config.pushkey)

        byuser = self.pushers.setdefault(pusher_config.user_name, {})
        if appid_pushkey in byuser:
            byuser[appid_pushkey].on_stop()
        byuser[appid_pushkey] = p

        synapse_pushers.labels(type(p).__name__, p.app_id).inc()

        # Check if there *may* be push to process. We do this as this check is a
        # lot cheaper to do than actually fetching the exact rows we need to
        # push.
        user_id = pusher_config.user_name
        last_stream_ordering = pusher_config.last_stream_ordering
        if last_stream_ordering:
            have_notifs = await self.store.get_if_maybe_push_in_range_for_user(
                user_id, last_stream_ordering
            )
        else:
            # We always want to default to starting up the pusher rather than
            # risk missing push.
            have_notifs = True

        p.on_started(have_notifs)

        return p

    async def remove_pusher(self, app_id: str, pushkey: str, user_id: str) -> None:
        appid_pushkey = "%s:%s" % (app_id, pushkey)

        byuser = self.pushers.get(user_id, {})

        if appid_pushkey in byuser:
            logger.info("Stopping pusher %s / %s", user_id, appid_pushkey)
            pusher = byuser.pop(appid_pushkey)
            pusher.on_stop()

            synapse_pushers.labels(type(pusher).__name__, pusher.app_id).dec()

        # We can only delete pushers on master.
        if self._remove_pusher_client:
            await self._remove_pusher_client(
                app_id=app_id, pushkey=pushkey, user_id=user_id
            )
        else:
            await self.store.delete_pusher_by_app_id_pushkey_user_id(
                app_id, pushkey, user_id
            )
