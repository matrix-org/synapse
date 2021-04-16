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
from typing import TYPE_CHECKING, Any, Dict, Optional

from synapse.types import RoomStreamToken

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer


class Pusher(metaclass=abc.ABCMeta):
    def __init__(self, hs: "HomeServer", pusherdict: Dict[str, Any]):
        self.hs = hs
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()

        self.pusher_id = pusherdict["id"]
        self.user_id = pusherdict["user_name"]
        self.app_id = pusherdict["app_id"]
        self.pushkey = pusherdict["pushkey"]

        # This is the highest stream ordering we know it's safe to process.
        # When new events arrive, we'll be given a window of new events: we
        # should honour this rather than just looking for anything higher
        # because of potential out-of-order event serialisation. This starts
        # off as None though as we don't know any better.
        self.max_stream_ordering = None  # type: Optional[int]

    @abc.abstractmethod
    def on_new_notifications(self, max_token: RoomStreamToken) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def on_new_receipts(self, min_stream_id: int, max_stream_id: int) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def on_started(self, have_notifs: bool) -> None:
        """Called when this pusher has been started.

        Args:
            should_check_for_notifs: Whether we should immediately
                check for push to send. Set to False only if it's known there
                is nothing to send
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def on_stop(self) -> None:
        raise NotImplementedError()


class PusherConfigException(Exception):
    """An error occurred when creating a pusher."""
