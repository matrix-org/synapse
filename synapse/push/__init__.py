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

import attr

from synapse.types import JsonDict, RoomStreamToken

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer


@attr.s(slots=True)
class PusherConfig:
    id = attr.ib(type=Optional[str])
    user_name = attr.ib(type=str)
    access_token = attr.ib(type=Optional[int])
    profile_tag = attr.ib(type=str)
    kind = attr.ib(type=str)
    app_id = attr.ib(type=str)
    app_display_name = attr.ib(type=str)
    device_display_name = attr.ib(type=str)
    pushkey = attr.ib(type=str)
    ts = attr.ib(type=int)
    lang = attr.ib(type=Optional[str])
    data = attr.ib(type=Optional[JsonDict])
    last_stream_ordering = attr.ib(type=Optional[int])
    last_success = attr.ib(type=Optional[int])
    failing_since = attr.ib(type=Optional[int])

    def as_get(self) -> Dict[str, Any]:
        """Information that can be retrieved about a pusher after creation."""
        return {
            "app_display_name": self.app_display_name,
            "app_id": self.app_id,
            "data": self.data,
            "device_display_name": self.device_display_name,
            "kind": self.kind,
            "lang": self.lang,
            "profile_tag": self.profile_tag,
            "pushkey": self.pushkey,
        }


class Pusher(metaclass=abc.ABCMeta):
    def __init__(self, hs: "HomeServer", pusher_config: PusherConfig):
        self.hs = hs
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()

        self.pusher_id = pusher_config.id
        self.user_id = pusher_config.user_name
        self.app_id = pusher_config.app_id
        self.pushkey = pusher_config.pushkey

        self.last_stream_ordering = pusher_config.last_stream_ordering

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
