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
import logging

from twisted.internet import defer

from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.util.async_helpers import maybe_awaitable

logger = logging.getLogger(__name__)


def user_left_room(distributor, user, room_id):
    distributor.fire("user_left_room", user=user, room_id=room_id)


class Distributor:
    """A central dispatch point for loosely-connected pieces of code to
    register, observe, and fire signals.

    Signals are named simply by strings.

    TODO(paul): It would be nice to give signals stronger object identities,
      so we can attach metadata, docstrings, detect typos, etc... But this
      model will do for today.
    """

    def __init__(self):
        self.signals = {}
        self.pre_registration = {}

    def declare(self, name):
        if name in self.signals:
            raise KeyError("%r already has a signal named %s" % (self, name))

        self.signals[name] = Signal(name)

        if name in self.pre_registration:
            signal = self.signals[name]
            for observer in self.pre_registration[name]:
                signal.observe(observer)

    def observe(self, name, observer):
        if name in self.signals:
            self.signals[name].observe(observer)
        else:
            # TODO: Avoid strong ordering dependency by allowing people to
            # pre-register observations on signals that don't exist yet.
            if name not in self.pre_registration:
                self.pre_registration[name] = []
            self.pre_registration[name].append(observer)

    def fire(self, name, *args, **kwargs):
        """Dispatches the given signal to the registered observers.

        Runs the observers as a background process. Does not return a deferred.
        """
        if name not in self.signals:
            raise KeyError("%r does not have a signal named %s" % (self, name))

        run_as_background_process(name, self.signals[name].fire, *args, **kwargs)


class Signal:
    """A Signal is a dispatch point that stores a list of callables as
    observers of it.

    Signals can be "fired", meaning that every callable observing it is
    invoked. Firing a signal does not change its state; it can be fired again
    at any later point. Firing a signal passes any arguments from the fire
    method into all of the observers.
    """

    def __init__(self, name):
        self.name = name
        self.observers = []

    def observe(self, observer):
        """Adds a new callable to the observer list which will be invoked by
        the 'fire' method.

        Each observer callable may return a Deferred."""
        self.observers.append(observer)

    def fire(self, *args, **kwargs):
        """Invokes every callable in the observer list, passing in the args and
        kwargs. Exceptions thrown by observers are logged but ignored. It is
        not an error to fire a signal with no observers.

        Returns a Deferred that will complete when all the observers have
        completed."""

        async def do(observer):
            try:
                return await maybe_awaitable(observer(*args, **kwargs))
            except Exception as e:
                logger.warning(
                    "%s signal observer %s failed: %r",
                    self.name,
                    observer,
                    e,
                )

        deferreds = [run_in_background(do, o) for o in self.observers]

        return make_deferred_yieldable(
            defer.gatherResults(deferreds, consumeErrors=True)
        )

    def __repr__(self):
        return "<Signal name=%r>" % (self.name,)
