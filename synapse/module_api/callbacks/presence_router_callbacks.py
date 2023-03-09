# Copyright 2021, 2023 The Matrix.org Foundation C.I.C.
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
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    TypeVar,
    Union,
)

from typing_extensions import ParamSpec

from synapse.api.presence import UserPresenceState
from synapse.util.async_helpers import maybe_awaitable

if TYPE_CHECKING:
    from synapse.server import HomeServer

GET_USERS_FOR_STATES_CALLBACK = Callable[
    [Iterable[UserPresenceState]], Awaitable[Dict[str, Set[UserPresenceState]]]
]
# This must either return a set of strings or the constant PresenceRouter.ALL_USERS.
GET_INTERESTED_USERS_CALLBACK = Callable[[str], Awaitable[Union[Set[str], str]]]


P = ParamSpec("P")
R = TypeVar("R")


def load_legacy_presence_router(hs: "HomeServer") -> None:
    """Wrapper that loads a presence router module configured using the old
    configuration, and registers the hooks they implement.
    """

    if hs.config.server.presence_router_module_class is None:
        return

    module = hs.config.server.presence_router_module_class
    config = hs.config.server.presence_router_config
    api = hs.get_module_api()

    presence_router = module(config=config, module_api=api)

    # The known hooks. If a module implements a method which name appears in this set,
    # we'll want to register it.
    presence_router_methods = {
        "get_users_for_states",
        "get_interested_users",
    }

    # All methods that the module provides should be async, but this wasn't enforced
    # in the old module system, so we wrap them if needed
    def async_wrapper(
        f: Optional[Callable[P, R]]
    ) -> Optional[Callable[P, Awaitable[R]]]:
        # f might be None if the callback isn't implemented by the module. In this
        # case we don't want to register a callback at all so we return None.
        if f is None:
            return None

        def run(*args: P.args, **kwargs: P.kwargs) -> Awaitable[R]:
            # Assertion required because mypy can't prove we won't change `f`
            # back to `None`. See
            # https://mypy.readthedocs.io/en/latest/common_issues.html#narrowing-and-inner-functions
            assert f is not None

            return maybe_awaitable(f(*args, **kwargs))

        return run

    # Register the hooks through the module API.
    hooks: Dict[str, Optional[Callable[..., Any]]] = {
        hook: async_wrapper(getattr(presence_router, hook, None))
        for hook in presence_router_methods
    }

    api.register_presence_router_callbacks(**hooks)


class PresenceRouterModuleApiCallbacks:
    def __init__(self) -> None:
        # Initially there are no callbacks
        self.get_users_for_states_callbacks: List[GET_USERS_FOR_STATES_CALLBACK] = []
        self.get_interested_users_callbacks: List[GET_INTERESTED_USERS_CALLBACK] = []

    def register_callbacks(
        self,
        get_users_for_states: Optional[GET_USERS_FOR_STATES_CALLBACK] = None,
        get_interested_users: Optional[GET_INTERESTED_USERS_CALLBACK] = None,
    ) -> None:
        # PresenceRouter modules are required to implement both of these methods
        # or neither of them as they are assumed to act in a complementary manner
        paired_methods = [get_users_for_states, get_interested_users]
        if paired_methods.count(None) == 1:
            raise RuntimeError(
                "PresenceRouter modules must register neither or both of the paired callbacks: "
                "[get_users_for_states, get_interested_users]"
            )

        # Append the methods provided to the lists of callbacks
        if get_users_for_states is not None:
            self.get_users_for_states_callbacks.append(get_users_for_states)

        if get_interested_users is not None:
            self.get_interested_users_callbacks.append(get_interested_users)
