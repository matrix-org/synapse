# Copyright 2017 New Vector Ltd
# Copyright 2019, 2023 The Matrix.org Foundation C.I.C.
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
import inspect
import logging
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Collection,
    List,
    Optional,
    Tuple,
    Union,
)

# `Literal` appears with Python 3.8.
from typing_extensions import Literal

import synapse
from synapse.api.errors import Codes
from synapse.rest.media.v1._base import FileInfo
from synapse.rest.media.v1.media_storage import ReadableFileWrapper
from synapse.spam_checker_api import RegistrationBehaviour
from synapse.types import JsonDict, RoomAlias, UserProfile
from synapse.util.async_helpers import maybe_awaitable

if TYPE_CHECKING:
    import synapse.events
    import synapse.server

logger = logging.getLogger(__name__)


CHECK_EVENT_FOR_SPAM_CALLBACK = Callable[
    ["synapse.events.EventBase"],
    Awaitable[
        Union[
            str,
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]
SHOULD_DROP_FEDERATED_EVENT_CALLBACK = Callable[
    ["synapse.events.EventBase"],
    Awaitable[Union[bool, str]],
]
USER_MAY_JOIN_ROOM_CALLBACK = Callable[
    [str, str, bool],
    Awaitable[
        Union[
            Literal["NOT_SPAM"],
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]
USER_MAY_INVITE_CALLBACK = Callable[
    [str, str, str],
    Awaitable[
        Union[
            Literal["NOT_SPAM"],
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]
USER_MAY_SEND_3PID_INVITE_CALLBACK = Callable[
    [str, str, str, str],
    Awaitable[
        Union[
            Literal["NOT_SPAM"],
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]
USER_MAY_CREATE_ROOM_CALLBACK = Callable[
    [str],
    Awaitable[
        Union[
            Literal["NOT_SPAM"],
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]
USER_MAY_CREATE_ROOM_ALIAS_CALLBACK = Callable[
    [str, RoomAlias],
    Awaitable[
        Union[
            Literal["NOT_SPAM"],
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]
USER_MAY_PUBLISH_ROOM_CALLBACK = Callable[
    [str, str],
    Awaitable[
        Union[
            Literal["NOT_SPAM"],
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]
CHECK_USERNAME_FOR_SPAM_CALLBACK = Callable[[UserProfile], Awaitable[bool]]
LEGACY_CHECK_REGISTRATION_FOR_SPAM_CALLBACK = Callable[
    [
        Optional[dict],
        Optional[str],
        Collection[Tuple[str, str]],
    ],
    Awaitable[RegistrationBehaviour],
]
CHECK_REGISTRATION_FOR_SPAM_CALLBACK = Callable[
    [
        Optional[dict],
        Optional[str],
        Collection[Tuple[str, str]],
        Optional[str],
    ],
    Awaitable[RegistrationBehaviour],
]
CHECK_MEDIA_FILE_FOR_SPAM_CALLBACK = Callable[
    [ReadableFileWrapper, FileInfo],
    Awaitable[
        Union[
            Literal["NOT_SPAM"],
            Codes,
            # Highly experimental, not officially part of the spamchecker API, may
            # disappear without warning depending on the results of ongoing
            # experiments.
            # Use this to return additional information as part of an error.
            Tuple[Codes, JsonDict],
            # Deprecated
            bool,
        ]
    ],
]


def load_legacy_spam_checkers(hs: "synapse.server.HomeServer") -> None:
    """Wrapper that loads spam checkers configured using the old configuration, and
    registers the spam checker hooks they implement.
    """
    spam_checkers: List[Any] = []
    api = hs.get_module_api()
    for module, config in hs.config.spamchecker.spam_checkers:
        # Older spam checkers don't accept the `api` argument, so we
        # try and detect support.
        spam_args = inspect.getfullargspec(module)
        if "api" in spam_args.args:
            spam_checkers.append(module(config=config, api=api))
        else:
            spam_checkers.append(module(config=config))

    # The known spam checker hooks. If a spam checker module implements a method
    # which name appears in this set, we'll want to register it.
    spam_checker_methods = {
        "check_event_for_spam",
        "user_may_invite",
        "user_may_create_room",
        "user_may_create_room_alias",
        "user_may_publish_room",
        "check_username_for_spam",
        "check_registration_for_spam",
        "check_media_file_for_spam",
    }

    for spam_checker in spam_checkers:
        # Methods on legacy spam checkers might not be async, so we wrap them around a
        # wrapper that will call maybe_awaitable on the result.
        def async_wrapper(f: Optional[Callable]) -> Optional[Callable[..., Awaitable]]:
            # f might be None if the callback isn't implemented by the module. In this
            # case we don't want to register a callback at all so we return None.
            if f is None:
                return None

            wrapped_func = f

            if f.__name__ == "check_registration_for_spam":
                checker_args = inspect.signature(f)
                if len(checker_args.parameters) == 3:
                    # Backwards compatibility; some modules might implement a hook that
                    # doesn't expect a 4th argument. In this case, wrap it in a function
                    # that gives it only 3 arguments and drops the auth_provider_id on
                    # the floor.
                    def wrapper(
                        email_threepid: Optional[dict],
                        username: Optional[str],
                        request_info: Collection[Tuple[str, str]],
                        auth_provider_id: Optional[str],
                    ) -> Union[Awaitable[RegistrationBehaviour], RegistrationBehaviour]:
                        # Assertion required because mypy can't prove we won't
                        # change `f` back to `None`. See
                        # https://mypy.readthedocs.io/en/latest/common_issues.html#narrowing-and-inner-functions
                        assert f is not None

                        return f(
                            email_threepid,
                            username,
                            request_info,
                        )

                    wrapped_func = wrapper
                elif len(checker_args.parameters) != 4:
                    raise RuntimeError(
                        "Bad signature for callback check_registration_for_spam",
                    )

            def run(*args: Any, **kwargs: Any) -> Awaitable:
                # Assertion required because mypy can't prove we won't change `f`
                # back to `None`. See
                # https://mypy.readthedocs.io/en/latest/common_issues.html#narrowing-and-inner-functions
                assert wrapped_func is not None

                return maybe_awaitable(wrapped_func(*args, **kwargs))

            return run

        # Register the hooks through the module API.
        hooks = {
            hook: async_wrapper(getattr(spam_checker, hook, None))
            for hook in spam_checker_methods
        }

        api.register_spam_checker_callbacks(**hooks)


class SpamCheckerModuleApiCallbacks:
    def __init__(self) -> None:
        self.check_event_for_spam_callbacks: List[CHECK_EVENT_FOR_SPAM_CALLBACK] = []
        self.should_drop_federated_event_callbacks: List[
            SHOULD_DROP_FEDERATED_EVENT_CALLBACK
        ] = []
        self.user_may_join_room_callbacks: List[USER_MAY_JOIN_ROOM_CALLBACK] = []
        self.user_may_invite_callbacks: List[USER_MAY_INVITE_CALLBACK] = []
        self.user_may_send_3pid_invite_callbacks: List[
            USER_MAY_SEND_3PID_INVITE_CALLBACK
        ] = []
        self.user_may_create_room_callbacks: List[USER_MAY_CREATE_ROOM_CALLBACK] = []
        self.user_may_create_room_alias_callbacks: List[
            USER_MAY_CREATE_ROOM_ALIAS_CALLBACK
        ] = []
        self.user_may_publish_room_callbacks: List[USER_MAY_PUBLISH_ROOM_CALLBACK] = []
        self.check_username_for_spam_callbacks: List[
            CHECK_USERNAME_FOR_SPAM_CALLBACK
        ] = []
        self.check_registration_for_spam_callbacks: List[
            CHECK_REGISTRATION_FOR_SPAM_CALLBACK
        ] = []
        self.check_media_file_for_spam_callbacks: List[
            CHECK_MEDIA_FILE_FOR_SPAM_CALLBACK
        ] = []

    def register_callbacks(
        self,
        check_event_for_spam: Optional[CHECK_EVENT_FOR_SPAM_CALLBACK] = None,
        should_drop_federated_event: Optional[
            SHOULD_DROP_FEDERATED_EVENT_CALLBACK
        ] = None,
        user_may_join_room: Optional[USER_MAY_JOIN_ROOM_CALLBACK] = None,
        user_may_invite: Optional[USER_MAY_INVITE_CALLBACK] = None,
        user_may_send_3pid_invite: Optional[USER_MAY_SEND_3PID_INVITE_CALLBACK] = None,
        user_may_create_room: Optional[USER_MAY_CREATE_ROOM_CALLBACK] = None,
        user_may_create_room_alias: Optional[
            USER_MAY_CREATE_ROOM_ALIAS_CALLBACK
        ] = None,
        user_may_publish_room: Optional[USER_MAY_PUBLISH_ROOM_CALLBACK] = None,
        check_username_for_spam: Optional[CHECK_USERNAME_FOR_SPAM_CALLBACK] = None,
        check_registration_for_spam: Optional[
            CHECK_REGISTRATION_FOR_SPAM_CALLBACK
        ] = None,
        check_media_file_for_spam: Optional[CHECK_MEDIA_FILE_FOR_SPAM_CALLBACK] = None,
    ) -> None:
        """Register callbacks from module for each hook."""
        if check_event_for_spam is not None:
            self.check_event_for_spam_callbacks.append(check_event_for_spam)

        if should_drop_federated_event is not None:
            self.should_drop_federated_event_callbacks.append(
                should_drop_federated_event
            )

        if user_may_join_room is not None:
            self.user_may_join_room_callbacks.append(user_may_join_room)

        if user_may_invite is not None:
            self.user_may_invite_callbacks.append(user_may_invite)

        if user_may_send_3pid_invite is not None:
            self.user_may_send_3pid_invite_callbacks.append(
                user_may_send_3pid_invite,
            )

        if user_may_create_room is not None:
            self.user_may_create_room_callbacks.append(user_may_create_room)

        if user_may_create_room_alias is not None:
            self.user_may_create_room_alias_callbacks.append(
                user_may_create_room_alias,
            )

        if user_may_publish_room is not None:
            self.user_may_publish_room_callbacks.append(user_may_publish_room)

        if check_username_for_spam is not None:
            self.check_username_for_spam_callbacks.append(check_username_for_spam)

        if check_registration_for_spam is not None:
            self.check_registration_for_spam_callbacks.append(
                check_registration_for_spam,
            )

        if check_media_file_for_spam is not None:
            self.check_media_file_for_spam_callbacks.append(check_media_file_for_spam)
