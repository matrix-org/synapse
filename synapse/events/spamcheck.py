# Copyright 2017 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from synapse.util.async_helpers import delay_cancellation, maybe_awaitable
from synapse.util.metrics import Measure

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


class SpamChecker:
    NOT_SPAM: Literal["NOT_SPAM"] = "NOT_SPAM"

    def __init__(self, hs: "synapse.server.HomeServer") -> None:
        self.hs = hs
        self.clock = hs.get_clock()

        self._check_event_for_spam_callbacks: List[CHECK_EVENT_FOR_SPAM_CALLBACK] = []
        self._should_drop_federated_event_callbacks: List[
            SHOULD_DROP_FEDERATED_EVENT_CALLBACK
        ] = []
        self._user_may_join_room_callbacks: List[USER_MAY_JOIN_ROOM_CALLBACK] = []
        self._user_may_invite_callbacks: List[USER_MAY_INVITE_CALLBACK] = []
        self._user_may_send_3pid_invite_callbacks: List[
            USER_MAY_SEND_3PID_INVITE_CALLBACK
        ] = []
        self._user_may_create_room_callbacks: List[USER_MAY_CREATE_ROOM_CALLBACK] = []
        self._user_may_create_room_alias_callbacks: List[
            USER_MAY_CREATE_ROOM_ALIAS_CALLBACK
        ] = []
        self._user_may_publish_room_callbacks: List[USER_MAY_PUBLISH_ROOM_CALLBACK] = []
        self._check_username_for_spam_callbacks: List[
            CHECK_USERNAME_FOR_SPAM_CALLBACK
        ] = []
        self._check_registration_for_spam_callbacks: List[
            CHECK_REGISTRATION_FOR_SPAM_CALLBACK
        ] = []
        self._check_media_file_for_spam_callbacks: List[
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
            self._check_event_for_spam_callbacks.append(check_event_for_spam)

        if should_drop_federated_event is not None:
            self._should_drop_federated_event_callbacks.append(
                should_drop_federated_event
            )

        if user_may_join_room is not None:
            self._user_may_join_room_callbacks.append(user_may_join_room)

        if user_may_invite is not None:
            self._user_may_invite_callbacks.append(user_may_invite)

        if user_may_send_3pid_invite is not None:
            self._user_may_send_3pid_invite_callbacks.append(
                user_may_send_3pid_invite,
            )

        if user_may_create_room is not None:
            self._user_may_create_room_callbacks.append(user_may_create_room)

        if user_may_create_room_alias is not None:
            self._user_may_create_room_alias_callbacks.append(
                user_may_create_room_alias,
            )

        if user_may_publish_room is not None:
            self._user_may_publish_room_callbacks.append(user_may_publish_room)

        if check_username_for_spam is not None:
            self._check_username_for_spam_callbacks.append(check_username_for_spam)

        if check_registration_for_spam is not None:
            self._check_registration_for_spam_callbacks.append(
                check_registration_for_spam,
            )

        if check_media_file_for_spam is not None:
            self._check_media_file_for_spam_callbacks.append(check_media_file_for_spam)

    async def check_event_for_spam(
        self, event: "synapse.events.EventBase"
    ) -> Union[Tuple[Codes, JsonDict], str]:
        """Checks if a given event is considered "spammy" by this server.

        If the server considers an event spammy, then it will be rejected if
        sent by a local user. If it is sent by a user on another server, the
        event is soft-failed.

        Args:
            event: the event to be checked

        Returns:
            - `NOT_SPAM` if the event is considered good (non-spammy) and should be let
                through. Other spamcheck filters may still reject it.
            - A `Code` if the event is considered spammy and is rejected with a specific
                error message/code.
            - A string that isn't `NOT_SPAM` if the event is considered spammy and the
                string should be used as the client-facing error message. This usage is
                generally discouraged as it doesn't support internationalization.
        """
        for callback in self._check_event_for_spam_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(callback(event))
                if res is False or res == self.NOT_SPAM:
                    # This spam-checker accepts the event.
                    # Other spam-checkers may reject it, though.
                    continue
                elif res is True:
                    # This spam-checker rejects the event with deprecated
                    # return value `True`
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif not isinstance(res, str):
                    # mypy complains that we can't reach this code because of the
                    # return type in CHECK_EVENT_FOR_SPAM_CALLBACK, but we don't know
                    # for sure that the module actually returns it.
                    logger.warning(
                        "Module returned invalid value, rejecting message as spam"
                    )
                    res = "This message has been rejected as probable spam"
                else:
                    # The module rejected the event either with a `Codes`
                    # or some other `str`. In either case, we stop here.
                    pass

                return res

        # No spam-checker has rejected the event, let it pass.
        return self.NOT_SPAM

    async def should_drop_federated_event(
        self, event: "synapse.events.EventBase"
    ) -> Union[bool, str]:
        """Checks if a given federated event is considered "spammy" by this
        server.

        If the server considers an event spammy, it will be silently dropped,
        and in doing so will split-brain our view of the room's DAG.

        Args:
            event: the event to be checked

        Returns:
            True if the event should be silently dropped
        """
        for callback in self._should_drop_federated_event_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res: Union[bool, str] = await delay_cancellation(callback(event))
            if res:
                return res

        return False

    async def user_may_join_room(
        self, user_id: str, room_id: str, is_invited: bool
    ) -> Union[Tuple[Codes, JsonDict], Literal["NOT_SPAM"]]:
        """Checks if a given users is allowed to join a room.
        Not called when a user creates a room.

        Args:
            userid: The ID of the user wanting to join the room
            room_id: The ID of the room the user wants to join
            is_invited: Whether the user is invited into the room

        Returns:
            NOT_SPAM if the operation is permitted, [Codes, Dict] otherwise.
        """
        for callback in self._user_may_join_room_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(callback(user_id, room_id, is_invited))
                # Normalize return values to `Codes` or `"NOT_SPAM"`.
                if res is True or res is self.NOT_SPAM:
                    continue
                elif res is False:
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                else:
                    logger.warning(
                        "Module returned invalid value, rejecting join as spam"
                    )
                    return synapse.api.errors.Codes.FORBIDDEN, {}

        # No spam-checker has rejected the request, let it pass.
        return self.NOT_SPAM

    async def user_may_invite(
        self, inviter_userid: str, invitee_userid: str, room_id: str
    ) -> Union[Tuple[Codes, dict], Literal["NOT_SPAM"]]:
        """Checks if a given user may send an invite

        Args:
            inviter_userid: The user ID of the sender of the invitation
            invitee_userid: The user ID targeted in the invitation
            room_id: The room ID

        Returns:
            NOT_SPAM if the operation is permitted, Codes otherwise.
        """
        for callback in self._user_may_invite_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(
                    callback(inviter_userid, invitee_userid, room_id)
                )
                # Normalize return values to `Codes` or `"NOT_SPAM"`.
                if res is True or res is self.NOT_SPAM:
                    continue
                elif res is False:
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                else:
                    logger.warning(
                        "Module returned invalid value, rejecting invite as spam"
                    )
                    return synapse.api.errors.Codes.FORBIDDEN, {}

        # No spam-checker has rejected the request, let it pass.
        return self.NOT_SPAM

    async def user_may_send_3pid_invite(
        self, inviter_userid: str, medium: str, address: str, room_id: str
    ) -> Union[Tuple[Codes, dict], Literal["NOT_SPAM"]]:
        """Checks if a given user may invite a given threepid into the room

        Note that if the threepid is already associated with a Matrix user ID, Synapse
        will call user_may_invite with said user ID instead.

        Args:
            inviter_userid: The user ID of the sender of the invitation
            medium: The 3PID's medium (e.g. "email")
            address: The 3PID's address (e.g. "alice@example.com")
            room_id: The room ID

        Returns:
            NOT_SPAM if the operation is permitted, Codes otherwise.
        """
        for callback in self._user_may_send_3pid_invite_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(
                    callback(inviter_userid, medium, address, room_id)
                )
                # Normalize return values to `Codes` or `"NOT_SPAM"`.
                if res is True or res is self.NOT_SPAM:
                    continue
                elif res is False:
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                else:
                    logger.warning(
                        "Module returned invalid value, rejecting 3pid invite as spam"
                    )
                    return synapse.api.errors.Codes.FORBIDDEN, {}

        return self.NOT_SPAM

    async def user_may_create_room(
        self, userid: str
    ) -> Union[Tuple[Codes, dict], Literal["NOT_SPAM"]]:
        """Checks if a given user may create a room

        Args:
            userid: The ID of the user attempting to create a room
        """
        for callback in self._user_may_create_room_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(callback(userid))
                if res is True or res is self.NOT_SPAM:
                    continue
                elif res is False:
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                else:
                    logger.warning(
                        "Module returned invalid value, rejecting room creation as spam"
                    )
                    return synapse.api.errors.Codes.FORBIDDEN, {}

        return self.NOT_SPAM

    async def user_may_create_room_alias(
        self, userid: str, room_alias: RoomAlias
    ) -> Union[Tuple[Codes, dict], Literal["NOT_SPAM"]]:
        """Checks if a given user may create a room alias

        Args:
            userid: The ID of the user attempting to create a room alias
            room_alias: The alias to be created

        """
        for callback in self._user_may_create_room_alias_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(callback(userid, room_alias))
                if res is True or res is self.NOT_SPAM:
                    continue
                elif res is False:
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                else:
                    logger.warning(
                        "Module returned invalid value, rejecting room create as spam"
                    )
                    return synapse.api.errors.Codes.FORBIDDEN, {}

        return self.NOT_SPAM

    async def user_may_publish_room(
        self, userid: str, room_id: str
    ) -> Union[Tuple[Codes, dict], Literal["NOT_SPAM"]]:
        """Checks if a given user may publish a room to the directory

        Args:
            userid: The user ID attempting to publish the room
            room_id: The ID of the room that would be published
        """
        for callback in self._user_may_publish_room_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(callback(userid, room_id))
                if res is True or res is self.NOT_SPAM:
                    continue
                elif res is False:
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                else:
                    logger.warning(
                        "Module returned invalid value, rejecting room publication as spam"
                    )
                    return synapse.api.errors.Codes.FORBIDDEN, {}

        return self.NOT_SPAM

    async def check_username_for_spam(self, user_profile: UserProfile) -> bool:
        """Checks if a user ID or display name are considered "spammy" by this server.

        If the server considers a username spammy, then it will not be included in
        user directory results.

        Args:
            user_profile: The user information to check, it contains the keys:
                * user_id
                * display_name
                * avatar_url

        Returns:
            True if the user is spammy.
        """
        for callback in self._check_username_for_spam_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                # Make a copy of the user profile object to ensure the spam checker cannot
                # modify it.
                res = await delay_cancellation(callback(user_profile.copy()))
            if res:
                return True

        return False

    async def check_registration_for_spam(
        self,
        email_threepid: Optional[dict],
        username: Optional[str],
        request_info: Collection[Tuple[str, str]],
        auth_provider_id: Optional[str] = None,
    ) -> RegistrationBehaviour:
        """Checks if we should allow the given registration request.

        Args:
            email_threepid: The email threepid used for registering, if any
            username: The request user name, if any
            request_info: List of tuples of user agent and IP that
                were used during the registration process.
            auth_provider_id: The SSO IdP the user used, e.g "oidc", "saml",
                "cas". If any. Note this does not include users registered
                via a password provider.

        Returns:
            Enum for how the request should be handled
        """

        for callback in self._check_registration_for_spam_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                behaviour = await delay_cancellation(
                    callback(email_threepid, username, request_info, auth_provider_id)
                )
            assert isinstance(behaviour, RegistrationBehaviour)
            if behaviour != RegistrationBehaviour.ALLOW:
                return behaviour

        return RegistrationBehaviour.ALLOW

    async def check_media_file_for_spam(
        self, file_wrapper: ReadableFileWrapper, file_info: FileInfo
    ) -> Union[Tuple[Codes, dict], Literal["NOT_SPAM"]]:
        """Checks if a piece of newly uploaded media should be blocked.

        This will be called for local uploads, downloads of remote media, each
        thumbnail generated for those, and web pages/images used for URL
        previews.

        Note that care should be taken to not do blocking IO operations in the
        main thread. For example, to get the contents of a file a module
        should do::

            async def check_media_file_for_spam(
                self, file: ReadableFileWrapper, file_info: FileInfo
            ) -> Union[Codes, Literal["NOT_SPAM"]]:
                buffer = BytesIO()
                await file.write_chunks_to(buffer.write)

                if buffer.getvalue() == b"Hello World":
                    return synapse.module_api.NOT_SPAM

                return Codes.FORBIDDEN


        Args:
            file: An object that allows reading the contents of the media.
            file_info: Metadata about the file.
        """

        for callback in self._check_media_file_for_spam_callbacks:
            with Measure(
                self.clock, "{}.{}".format(callback.__module__, callback.__qualname__)
            ):
                res = await delay_cancellation(callback(file_wrapper, file_info))
                # Normalize return values to `Codes` or `"NOT_SPAM"`.
                if res is False or res is self.NOT_SPAM:
                    continue
                elif res is True:
                    return synapse.api.errors.Codes.FORBIDDEN, {}
                elif isinstance(res, synapse.api.errors.Codes):
                    return res, {}
                elif (
                    isinstance(res, tuple)
                    and len(res) == 2
                    and isinstance(res[0], synapse.api.errors.Codes)
                    and isinstance(res[1], dict)
                ):
                    return res
                else:
                    logger.warning(
                        "Module returned invalid value, rejecting media file as spam"
                    )
                    return synapse.api.errors.Codes.FORBIDDEN, {}

        return self.NOT_SPAM
