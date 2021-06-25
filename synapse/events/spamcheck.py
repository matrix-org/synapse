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
    Dict,
    List,
    Optional,
    Tuple,
    Union,
)

from synapse.rest.media.v1._base import FileInfo
from synapse.rest.media.v1.media_storage import ReadableFileWrapper
from synapse.spam_checker_api import RegistrationBehaviour
from synapse.types import RoomAlias
from synapse.util.async_helpers import maybe_awaitable

if TYPE_CHECKING:
    import synapse.events
    import synapse.server

logger = logging.getLogger(__name__)

CHECK_EVENT_FOR_SPAM_CALLBACK = Callable[
    ["synapse.events.EventBase"],
    Awaitable[Union[bool, str]],
]
USER_MAY_INVITE_CALLBACK = Callable[[str, str, str], Awaitable[bool]]
USER_MAY_CREATE_ROOM_CALLBACK = Callable[[str], Awaitable[bool]]
USER_MAY_CREATE_ROOM_ALIAS_CALLBACK = Callable[[str, RoomAlias], Awaitable[bool]]
USER_MAY_PUBLISH_ROOM_CALLBACK = Callable[[str, str], Awaitable[bool]]
CHECK_USERNAME_FOR_SPAM_CALLBACK = Callable[[Dict[str, str]], Awaitable[bool]]
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
    Awaitable[bool],
]


def load_legacy_spam_checkers(hs: "synapse.server.HomeServer"):
    """Wrapper that loads spam checkers configured using the old configuration, and
    registers the spam checker hooks they implement.
    """
    spam_checkers = []  # type: List[Any]
    api = hs.get_module_api()
    for module, config in hs.config.spam_checkers:
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
                        # We've already made sure f is not None above, but mypy doesn't
                        # do well across function boundaries so we need to tell it f is
                        # definitely not None.
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

            def run(*args, **kwargs):
                # mypy doesn't do well across function boundaries so we need to tell it
                # wrapped_func is definitely not None.
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
    def __init__(self):
        self._check_event_for_spam_callbacks: List[CHECK_EVENT_FOR_SPAM_CALLBACK] = []
        self._user_may_invite_callbacks: List[USER_MAY_INVITE_CALLBACK] = []
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
        user_may_invite: Optional[USER_MAY_INVITE_CALLBACK] = None,
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
    ):
        """Register callbacks from module for each hook."""
        if check_event_for_spam is not None:
            self._check_event_for_spam_callbacks.append(check_event_for_spam)

        if user_may_invite is not None:
            self._user_may_invite_callbacks.append(user_may_invite)

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
    ) -> Union[bool, str]:
        """Checks if a given event is considered "spammy" by this server.

        If the server considers an event spammy, then it will be rejected if
        sent by a local user. If it is sent by a user on another server, then
        users receive a blank event.

        Args:
            event: the event to be checked

        Returns:
            True or a string if the event is spammy. If a string is returned it
            will be used as the error message returned to the user.
        """
        for callback in self._check_event_for_spam_callbacks:
            res = await callback(event)  # type: Union[bool, str]
            if res:
                return res

        return False

    async def user_may_invite(
        self, inviter_userid: str, invitee_userid: str, room_id: str
    ) -> bool:
        """Checks if a given user may send an invite

        If this method returns false, the invite will be rejected.

        Args:
            inviter_userid: The user ID of the sender of the invitation
            invitee_userid: The user ID targeted in the invitation
            room_id: The room ID

        Returns:
            True if the user may send an invite, otherwise False
        """
        for callback in self._user_may_invite_callbacks:
            if await callback(inviter_userid, invitee_userid, room_id) is False:
                return False

        return True

    async def user_may_create_room(self, userid: str) -> bool:
        """Checks if a given user may create a room

        If this method returns false, the creation request will be rejected.

        Args:
            userid: The ID of the user attempting to create a room

        Returns:
            True if the user may create a room, otherwise False
        """
        for callback in self._user_may_create_room_callbacks:
            if await callback(userid) is False:
                return False

        return True

    async def user_may_create_room_alias(
        self, userid: str, room_alias: RoomAlias
    ) -> bool:
        """Checks if a given user may create a room alias

        If this method returns false, the association request will be rejected.

        Args:
            userid: The ID of the user attempting to create a room alias
            room_alias: The alias to be created

        Returns:
            True if the user may create a room alias, otherwise False
        """
        for callback in self._user_may_create_room_alias_callbacks:
            if await callback(userid, room_alias) is False:
                return False

        return True

    async def user_may_publish_room(self, userid: str, room_id: str) -> bool:
        """Checks if a given user may publish a room to the directory

        If this method returns false, the publish request will be rejected.

        Args:
            userid: The user ID attempting to publish the room
            room_id: The ID of the room that would be published

        Returns:
            True if the user may publish the room, otherwise False
        """
        for callback in self._user_may_publish_room_callbacks:
            if await callback(userid, room_id) is False:
                return False

        return True

    async def check_username_for_spam(self, user_profile: Dict[str, str]) -> bool:
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
            # Make a copy of the user profile object to ensure the spam checker cannot
            # modify it.
            if await callback(user_profile.copy()):
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
            behaviour = await (
                callback(email_threepid, username, request_info, auth_provider_id)
            )
            assert isinstance(behaviour, RegistrationBehaviour)
            if behaviour != RegistrationBehaviour.ALLOW:
                return behaviour

        return RegistrationBehaviour.ALLOW

    async def check_media_file_for_spam(
        self, file_wrapper: ReadableFileWrapper, file_info: FileInfo
    ) -> bool:
        """Checks if a piece of newly uploaded media should be blocked.

        This will be called for local uploads, downloads of remote media, each
        thumbnail generated for those, and web pages/images used for URL
        previews.

        Note that care should be taken to not do blocking IO operations in the
        main thread. For example, to get the contents of a file a module
        should do::

            async def check_media_file_for_spam(
                self, file: ReadableFileWrapper, file_info: FileInfo
            ) -> bool:
                buffer = BytesIO()
                await file.write_chunks_to(buffer.write)

                if buffer.getvalue() == b"Hello World":
                    return True

                return False


        Args:
            file: An object that allows reading the contents of the media.
            file_info: Metadata about the file.

        Returns:
            True if the media should be blocked or False if it should be
            allowed.
        """

        for callback in self._check_media_file_for_spam_callbacks:
            spam = await callback(file_wrapper, file_info)
            if spam:
                return True

        return False
