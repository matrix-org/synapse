# Copyright 2014 - 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2019 - 2020, 2023 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Awaitable, Callable, Dict, List, Optional, Tuple

from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.module_api import LoginResponse

logger = logging.getLogger(__name__)


CHECK_3PID_AUTH_CALLBACK = Callable[
    [str, str, str],
    Awaitable[
        Optional[Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]]
    ],
]
ON_LOGGED_OUT_CALLBACK = Callable[[str, Optional[str], str], Awaitable]
CHECK_AUTH_CALLBACK = Callable[
    [str, str, JsonDict],
    Awaitable[
        Optional[Tuple[str, Optional[Callable[["LoginResponse"], Awaitable[None]]]]]
    ],
]
GET_USERNAME_FOR_REGISTRATION_CALLBACK = Callable[
    [JsonDict, JsonDict],
    Awaitable[Optional[str]],
]
GET_DISPLAYNAME_FOR_REGISTRATION_CALLBACK = Callable[
    [JsonDict, JsonDict],
    Awaitable[Optional[str]],
]
IS_3PID_ALLOWED_CALLBACK = Callable[[str, str, bool], Awaitable[bool]]


class PasswordAuthProviderModuleApiCallbacks:
    def __init__(self) -> None:
        # Mapping from login type to login parameters
        self.supported_login_types: Dict[str, Tuple[str, ...]] = {}

        self.check_3pid_auth_callbacks: List[CHECK_3PID_AUTH_CALLBACK] = []
        self.on_logged_out_callbacks: List[ON_LOGGED_OUT_CALLBACK] = []
        self.get_username_for_registration_callbacks: List[
            GET_USERNAME_FOR_REGISTRATION_CALLBACK
        ] = []
        self.get_displayname_for_registration_callbacks: List[
            GET_DISPLAYNAME_FOR_REGISTRATION_CALLBACK
        ] = []
        self.is_3pid_allowed_callbacks: List[IS_3PID_ALLOWED_CALLBACK] = []

        # Mapping from login type to auth checker callbacks
        self.auth_checker_callbacks: Dict[str, List[CHECK_AUTH_CALLBACK]] = {}

    def register_callbacks(
        self,
        check_3pid_auth: Optional[CHECK_3PID_AUTH_CALLBACK] = None,
        on_logged_out: Optional[ON_LOGGED_OUT_CALLBACK] = None,
        is_3pid_allowed: Optional[IS_3PID_ALLOWED_CALLBACK] = None,
        auth_checkers: Optional[
            Dict[Tuple[str, Tuple[str, ...]], CHECK_AUTH_CALLBACK]
        ] = None,
        get_username_for_registration: Optional[
            GET_USERNAME_FOR_REGISTRATION_CALLBACK
        ] = None,
        get_displayname_for_registration: Optional[
            GET_DISPLAYNAME_FOR_REGISTRATION_CALLBACK
        ] = None,
    ) -> None:
        # Register check_3pid_auth callback
        if check_3pid_auth is not None:
            self.check_3pid_auth_callbacks.append(check_3pid_auth)

        # register on_logged_out callback
        if on_logged_out is not None:
            self.on_logged_out_callbacks.append(on_logged_out)

        if auth_checkers is not None:
            # register a new supported login_type
            # Iterate through all of the types being registered
            for (login_type, fields), callback in auth_checkers.items():
                # Note: fields may be empty here. This would allow a modules auth checker to
                # be called with just 'login_type' and no password or other secrets

                # Need to check that all the field names are strings or may get nasty errors later
                for f in fields:
                    if not isinstance(f, str):
                        raise RuntimeError(
                            "A module tried to register support for login type: %s with parameters %s"
                            " but all parameter names must be strings"
                            % (login_type, fields)
                        )

                # 2 modules supporting the same login type must expect the same fields
                # e.g. 1 can't expect "pass" if the other expects "password"
                # so throw an exception if that happens
                if login_type not in self.supported_login_types.get(login_type, []):
                    self.supported_login_types[login_type] = fields
                else:
                    fields_currently_supported = self.supported_login_types.get(
                        login_type
                    )
                    if fields_currently_supported != fields:
                        raise RuntimeError(
                            "A module tried to register support for login type: %s with parameters %s"
                            " but another module had already registered support for that type with parameters %s"
                            % (login_type, fields, fields_currently_supported)
                        )

                # Add the new method to the list of auth_checker_callbacks for this login type
                self.auth_checker_callbacks.setdefault(login_type, []).append(callback)

        if get_username_for_registration is not None:
            self.get_username_for_registration_callbacks.append(
                get_username_for_registration,
            )

        if get_displayname_for_registration is not None:
            self.get_displayname_for_registration_callbacks.append(
                get_displayname_for_registration,
            )

        if is_3pid_allowed is not None:
            self.is_3pid_allowed_callbacks.append(is_3pid_allowed)
