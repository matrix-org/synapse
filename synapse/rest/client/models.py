# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Dict, Optional

from pydantic import Extra, StrictInt, StrictStr, constr, validator

from synapse.rest.models import RequestBodyModel
from synapse.util.threepids import validate_email


class AuthenticationData(RequestBodyModel):
    """
    Data used during user-interactive authentication.

    (The name "Authentication Data" is taken directly from the spec.)

    Additional keys will be present, depending on the `type` field. Use `.dict()` to
    access them.
    """

    class Config:
        extra = Extra.allow

    session: Optional[StrictStr] = None
    type: Optional[StrictStr] = None


class EmailRequestTokenBody(RequestBodyModel):
    if TYPE_CHECKING:
        client_secret: StrictStr
    else:
        # See also assert_valid_client_secret()
        client_secret: constr(
            regex="[0-9a-zA-Z.=_-]",  # noqa: F722
            min_length=0,
            max_length=255,
            strict=True,
        )
    email: StrictStr
    id_server: Optional[StrictStr]
    id_access_token: Optional[StrictStr]
    next_link: Optional[StrictStr]
    send_attempt: StrictInt

    @validator("id_access_token", always=True)
    def token_required_for_identity_server(
        cls, token: Optional[str], values: Dict[str, object]
    ) -> Optional[str]:
        if values.get("id_server") is not None and token is None:
            raise ValueError("id_access_token is required if an id_server is supplied.")
        return token

    # Canonicalise the email address. The addresses are all stored canonicalised
    # in the database. This allows the user to reset his password without having to
    # know the exact spelling (eg. upper and lower case) of address in the database.
    # Without this, an email stored in the database as "foo@bar.com" would cause
    # user requests for "FOO@bar.com" to raise a Not Found error.
    _email_validator = validator("email", allow_reuse=True)(validate_email)
