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
from typing import TYPE_CHECKING

from synapse._pydantic_compat import HAS_PYDANTIC_V2

if TYPE_CHECKING or HAS_PYDANTIC_V2:
    from pydantic.v1 import BaseModel, Extra
else:
    from pydantic import BaseModel, Extra


class RequestBodyModel(BaseModel):
    """A custom version of Pydantic's BaseModel which

     - ignores unknown fields and
     - does not allow fields to be overwritten after construction,

    but otherwise uses Pydantic's default behaviour.

    Ignoring unknown fields is a useful default. It means that clients can provide
    unstable field not known to the server without the request being refused outright.

    Subclassing in this way is recommended by
    https://pydantic-docs.helpmanual.io/usage/model_config/#change-behaviour-globally
    """

    class Config:
        # By default, ignore fields that we don't recognise.
        extra = Extra.ignore
        # By default, don't allow fields to be reassigned after parsing.
        allow_mutation = False
