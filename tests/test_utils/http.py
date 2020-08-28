# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C
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

from twisted.web.server import Request


def convert_request_args_to_form_data(request: Request) -> bytes:
    """Converts query arguments from a request to formatted HTML form data

    Ref: https://developer.mozilla.org/en-US/docs/Learn/Forms/Sending_and_retrieving_form_data

    Args:
        The request to pull arguments from

    Returns:
        The HTML form body data representation of the request's arguments
    """
    body = b""
    for key, value in request.args.items():
        arg = b"%s=%s&" % (key, value[0])
        body += arg

    # Remove the last '&' sign
    return body[:-1]
