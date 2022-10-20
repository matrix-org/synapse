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

from synapse.api.errors import StoreError
from synapse.http.server import DirectServeHtmlResource, respond_with_html_bytes
from synapse.http.servlet import parse_string
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer


class UnsubscribeResource(DirectServeHtmlResource):
    """
    To allow pusher to be delete by clicking a link (ie. GET request)
    """

    SUCCESS_HTML = b"<html><body>You have been unsubscribed</body><html>"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.notifier = hs.get_notifier()
        self.auth = hs.get_auth()
        self.pusher_pool = hs.get_pusherpool()
        self.macaroon_generator = hs.get_macaroon_generator()

    async def _async_render_GET(self, request: SynapseRequest) -> None:
        token = parse_string(request, "access_token", required=True)
        app_id = parse_string(request, "app_id", required=True)
        pushkey = parse_string(request, "pushkey", required=True)

        user_id = self.macaroon_generator.verify_delete_pusher_token(
            token, app_id, pushkey
        )

        try:
            await self.pusher_pool.remove_pusher(
                app_id=app_id, pushkey=pushkey, user_id=user_id
            )
        except StoreError as se:
            if se.code != 404:
                # This is fine: they're already unsubscribed
                raise

        self.notifier.on_new_replication_data()

        respond_with_html_bytes(
            request,
            200,
            UnsubscribeResource.SUCCESS_HTML,
        )
