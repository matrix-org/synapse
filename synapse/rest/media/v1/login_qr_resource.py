# Copyright 2015 OpenMarket Ltd
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

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer, threads

from synapse.api.errors import CodeMessageException

import simplejson
import logging

from unpaddedbase64 import encode_base64
from hashlib import sha256
from OpenSSL import crypto

logger = logging.getLogger(__name__)


class LoginQRResource(Resource):
    isLeaf = True

    def __init__(self, hs):
        Resource.__init__(self)
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()
        self.config = hs.get_config()

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        try:
            auth_user, _ = yield self.auth.get_user_by_req(request)
            image = yield self.make_short_term_qr_code(auth_user.to_string())
            request.setHeader(b"Content-Type", b"image/png")

            image.save(request)
            request.finish()
        except CodeMessageException as e:
            logger.info("Returning: %s", e)
            request.setResponseCode(e.code)
            request.finish()
        except Exception:
            logger.exception("Exception while generating token")
            request.setResponseCode(500)
            request.finish()

    @defer.inlineCallbacks
    def make_short_term_qr_code(self, user_id):
        h = self.handlers.auth_handler
        token = h.make_short_term_token(user_id)

        x509_certificate_bytes = crypto.dump_certificate(
            crypto.FILETYPE_ASN1,
            self.config.tls_certificate
        )

        sha256_fingerprint = sha256(x509_certificate_bytes).digest()

        def gen():
            import qrcode
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=5,
            )
            qr.add_data(simplejson.dumps({
                "user_id": user_id,
                "token": token,
                "homeserver_url": self.config.client_addr,
                "fingerprints": [{
                    "hash_type": "SHA256",
                    "bytes": encode_base64(sha256_fingerprint),
                }],
            }))
            qr.make(fit=True)
            return qr.make_image()

        res = yield threads.deferToThread(gen)
        defer.returnValue(res)
