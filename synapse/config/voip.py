# Copyright 2014, 2015 OpenMarket Ltd
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

from ._base import Config


class VoipConfig(Config):

    def __init__(self, args):
        super(VoipConfig, self).__init__(args)
        self.turn_uris = args.turn_uris
        self.turn_shared_secret = args.turn_shared_secret
        self.turn_user_lifetime = args.turn_user_lifetime

    @classmethod
    def add_arguments(cls, parser):
        super(VoipConfig, cls).add_arguments(parser)
        group = parser.add_argument_group("voip")
        group.add_argument(
            "--turn-uris", type=str, default=None,
            help="The public URIs of the TURN server to give to clients"
        )
        group.add_argument(
            "--turn-shared-secret", type=str, default=None,
            help=(
                "The shared secret used to compute passwords for the TURN"
                " server"
            )
        )
        group.add_argument(
            "--turn-user-lifetime", type=int, default=(1000 * 60 * 60),
            help="How long generated TURN credentials last, in ms"
        )
