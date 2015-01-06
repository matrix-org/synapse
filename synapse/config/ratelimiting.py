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


class RatelimitConfig(Config):

    def __init__(self, args):
        super(RatelimitConfig, self).__init__(args)
        self.rc_messages_per_second = args.rc_messages_per_second
        self.rc_message_burst_count = args.rc_message_burst_count

    @classmethod
    def add_arguments(cls, parser):
        super(RatelimitConfig, cls).add_arguments(parser)
        rc_group = parser.add_argument_group("ratelimiting")
        rc_group.add_argument(
            "--rc-messages-per-second", type=float, default=0.2,
            help="number of messages a client can send per second"
        )
        rc_group.add_argument(
            "--rc-message-burst-count", type=float, default=10,
            help="number of message a client can send before being throttled"
        )
