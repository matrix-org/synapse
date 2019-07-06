# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from mock import Mock, patch

from synapse.util.distributor import Distributor

from . import unittest


class DistributorTestCase(unittest.TestCase):
    def setUp(self):
        self.dist = Distributor()

    def test_signal_dispatch(self):
        self.dist.declare("alert")

        observer = Mock()
        self.dist.observe("alert", observer)

        self.dist.fire("alert", 1, 2, 3)
        observer.assert_called_with(1, 2, 3)

    def test_signal_catch(self):
        self.dist.declare("alarm")

        observers = [Mock() for i in (1, 2)]
        for o in observers:
            self.dist.observe("alarm", o)

        observers[0].side_effect = Exception("Awoogah!")

        with patch("synapse.util.distributor.logger", spec=["warning"]) as mock_logger:
            self.dist.fire("alarm", "Go")

            observers[0].assert_called_once_with("Go")
            observers[1].assert_called_once_with("Go")

            self.assertEquals(mock_logger.warning.call_count, 1)
            self.assertIsInstance(mock_logger.warning.call_args[0][0], str)

    def test_signal_prereg(self):
        observer = Mock()
        self.dist.observe("flare", observer)

        self.dist.declare("flare")
        self.dist.fire("flare", 4, 5)

        observer.assert_called_with(4, 5)

    def test_signal_undeclared(self):
        def code():
            self.dist.fire("notification")

        self.assertRaises(KeyError, code)
