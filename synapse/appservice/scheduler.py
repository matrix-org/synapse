# -*- coding: utf-8 -*-
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
"""
This module controls the reliability for application service transactions.

The nominal flow through this module looks like:
                    ___________
  \O/ --- event -->|           |                           +--------------+
   |  - event ---->| EventPool |<-- poll 1/s for events ---|  EventSorter |
  / \ ---- event ->|___________|                           +--------------+
 USERS                                 ____________________________|
                                      |        |       |
                                      V        V       V
                                     ASa       ASb     ASc
                                    [e,e]      [e]   [e,e,e]
                                      |
                                      V
      -````````-            +------------+
      |````````|<--StoreTxn-|Transaction |
      |Database|            |    Maker   |---> SEND TO AS
      `--------`            +------------+
What happens on SEND TO AS depends on the state of the Application Service:
 - If the AS is marked as DOWN, do nothing.
 - If the AS is marked as UP, send the transaction.
     * SUCCESS : Increment where the AS is up to txn-wise and nuke the txn
                 contents from the db.
     * FAILURE : Marked AS as DOWN and start Recoverer.

Recoverer attempts to recover ASes who have died. The flow for this looks like:
                ,--------------------- backoff++ --------------.
               V                                               |
  START ---> Wait exp ------> Get oldest txn ID from ----> FAILURE
             backoff           DB and try to send it
                                 ^                |__________
Mark AS as                       |                           V
UP & quit           +---------- YES                      SUCCESS
    |               |                                        |
    NO <--- Have more txns? <------ Mark txn success & nuke -+
                                      from db; incr AS pos.
"""


class EventPool(object):
    pass


class EventSorter(object):
    pass


class TransactionMaker(object):
    pass


class Recoverer(object):
    pass
