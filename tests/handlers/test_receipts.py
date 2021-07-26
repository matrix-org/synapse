# Copyright 2021 Šimon Brandner <simon.bra.ag@gmail.com>
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


from typing import List

from synapse.api.constants import ReadReceiptEventFields
from synapse.types import JsonDict

from tests import unittest


class ReceiptsTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.event_source = hs.get_event_sources().sources["receipt"]

    def test_hidden_receipt_filtering(self):
        """
        In the first param of _test_filters_hidden we use "hidden" instead of
        ReadReceiptEventFields.MSC2285_HIDDEN. We do this because we're mocking
        the data from the database which doesn't use the prefix
        """

        # Filters out a hidden receipt
        self._test_filters_hidden(
            [
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                    "hidden": True,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
            [],
        )

        # Doesn't filter out our hidden read receipt
        self._test_filters_hidden(
            [
                {
                    "content": {
                        "$1435641916hfgh4394fHBLK:matrix.org": {
                            "m.read": {
                                "@me:server.org": {
                                    "ts": 1436451550453,
                                    "hidden": True,
                                },
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
            [
                {
                    "content": {
                        "$1435641916hfgh4394fHBLK:matrix.org": {
                            "m.read": {
                                "@me:server.org": {
                                    "ts": 1436451550453,
                                    ReadReceiptEventFields.MSC2285_HIDDEN: True,
                                },
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
        )

        # Filters out a hidden read receipt and doesn't touch the rest
        self._test_filters_hidden(
            [
                {
                    "content": {
                        "$1dgdgrd5641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                    "hidden": True,
                                },
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                },
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
            [
                {
                    "content": {
                        "$1dgdgrd5641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
        )

        # Filters out an event with only hidden read receipts and doesn't touch the rest
        self._test_filters_hidden(
            [
                {
                    "content": {
                        "$14356419edgd14394fHBLK:matrix.org": {
                            "m.read": {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                    "hidden": True,
                                },
                            }
                        },
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
            [
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
        )

        # Handles missing content of m.read
        self._test_filters_hidden(
            [
                {
                    "content": {
                        "$14356419ggffg114394fHBLK:matrix.org": {"m.read": {}},
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
            [
                {
                    "content": {
                        "$14356419ggffg114394fHBLK:matrix.org": {"m.read": {}},
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
        )

        # Handles an empty event
        self._test_filters_hidden(
            [
                {
                    "content": {
                        "$143564gdfg6114394fHBLK:matrix.org": {},
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
            [
                {
                    "content": {
                        "$143564gdfg6114394fHBLK:matrix.org": {},
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
        )

        # Filters out an event with only hidden read receipts and doesn't touch the rest
        self._test_filters_hidden(
            [
                {
                    "content": {
                        "$14356419edgd14394fHBLK:matrix.org": {
                            "m.read": {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                    "hidden": True,
                                },
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                },
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                },
            ],
            [
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            "m.read": {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": "m.receipt",
                }
            ],
        )

    def _test_filters_hidden(
        self, events: List[JsonDict], expected_output: List[JsonDict]
    ):
        """Tests that the _filter_out_hidden returns the expected output"""
        filtered_events = self.event_source.filter_out_hidden(events, "@me:server.org")
        self.assertEquals(filtered_events, expected_output)
