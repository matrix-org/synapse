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

from copy import deepcopy
from typing import List

from synapse.api.constants import EduTypes, ReceiptTypes
from synapse.types import JsonDict

from tests import unittest


class ReceiptsTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.event_source = hs.get_event_sources().sources.receipt

    def test_filters_out_private_receipt(self) -> None:
        self._test_filters_private(
            [
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ_PRIVATE: {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
            [],
        )

    def test_filters_out_private_receipt_and_ignores_rest(self) -> None:
        self._test_filters_private(
            [
                {
                    "content": {
                        "$1dgdgrd5641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ_PRIVATE: {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                },
                            },
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                },
                            },
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
            [
                {
                    "content": {
                        "$1dgdgrd5641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
        )

    def test_filters_out_event_with_only_private_receipts_and_ignores_the_rest(
        self,
    ) -> None:
        self._test_filters_private(
            [
                {
                    "content": {
                        "$14356419edgd14394fHBLK:matrix.org": {
                            ReceiptTypes.READ_PRIVATE: {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                },
                            }
                        },
                        "$1435641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
            [
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
        )

    def test_handles_empty_event(self) -> None:
        self._test_filters_private(
            [
                {
                    "content": {
                        "$143564gdfg6114394fHBLK:matrix.org": {},
                        "$1435641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
            [
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
        )

    def test_filters_out_receipt_event_with_only_private_receipt_and_ignores_rest(
        self,
    ) -> None:
        self._test_filters_private(
            [
                {
                    "content": {
                        "$14356419edgd14394fHBLK:matrix.org": {
                            ReceiptTypes.READ_PRIVATE: {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                },
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                },
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                },
            ],
            [
                {
                    "content": {
                        "$1435641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@user:jki.re": {
                                    "ts": 1436451550453,
                                }
                            }
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
        )

    def test_handles_string_data(self) -> None:
        """
        Tests that an invalid shape for read-receipts is handled.
        Context: https://github.com/matrix-org/synapse/issues/10603
        """

        self._test_filters_private(
            [
                {
                    "content": {
                        "$14356419edgd14394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@rikj:jki.re": "string",
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                },
            ],
            [
                {
                    "content": {
                        "$14356419edgd14394fHBLK:matrix.org": {
                            ReceiptTypes.READ: {
                                "@rikj:jki.re": "string",
                            }
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                },
            ],
        )

    def test_leaves_our_private_and_their_public(self) -> None:
        self._test_filters_private(
            [
                {
                    "content": {
                        "$1dgdgrd5641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ_PRIVATE: {
                                "@me:server.org": {
                                    "ts": 1436451550453,
                                },
                            },
                            ReceiptTypes.READ: {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                },
                            },
                            "a.receipt.type": {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                },
                            },
                        },
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
            [
                {
                    "content": {
                        "$1dgdgrd5641916114394fHBLK:matrix.org": {
                            ReceiptTypes.READ_PRIVATE: {
                                "@me:server.org": {
                                    "ts": 1436451550453,
                                },
                            },
                            ReceiptTypes.READ: {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                },
                            },
                            "a.receipt.type": {
                                "@rikj:jki.re": {
                                    "ts": 1436451550453,
                                },
                            },
                        }
                    },
                    "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                    "type": EduTypes.RECEIPT,
                }
            ],
        )

    def test_we_do_not_mutate(self) -> None:
        """Ensure the input values are not modified."""
        events = [
            {
                "content": {
                    "$1435641916114394fHBLK:matrix.org": {
                        ReceiptTypes.READ_PRIVATE: {
                            "@rikj:jki.re": {
                                "ts": 1436451550453,
                            }
                        }
                    }
                },
                "room_id": "!jEsUZKDJdhlrceRyVU:example.org",
                "type": EduTypes.RECEIPT,
            }
        ]
        original_events = deepcopy(events)
        self._test_filters_private(events, [])
        # Since the events are fed in from a cache they should not be modified.
        self.assertEqual(events, original_events)

    def _test_filters_private(
        self, events: List[JsonDict], expected_output: List[JsonDict]
    ) -> None:
        """Tests that the _filter_out_private returns the expected output"""
        filtered_events = self.event_source.filter_out_private_receipts(
            events, "@me:server.org"
        )
        self.assertEqual(filtered_events, expected_output)
