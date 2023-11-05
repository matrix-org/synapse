from immutabledict import immutabledict

from synapse.api.constants import EventTypes
from synapse.types.state import StateFilter

from tests.unittest import TestCase


class StateFilterDifferenceTestCase(TestCase):
    def assert_difference(
        self, minuend: StateFilter, subtrahend: StateFilter, expected: StateFilter
    ) -> None:
        self.assertEqual(
            minuend.approx_difference(subtrahend),
            expected,
            f"StateFilter difference not correct:\n\n\t{minuend!r}\nminus\n\t{subtrahend!r}\nwas\n\t{minuend.approx_difference(subtrahend)}\nexpected\n\t{expected}",
        )

    def test_state_filter_difference_no_include_other_minus_no_include_other(
        self,
    ) -> None:
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), both a and b do not have the
        include_others flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=False,
            ),
            StateFilter.freeze({EventTypes.Create: None}, include_others=False),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
            StateFilter.freeze(
                {EventTypes.Member: {"@wombat:spqr"}},
                include_others=False,
            ),
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.CanonicalAlias: {""}},
                include_others=False,
            ),
        )

        # (specific state keys) - (specific state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
        )

    def test_state_filter_difference_include_other_minus_no_include_other(self) -> None:
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), only a has the include_others flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Create: None,
                    EventTypes.Member: set(),
                    EventTypes.CanonicalAlias: set(),
                },
                include_others=True,
            ),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        # This also shows that the resultant state filter is normalised.
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=True),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                    EventTypes.Create: {""},
                },
                include_others=False,
            ),
            StateFilter(types=immutabledict(), include_others=True),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter(
                types=immutabledict(),
                include_others=True,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.CanonicalAlias: {""},
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
        )

        # (specific state keys) - (specific state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
        )

    def test_state_filter_difference_include_other_minus_include_other(self) -> None:
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), both a and b have the include_others
        flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=True,
            ),
            StateFilter(types=immutabledict(), include_others=False),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=True),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=False,
            ),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter(
                types=immutabledict(),
                include_others=False,
            ),
        )

        # (specific state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                    EventTypes.Create: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                    EventTypes.Create: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                    EventTypes.Create: {""},
                },
                include_others=False,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                },
                include_others=False,
            ),
        )

    def test_state_filter_difference_no_include_other_minus_include_other(self) -> None:
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), only b has the include_others flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=True,
            ),
            StateFilter(types=immutabledict(), include_others=False),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
            StateFilter.freeze(
                {EventTypes.Member: {"@wombat:spqr"}},
                include_others=True,
            ),
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter(
                types=immutabledict(),
                include_others=False,
            ),
        )

        # (specific state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                },
                include_others=False,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                },
                include_others=False,
            ),
        )

    def test_state_filter_difference_simple_cases(self) -> None:
        """
        Tests some very simple cases of the StateFilter approx_difference,
        that are not explicitly tested by the more in-depth tests.
        """

        self.assert_difference(StateFilter.all(), StateFilter.all(), StateFilter.none())

        self.assert_difference(
            StateFilter.all(),
            StateFilter.none(),
            StateFilter.all(),
        )


class StateFilterTestCase(TestCase):
    def test_return_expanded(self) -> None:
        """
        Tests the behaviour of the return_expanded() function that expands
        StateFilters to include more state types (for the sake of cache hit rate).
        """

        self.assertEqual(StateFilter.all().return_expanded(), StateFilter.all())

        self.assertEqual(StateFilter.none().return_expanded(), StateFilter.none())

        # Concrete-only state filters stay the same
        # (Case: mixed filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                    "some.other.state.type": {""},
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                    "some.other.state.type": {""},
                },
                include_others=False,
            ),
        )

        # Concrete-only state filters stay the same
        # (Case: non-member-only filter)
        self.assertEqual(
            StateFilter.freeze(
                {"some.other.state.type": {""}}, include_others=False
            ).return_expanded(),
            StateFilter.freeze({"some.other.state.type": {""}}, include_others=False),
        )

        # Concrete-only state filters stay the same
        # (Case: member-only filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                },
                include_others=False,
            ),
        )

        # Wildcard member-only state filters stay the same
        self.assertEqual(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # If there is a wildcard in the non-member portion of the filter,
        # it's expanded to include ALL non-member events.
        # (Case: mixed filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                    "some.other.state.type": None,
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {EventTypes.Member: {"@wombat:test", "@alicia:test"}},
                include_others=True,
            ),
        )

        # If there is a wildcard in the non-member portion of the filter,
        # it's expanded to include ALL non-member events.
        # (Case: non-member-only filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    "some.other.state.type": None,
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze({EventTypes.Member: set()}, include_others=True),
        )
        self.assertEqual(
            StateFilter.freeze(
                {
                    "some.other.state.type": None,
                    "yet.another.state.type": {"wombat"},
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze({EventTypes.Member: set()}, include_others=True),
        )
