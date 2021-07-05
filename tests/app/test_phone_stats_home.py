import synapse
from synapse.rest.client.v1 import login, room

from tests.unittest import HomeserverTestCase

DAY = 86400


class PhoneHomeTestCase(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def test_r30_minimum_usage(self):
        """
        Tests the minimum amount of interaction necessary for the R30 metric
        to consider a user 'retained'.
        """

        # Register a user, log it in, create a room and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=access_token)
        self.helper.send(room_id, "message", tok=access_token)

        # Check the R30 results do not count that user.
        r30_results = self.get_success(
            self.hs.get_datastore().count_r30_users()
        )
        self.assertEqual(r30_results, {"all": 0})

        # Advance 30 days (+ 1 second, because strict inequality causes issues if we are
        # bang on 30 days later).
        self.reactor.advance(30 * DAY + 1)

        # (Make sure the user isn't somehow counted by this point.)
        r30_results = self.get_success(
            self.hs.get_datastore().count_r30_users()
        )
        self.assertEqual(r30_results, {"all": 0})

        # Send a message (this counts as activity)
        self.helper.send(room_id, "message2", tok=access_token)

        # TODO: Not sure why this needs 4+ seconds advancing here...?
        self.reactor.advance(4)

        # *Now* the user is counted.
        r30_results = self.get_success(
            self.hs.get_datastore().count_r30_users()
        )
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})

        # Advance 27 days. The user has now not posted for 27 days.
        self.reactor.advance(27 * DAY)

        # The user is still counted.
        r30_results = self.get_success(
            self.hs.get_datastore().count_r30_users()
        )
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})

        # Advance another day. The user has now not posted for 28 days.
        self.reactor.advance(DAY)

        # The user is now no longer counted in R30.
        # TODO: why is this the case after only 28 days?
        r30_results = self.get_success(
            self.hs.get_datastore().count_r30_users()
        )
        self.assertEqual(r30_results, {"all": 0})

    def test_r30_user_must_be_retained_for_at_least_a_month(self):
        """
        Tests that a newly-registered user must be retained for a whole month
        before appearing in the R30 statistic, even if they post every day
        during that time!
        """
        # Register a user and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=access_token)
        self.helper.send(room_id, "message", tok=access_token)

        # Check the user does not contribute to R30 yet.
        r30_results = self.get_success(self.hs.get_datastore().count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

        for _ in range(30):
            # This loop posts a message every day for 30 days
            self.reactor.advance(DAY)
            self.helper.send(room_id, "I'm still here", tok=access_token)

            # Notice that the user *still* does not contribute to R30!
            r30_results = self.get_success(self.hs.get_datastore().count_r30_users())
            self.assertEqual(r30_results, {"all": 0})

        self.reactor.advance(DAY)
        self.helper.send(room_id, "Still here!", tok=access_token)

        # *Now* the user appears in R30.
        r30_results = self.get_success(self.hs.get_datastore().count_r30_users())
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})
