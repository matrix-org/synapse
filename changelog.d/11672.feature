Whenever the `spamcheck` forbids a user to create a room, a `SynapseError` with `errcode` `M_UNKNOWN` is returned to the client. However, it would be more specific to return the `errcode` `M_UNKNOWN`.

Therefore, this PR will raise `M_FORBIDDEN` instead of `M_UNKNOWN` whenever `synapse/events/spamcheck.py:user_may_create_room` returns `False`.
Note: The `M_FORBIDDEN` code is set in the methods which currently call `user_may_create_room`, not in the method `user_may_create_room` itself.
