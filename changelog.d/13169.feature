Add per-room rate limiting for room joins. For each room, Synapse now monitors the rate of join events in that room and throttles additional joins if that rate grows too large.
