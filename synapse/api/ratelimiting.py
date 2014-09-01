import collections


class Ratelimiter(object):

    def __init__(self):
        self.message_counts = collections.OrderedDict()

    def prune_message_counts(self, time_now):
        for user_id in self.message_counts.keys():
            message_count, time_start, msg_rate_hz = (
                self.message_counts[user_id]
            )
            time_delta = time_now - time_start
            if message_count - time_delta * msg_rate_hz > 0:
                break
            else:
                del self.message_counts[user_id]

    def send_message(self, user_id, time_now, msg_rate_hz, burst_count):
        self.prune_message_counts(time_now)
        message_count, time_start, _ignored = self.message_counts.pop(
            user_id, (0., time_now, None),
        )
        time_delta = time_now - time_start
        if message_count - time_delta * msg_rate_hz < 0:
            a
        if message_count - (time_now - time_start) * msg_rate_hz > burst_count:
            allowed = False
        else:
            allowed = True
            message_count += 1
        self.message_counts[user_id] = (
            message_count, time_start, msg_rate_hz
        )
        return allowed
