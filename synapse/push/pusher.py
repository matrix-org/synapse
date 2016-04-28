from httppusher import HttpPusher


def create_pusher(hs, pusherdict):
    PUSHER_TYPES = {
        "http": HttpPusher,
    }

    if hs.config.email_enable_notifs:
        from emailpusher import EmailPusher
        PUSHER_TYPES["email"] = EmailPusher

    if pusherdict['kind'] in PUSHER_TYPES:
        return PUSHER_TYPES[pusherdict['kind']](hs, pusherdict)
