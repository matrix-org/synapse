from httppusher import HttpPusher

PUSHER_TYPES = {
    'http': HttpPusher
}


def create_pusher(hs, pusherdict):
    if pusherdict['kind'] in PUSHER_TYPES:
        return PUSHER_TYPES[pusherdict['kind']](hs, pusherdict)
