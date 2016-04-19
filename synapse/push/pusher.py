from httppusher import HttpPusher
from emailpusher import EmailPusher

PUSHER_TYPES = {
    'http': HttpPusher,
    'email': EmailPusher,
}


def create_pusher(hs, pusherdict):
    if pusherdict['kind'] in PUSHER_TYPES:
        return PUSHER_TYPES[pusherdict['kind']](hs, pusherdict)
