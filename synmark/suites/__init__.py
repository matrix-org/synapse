from . import logging, lrucache, lrucache_evict

SUITES = [
    (logging, 1000),
    (logging, 10000),
    (logging, None),
    (lrucache, None),
    (lrucache_evict, None),
]
