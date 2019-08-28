from os.path import realpath, pardir, sep, relpath


def is_subpath(superpath, subpath):
    subpath = realpath(subpath)
    superpath = realpath(superpath)
    relative = relpath(subpath, superpath)
    return not relative.startswith(pardir + sep)
