# -*- coding: utf-8 -*-
import PIL.Image

# check for JPEG support.
try:
    PIL.Image._getdecoder("rgb", "jpeg", None)
except IOError as e:
    if str(e).startswith("decoder jpeg not available"):
        raise Exception(
            "FATAL: jpeg codec not supported. Install pillow correctly! "
            " 'sudo apt-get install libjpeg-dev' then 'pip install -I pillow'"
        )
except Exception:
    # any other exception is fine
    pass


# check for PNG support.
try:
    PIL.Image._getdecoder("rgb", "zip", None)
except IOError as e:
    if str(e).startswith("decoder zip not available"):
        raise Exception(
            "FATAL: zip codec not supported. Install pillow correctly! "
            " 'sudo apt-get install libjpeg-dev' then 'pip install -I pillow'"
        )
except Exception:
    # any other exception is fine
    pass