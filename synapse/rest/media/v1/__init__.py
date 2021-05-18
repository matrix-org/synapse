# Copyright 2014-2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import PIL.Image

# check for JPEG support.
try:
    PIL.Image._getdecoder("rgb", "jpeg", None)
except IOError as e:
    if str(e).startswith("decoder jpeg not available"):
        raise Exception(
            "FATAL: jpeg codec not supported. Install pillow correctly! "
            " 'sudo apt-get install libjpeg-dev' then 'pip uninstall pillow &&"
            " pip install pillow --user'"
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
            " 'sudo apt-get install libjpeg-dev' then 'pip uninstall pillow &&"
            " pip install pillow --user'"
        )
except Exception:
    # any other exception is fine
    pass
