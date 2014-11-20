# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.api.errors import SynapseError, Codes


class EventValidator(object):
    def __init__(self, hs):
        pass

    def validate(self, event):
        """Checks the given JSON content abides by the rules of the template.

        Args:
            content : A JSON object to check.
            raises: True to raise a SynapseError if the check fails.
        Returns:
            True if the content passes the template. Returns False if the check
            fails and raises=False.
        Raises:
            SynapseError if the check fails and raises=True.
        """
        # recursively call to inspect each layer
        err_msg = self._check_json_template(
            event.content,
            event.get_content_template()
        )
        if err_msg:
            raise SynapseError(400, err_msg, Codes.BAD_JSON)
        else:
            return True

    def _check_json_template(self, content, template):
        """Check content and template matches.

        If the template is a dict, each key in the dict will be validated with
        the content, else it will just compare the types of content and
        template. This basic type check is required because this function will
        be recursively called and could be called with just strs or ints.

        Args:
            content: The content to validate.
            template: The validation template.
        Returns:
            str: An error message if the validation fails, else None.
        """
        if type(content) != type(template):
            return "Mismatched types: %s" % template

        if type(template) == dict:
            for key in template:
                if key not in content:
                    return "Missing %s key" % key

                if type(content[key]) != type(template[key]):
                    return "Key %s is of the wrong type (got %s, want %s)" % (
                        key, type(content[key]), type(template[key]))

                if type(content[key]) == dict:
                    # we must go deeper
                    msg = self._check_json_template(
                        content[key],
                        template[key]
                    )
                    if msg:
                        return msg
                elif type(content[key]) == list:
                    # make sure each item type in content matches the template
                    for entry in content[key]:
                        msg = self._check_json_template(
                            entry,
                            template[key][0]
                        )
                        if msg:
                            return msg
