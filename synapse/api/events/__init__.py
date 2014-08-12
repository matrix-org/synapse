# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from synapse.util.jsonobject import JsonEncodedObject


class SynapseEvent(JsonEncodedObject):

    """Base class for Synapse events. These are JSON objects which must abide
    by a certain well-defined structure.
    """

    # Attributes that are currently assumed by the federation side:
    # Mandatory:
    # - event_id
    # - room_id
    # - type
    # - is_state
    #
    # Optional:
    # - state_key (mandatory when is_state is True)
    # - prev_events (these can be filled out by the federation layer itself.)
    # - prev_state

    valid_keys = [
        "event_id",
        "type",
        "room_id",
        "user_id",  # sender/initiator
        "content",  # HTTP body, JSON
    ]

    internal_keys = [
        "is_state",
        "state_key",
        "prev_events",
        "prev_state",
        "depth",
        "destinations",
        "origin",
    ]

    required_keys = [
        "event_id",
        "room_id",
        "content",
    ]

    def __init__(self, raises=True, **kwargs):
        super(SynapseEvent, self).__init__(**kwargs)
        if "content" in kwargs:
            self.check_json(self.content, raises=raises)

    def get_content_template(self):
        """ Retrieve the JSON template for this event as a dict.

        The template must be a dict representing the JSON to match. Only
        required keys should be present. The values of the keys in the template
        are checked via type() to the values of the same keys in the actual
        event JSON.

        NB: If loading content via json.loads, you MUST define strings as
        unicode.

        For example:
            Content:
                {
                    "name": u"bob",
                    "age": 18,
                    "friends": [u"mike", u"jill"]
                }
            Template:
                {
                    "name": u"string",
                    "age": 0,
                    "friends": [u"string"]
                }
            The values "string" and 0 could be anything, so long as the types
            are the same as the content.
        """
        raise NotImplementedError("get_content_template not implemented.")

    def check_json(self, content, raises=True):
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
        err_msg = self._check_json(content, self.get_content_template())
        if err_msg:
            if raises:
                raise SynapseError(400, err_msg, Codes.BAD_JSON)
            else:
                return False
        else:
            return True

    def _check_json(self, content, template):
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
                    return "Key %s is of the wrong type." % key

                if type(content[key]) == dict:
                    # we must go deeper
                    msg = self._check_json(content[key], template[key])
                    if msg:
                        return msg
                elif type(content[key]) == list:
                    # make sure each item type in content matches the template
                    for entry in content[key]:
                        msg = self._check_json(entry, template[key][0])
                        if msg:
                            return msg
