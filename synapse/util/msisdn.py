# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

import phonenumbers

from synapse.api.errors import SynapseError


def phone_number_to_msisdn(country, number):
    """
    Takes an ISO-3166-1 2 letter country code and phone number and
    returns an msisdn representing the canonical version of that
    phone number.
    Args:
        country (str): ISO-3166-1 2 letter country code
        number (str): Phone number in a national or international format

    Returns:
        (str) The canonical form of the phone number, as an msisdn
    Raises:
            SynapseError if the number could not be parsed.
    """
    try:
        phoneNumber = phonenumbers.parse(number, country)
    except phonenumbers.NumberParseException:
        raise SynapseError(400, "Unable to parse phone number")
    return phonenumbers.format_number(
        phoneNumber, phonenumbers.PhoneNumberFormat.E164
    )[1:]
