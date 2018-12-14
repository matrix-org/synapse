# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018 New Vector Ltd
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

REQUIREMENTS = [
    "jsonschema>=2.5.1",
    "frozendict>=1",
    "unpaddedbase64>=1.1.0",
    "canonicaljson>=1.1.3",
    "signedjson>=1.0.0",
    "pynacl>=1.2.1",
    "service_identity>=16.0.0",
    "Twisted>=17.1.0",
    "treq>=15.1",
    # Twisted has required pyopenssl 16.0 since about Twisted 16.6.
    "pyopenssl>=16.0.0",
    "pyyaml>=3.11",
    "pyasn1>=0.1.9",
    "pyasn1-modules>=0.0.7",
    "daemonize>=2.3.1",
    "bcrypt>=3.1.0",
    "pillow>=3.1.2",
    "sortedcontainers>=1.4.4",
    "psutil>=2.0.0",
    "pymacaroons-pynacl>=0.9.3",
    "msgpack-python>=0.4.2",
    "phonenumbers>=8.2.0",
    "six>=1.10",
    # prometheus_client 0.4.0 changed the format of counter metrics
    # (cf https://github.com/matrix-org/synapse/issues/4001)
    "prometheus_client>=0.0.18,<0.4.0",
    # we use attr.s(slots), which arrived in 16.0.0
    "attrs>=16.0.0",
    "netaddr>=0.7.18",
]

CONDITIONAL_REQUIREMENTS = {
    "email.enable_notifs": ["Jinja2>=2.8", "bleach>=1.4.2"],
    "matrix-synapse-ldap3": ["matrix-synapse-ldap3>=0.1"],
    "postgres": ["psycopg2>=2.6"],
    "saml2": ["pysaml2>=4.5.0"],
    "url_preview": ["lxml>=3.5.0"],
    "test": ["mock>=2.0"],
}

def list_requirements():
    deps = set(REQUIREMENTS)
    for opt in CONDITIONAL_REQUIREMENTS.values():
        deps = set(opt) | deps

    return list(deps)

if __name__ == "__main__":
    import sys
    sys.stdout.writelines(req + "\n" for req in list_requirements())
