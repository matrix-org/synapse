
from twisted.internet import defer

from synapse.config._base import ConfigError
from synapse.types import UserID

import ldap3
import ldap3.core.exceptions

import logging

try:
    import ldap3
    import ldap3.core.exceptions
except ImportError:
    ldap3 = None
    pass


logger = logging.getLogger(__name__)


class LDAPMode(object):
    SIMPLE = "simple",
    SEARCH = "search",

    LIST = (SIMPLE, SEARCH)


class LdapAuthProvider(object):
    __version__ = "0.1"

    def __init__(self, config, account_handler):
        self.account_handler = account_handler

        if not ldap3:
            raise RuntimeError(
                'Missing ldap3 library. This is required for LDAP Authentication.'
            )

        self.ldap_mode = config.mode
        self.ldap_uri = config.uri
        self.ldap_start_tls = config.start_tls
        self.ldap_base = config.base
        self.ldap_attributes = config.attributes
        if self.ldap_mode == LDAPMode.SEARCH:
            self.ldap_bind_dn = config.bind_dn
            self.ldap_bind_password = config.bind_password
            self.ldap_filter = config.filter

    @defer.inlineCallbacks
    def check_password(self, user_id, password):
        """ Attempt to authenticate a user against an LDAP Server
            and register an account if none exists.

            Returns:
                True if authentication against LDAP was successful
        """
        localpart = UserID.from_string(user_id).localpart

        try:
            server = ldap3.Server(self.ldap_uri)
            logger.debug(
                "Attempting LDAP connection with %s",
                self.ldap_uri
            )

            if self.ldap_mode == LDAPMode.SIMPLE:
                result, conn = self._ldap_simple_bind(
                    server=server, localpart=localpart, password=password
                )
                logger.debug(
                    'LDAP authentication method simple bind returned: %s (conn: %s)',
                    result,
                    conn
                )
                if not result:
                    defer.returnValue(False)
            elif self.ldap_mode == LDAPMode.SEARCH:
                result, conn = self._ldap_authenticated_search(
                    server=server, localpart=localpart, password=password
                )
                logger.debug(
                    'LDAP auth method authenticated search returned: %s (conn: %s)',
                    result,
                    conn
                )
                if not result:
                    defer.returnValue(False)
            else:
                raise RuntimeError(
                    'Invalid LDAP mode specified: {mode}'.format(
                        mode=self.ldap_mode
                    )
                )

            try:
                logger.info(
                    "User authenticated against LDAP server: %s",
                    conn
                )
            except NameError:
                logger.warn(
                    "Authentication method yielded no LDAP connection, aborting!"
                )
                defer.returnValue(False)

            # check if user with user_id exists
            if (yield self.account_handler.check_user_exists(user_id)):
                # exists, authentication complete
                conn.unbind()
                defer.returnValue(True)

            else:
                # does not exist, fetch metadata for account creation from
                # existing ldap connection
                query = "({prop}={value})".format(
                    prop=self.ldap_attributes['uid'],
                    value=localpart
                )

                if self.ldap_mode == LDAPMode.SEARCH and self.ldap_filter:
                    query = "(&{filter}{user_filter})".format(
                        filter=query,
                        user_filter=self.ldap_filter
                    )
                logger.debug(
                    "ldap registration filter: %s",
                    query
                )

                conn.search(
                    search_base=self.ldap_base,
                    search_filter=query,
                    attributes=[
                        self.ldap_attributes['name'],
                        self.ldap_attributes['mail']
                    ]
                )

                if len(conn.response) == 1:
                    attrs = conn.response[0]['attributes']
                    mail = attrs[self.ldap_attributes['mail']][0]
                    name = attrs[self.ldap_attributes['name']][0]

                    # create account
                    user_id, access_token = (
                        yield self.account_handler.register(localpart=localpart)
                    )

                    # TODO: bind email, set displayname with data from ldap directory

                    logger.info(
                        "Registration based on LDAP data was successful: %d: %s (%s, %)",
                        user_id,
                        localpart,
                        name,
                        mail
                    )

                    defer.returnValue(True)
                else:
                    if len(conn.response) == 0:
                        logger.warn("LDAP registration failed, no result.")
                    else:
                        logger.warn(
                            "LDAP registration failed, too many results (%s)",
                            len(conn.response)
                        )

                    defer.returnValue(False)

            defer.returnValue(False)

        except ldap3.core.exceptions.LDAPException as e:
            logger.warn("Error during ldap authentication: %s", e)
            defer.returnValue(False)

    @staticmethod
    def parse_config(config):
        class _LdapConfig(object):
            pass

        ldap_config = _LdapConfig()

        ldap_config.enabled = config.get("enabled", False)

        ldap_config.mode = LDAPMode.SIMPLE

        # verify config sanity
        _require_keys(config, [
            "uri",
            "base",
            "attributes",
        ])

        ldap_config.uri = config["uri"]
        ldap_config.start_tls = config.get("start_tls", False)
        ldap_config.base = config["base"]
        ldap_config.attributes = config["attributes"]

        if "bind_dn" in config:
            ldap_config.mode = LDAPMode.SEARCH
            _require_keys(config, [
                "bind_dn",
                "bind_password",
            ])

            ldap_config.bind_dn = config["bind_dn"]
            ldap_config.bind_password = config["bind_password"]
            ldap_config.filter = config.get("filter", None)

        # verify attribute lookup
        _require_keys(config['attributes'], [
            "uid",
            "name",
            "mail",
        ])

        return ldap_config

    def _ldap_simple_bind(self, server, localpart, password):
        """ Attempt a simple bind with the credentials
            given by the user against the LDAP server.

            Returns True, LDAP3Connection
                if the bind was successful
            Returns False, None
                if an error occured
        """

        try:
            # bind with the the local users ldap credentials
            bind_dn = "{prop}={value},{base}".format(
                prop=self.ldap_attributes['uid'],
                value=localpart,
                base=self.ldap_base
            )
            conn = ldap3.Connection(server, bind_dn, password,
                                    authentication=ldap3.SIMPLE)
            logger.debug(
                "Established LDAP connection in simple bind mode: %s",
                conn
            )

            if self.ldap_start_tls:
                conn.bind()
                conn.start_tls()
                logger.debug(
                    "Upgraded LDAP connection in simple bind mode through StartTLS: %s",
                    conn
                )

            if conn.bind():
                # GOOD: bind okay
                logger.debug("LDAP Bind successful in simple bind mode.")
                return True, conn

            # BAD: bind failed
            logger.info(
                "Binding against LDAP failed for '%s' failed: %s",
                localpart, conn.result['description']
            )
            conn.unbind()
            return False, None

        except ldap3.core.exceptions.LDAPException as e:
            logger.warn("Error during LDAP authentication: %s", e)
            return False, None

    def _ldap_authenticated_search(self, server, localpart, password):
        """ Attempt to login with the preconfigured bind_dn
            and then continue searching and filtering within
            the base_dn

            Returns (True, LDAP3Connection)
                if a single matching DN within the base was found
                that matched the filter expression, and with which
                a successful bind was achieved

                The LDAP3Connection returned is the instance that was used to
                verify the password not the one using the configured bind_dn.
            Returns (False, None)
                if an error occured
        """

        try:
            conn = ldap3.Connection(
                server,
                self.ldap_bind_dn,
                self.ldap_bind_password
            )
            logger.debug(
                "Established LDAP connection in search mode: %s",
                conn
            )

            if self.ldap_start_tls:
                conn.bind()
                conn.start_tls()
                logger.debug(
                    "Upgraded LDAP connection in search mode through StartTLS: %s",
                    conn
                )

            if not conn.bind():
                logger.warn(
                    "Binding against LDAP with `bind_dn` failed: %s",
                    conn.result['description']
                )
                conn.unbind()
                return False, None

            # construct search_filter like (uid=localpart)
            query = "({prop}={value})".format(
                prop=self.ldap_attributes['uid'],
                value=localpart
            )
            if self.ldap_filter:
                # combine with the AND expression
                query = "(&{query}{filter})".format(
                    query=query,
                    filter=self.ldap_filter
                )
            logger.debug(
                "LDAP search filter: %s",
                query
            )
            conn.search(
                search_base=self.ldap_base,
                search_filter=query
            )

            if len(conn.response) == 1:
                # GOOD: found exactly one result
                user_dn = conn.response[0]['dn']
                logger.debug('LDAP search found dn: %s', user_dn)

                # unbind and simple bind with user_dn to verify the password
                # Note: do not use rebind(), for some reason it did not verify
                #       the password for me!
                conn.unbind()
                return self._ldap_simple_bind(server, localpart, password)
            else:
                # BAD: found 0 or > 1 results, abort!
                if len(conn.response) == 0:
                    logger.info(
                        "LDAP search returned no results for '%s'",
                        localpart
                    )
                else:
                    logger.info(
                        "LDAP search returned too many (%s) results for '%s'",
                        len(conn.response), localpart
                    )
                conn.unbind()
                return False, None

        except ldap3.core.exceptions.LDAPException as e:
            logger.warn("Error during LDAP authentication: %s", e)
            return False, None


def _require_keys(config, required):
    missing = [key for key in required if key not in config]
    if missing:
        raise ConfigError(
            "LDAP enabled but missing required config values: {}".format(
                ", ".join(missing)
            )
        )
