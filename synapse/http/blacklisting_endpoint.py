#  Copyright 2020 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import logging
from typing import List, Optional, Union

from netaddr import IPAddress, IPSet
from zope.interface import provider

from twisted.internet.endpoints import HostnameEndpoint
from twisted.internet.interfaces import (
    IAddress,
    IHostResolution,
    IReactorPluggableNameResolver,
    IResolutionReceiver,
)

logger = logging.getLogger(__name__)


def check_against_blacklist(
    ip_address: IPAddress, ip_whitelist: Optional[IPSet], ip_blacklist: IPSet
) -> bool:
    """
    Compares an IP address to allowed and disallowed IP sets.

    Args:
        ip_address: The IP address to check
        ip_whitelist: Allowed IP addresses.
        ip_blacklist: Disallowed IP addresses.

    Returns:
        True if the IP address is in the blacklist and not in the whitelist.
    """
    if ip_address in ip_blacklist:
        if ip_whitelist is None or ip_address not in ip_whitelist:
            return True
    return False


class BlacklistingHostnameEndpoint(HostnameEndpoint):
    def __init__(
        self,
        reactor: IReactorPluggableNameResolver,
        host: Union[str, bytes],
        port: int,
        timeout: int = 30,
        bindAddress=None,
        attemptDelay=None,
        ip_whitelist: Optional[IPSet] = None,
        ip_blacklist: Optional[IPSet] = None,
    ):
        super().__init__(reactor, host, port, timeout, bindAddress, attemptDelay)

        self._ip_whitelist = ip_whitelist
        self._ip_blacklist = ip_blacklist

        # Calling super().__init__ sets up _nameResolver, wrap that so the
        # results can be filtered before being returned.
        #
        # Note that the nameResolver is called even if the passed in host is an
        # IP address (which will resolve to itself).
        self._real_nameResolver = self._nameResolver
        self._nameResolver = self._filteringNameResolver

    def _filteringNameResolver(
        self, recv: IResolutionReceiver, hostname: str, portNumber: int = 0
    ) -> IResolutionReceiver:
        r = recv()
        addresses = []  # type: List[IAddress]

        def _callback() -> None:
            r.resolutionBegan(None)

            has_bad_ip = False
            for i in addresses:
                ip_address = IPAddress(i.host)

                if check_against_blacklist(
                    ip_address, self._ip_whitelist, self._ip_blacklist
                ):
                    logger.info(
                        "Dropped %s from DNS resolution to %s due to blacklist"
                        % (ip_address, hostname)
                    )
                    has_bad_ip = True

            # if we have a blacklisted IP, we'd like to raise an error to block the
            # request, but all we can really do from here is claim that there were no
            # valid results.
            if not has_bad_ip:
                for i in addresses:
                    r.addressResolved(i)
            r.resolutionComplete()

        @provider(IResolutionReceiver)
        class EndpointReceiver:
            @staticmethod
            def resolutionBegan(resolutionInProgress: IHostResolution) -> None:
                pass

            @staticmethod
            def addressResolved(address: IAddress) -> None:
                addresses.append(address)

            @staticmethod
            def resolutionComplete() -> None:
                _callback()

        self._real_nameResolver.resolveHostName(
            EndpointReceiver, hostname, portNumber=portNumber
        )

        return r
