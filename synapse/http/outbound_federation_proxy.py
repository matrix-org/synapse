from twisted.web.http import HTTPFactory
from twisted.web.proxy import Proxy, ProxyClient, ProxyClientFactory, ProxyRequest


class FederationOutboundProxyClient(ProxyClient):
    ...


class FederationOutboundProxyClientFactory(ProxyClientFactory):
    protocol = FederationOutboundProxyClient


class FederationOutboundProxyRequest(ProxyRequest):
    protocols = {b"matrix": FederationOutboundProxyClientFactory}
    ports = {b"matrix": 80}


class FederationOutboundProxy(Proxy):
    requestFactory = FederationOutboundProxyRequest


OutboundFederationProxyFactory = HTTPFactory.forProtocol(FederationOutboundProxy)
