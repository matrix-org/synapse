# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from typing import Dict

from zope.interface import implementer

from twisted.internet.endpoints import UNIXClientEndpoint
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.web.client import URI
from twisted.web.iweb import IAgentEndpointFactory

from synapse.config.workers import (
    InstanceLocationConfig,
    TcpInstanceLocationConfig,
    UnixSocketInstanceLocationConfig,
)
from synapse.types import ISynapseReactor


@implementer(IAgentEndpointFactory)
class WorkerEndpointFactory:
    def __init__(
        self,
        reactor: ISynapseReactor,
        configs: Dict[str, InstanceLocationConfig],
        tcp_endpoint_factory: IAgentEndpointFactory,
    ):
        self.reactor = reactor
        self.configs = configs
        self.tcp_agent_factory = tcp_endpoint_factory

    def endpointForURI(self, uri: URI) -> IStreamClientEndpoint:
        worker_config = self.configs.get(uri.host)
        if not worker_config:
            raise ValueError(f"Don't know how to connect to worker: {uri.host}")

        if isinstance(worker_config, TcpInstanceLocationConfig):
            # TODO TLS support
            rewritten_uri = URI(
                scheme=uri.scheme,
                # TODO I'd probably cache the encoded netloc and host in the TCP Config?
                netloc=f"{worker_config.host}:{worker_config.port}".encode("utf-8"),
                host=worker_config.host.encode("utf-8"),
                port=worker_config.port,
                path=uri.path,
                params=uri.params,
                query=uri.query,
                fragment=uri.fragment,
            )
            return self.tcp_agent_factory.endpointForURI(rewritten_uri)
        elif isinstance(worker_config, UnixSocketInstanceLocationConfig):
            return UNIXClientEndpoint(self.reactor, worker_config.socket_path)
        else:
            raise ValueError(
                f"Unknown worker connection config {worker_config} for {uri.host}"
            )
