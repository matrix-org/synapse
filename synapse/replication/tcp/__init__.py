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

"""This module implements the TCP replication protocol used by synapse to
communicate between the master process and its workers (when they're enabled).

Further details can be found in docs/tcp_replication.rst


Structure of the module:
 * client.py   - the client classes used for workers to connect to master
 * command.py  - the definitions of all the valid commands
 * protocol.py - contains bot the client and server protocol implementations,
                 these should not be used directly
 * resource.py - the server classes that accepts and handle client connections
 * streams.py  - the definitons of all the valid streams

"""
