# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Interface documentation.
"""

from __future__ import absolute_import, division

from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Text,
    Tuple,
    Union,
)

from zope.interface import Attribute, Interface

from twisted.internet.abstract import FileDescriptor
from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.defer import Deferred
from twisted.internet.protocol import ConnectedDatagramProtocol, DatagramProtocol
from twisted.names.dns import Query, RRHeader
from twisted.python.failure import Failure
from twisted.python.threadpool import ThreadPool

class IAddress(Interface): ...

class IConnector(Interface):
    def stopConnecting(): ...
    def disconnect(): ...
    def connect(): ...
    def getDestination() -> IAddress: ...

class IResolverSimple(Interface):
    def getHostByName(name: str, timeout: Sequence[int]) -> Deferred: ...

class IHostResolution(Interface):

    name: str
    def cancel(): ...

class IResolutionReceiver(Interface):
    def resolutionBegan(resolutionInProgress: IHostResolution): ...
    def addressResolved(address: IAddress): ...
    def resolutionComplete(): ...

class IHostnameResolver(Interface):
    def resolveHostName(
        resolutionReceiver: IResolutionReceiver,
        hostName: str,
        portNumber: int = ...,
        addressTypes: Iterable[Any] = ...,
        transportSemantics: str = ...,
    ) -> IResolutionReceiver: ...

class IResolver(IResolverSimple):
    def query(
        query: Query, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupAddress(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupAddress6(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupIPV6Address(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupMailExchange(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupNameservers(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupCanonicalName(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupMailBox(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupMailGroup(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupMailRename(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupPointer(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupAuthority(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupNull(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupWellKnownServices(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupHostInfo(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupMailboxInfo(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupText(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupResponsibility(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupAFSDatabase(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupService(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupAllRecords(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupSenderPolicy(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupNamingAuthorityPointer(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...
    def lookupZone(
        name: bytes, timeout: Sequence[int]
    ) -> Deferred[Tuple[List[RRHeader, ...], ...]]: ...

class IReactorTCP(Interface):
    def connectTCP(
        host: bytes,
        port: int,
        factory: IProtocolFactory,
        timeout: int,
        bindAddress: Tuple[str, str],
    ) -> IConnector: ...
    def listenTCP(
        port: int, factory: IProtocolFactory, backlog: int, interface: str
    ) -> IListeningPort: ...

class IReactorSSL(Interface):
    def connectSSL(
        host: bytes,
        port: int,
        factory: IProtocolFactory,
        contextFactory: IOpenSSLContextFactory,
        timeout: int,
        bindAddress=Tuple[str, str],
    ) -> IConnector: ...
    def listenSSL(
        port: int,
        factory: IProtocolFactory,
        contextFactory: IOpenSSLContextFactory,
        backlog: int,
        interface: str,
    ) -> IListeningPort: ...

class IReactorUNIX(Interface):
    def connectUNIX(
        address: str, factory: IProtocolFactory, timeout: int, checkPID: bool
    ) -> IConnector: ...
    def listenUNIX(
        address: str, factory: IProtocolFactory, backlog: int, mode: int, wantPID: bool
    ) -> IListeningPort: ...

class IReactorUNIXDatagram(Interface):
    def connectUNIXDatagram(
        address: str,
        protocol: ConnectedDatagramProtocol,
        maxPacketSize: int,
        mode: int,
        bindAddress: str,
    ) -> IConnector: ...
    def listenUNIXDatagram(
        address: str, protocol: DatagramProtocol, maxPacketSize: int, mode: int
    ) -> IListeningPort: ...

class IReactorWin32Events(Interface):
    def addEvent(event, fd: FileDescriptor, action: str) -> None: ...
    def removeEvent(event) -> None: ...

class IReactorUDP(Interface):
    def listenUDP(
        port: int, protocol: DatagramProtocol, interface: str, maxPacketSize: int
    ) -> IListeningPort: ...

class IReactorMulticast(Interface):
    def listenMulticast(
        port: int,
        protocol: DatagramProtocol,
        interface: str,
        maxPacketSize: int,
        listenMultiple: bool,
    ) -> IListeningPort: ...

class IReactorSocket(Interface):
    def adoptStreamPort(
        fileDescriptor: int, addressFamily, factory: IProtocolFactory
    ) -> IListeningPort: ...
    def adoptStreamConnection(
        fileDescriptor: int, addressFamily, factory: IProtocolFactory
    ): ...
    def adoptDatagramPort(
        fileDescriptor: int,
        addressFamily,
        protocol: DatagramProtocol,
        maxPacketSize: int,
    ) -> IListeningPort: ...

class IReactorProcess(Interface):
    def spawnProcess(
        processProtocol: IProcessProtocol,
        executable: Union[bytes, str],
        args=Sequence[Union[bytes, str]],
        env=Optional[Dict[Union[bytes, str], Union[bytes, str]]],
        path=Optional[Union[bytes, str]],
        uid=Optional[int],
        gid=Optional[int],
        usePTY=Union[bool, Tuple[int, int, str]],
        childFDs=Dict[int, Union[int, str]],
    ) -> IProcessTransport: ...

class IReactorTime(Interface):
    def seconds() -> Union[int, float]: ...
    def callLater(
        delay: float, callable: Callable[..., None], *args, **kw
    ) -> IDelayedCall: ...
    def getDelayedCalls() -> List[IDelayedCall]: ...

class IDelayedCall(Interface):
    def getTime() -> float: ...
    def cancel() -> None: ...
    def delay(secondsLater: float) -> None: ...
    def reset(secondsFromNow: float) -> None: ...
    def active() -> bool: ...

class IReactorFromThreads(Interface):
    def callFromThread(callable: Callable, *args, **kw) -> Any: ...

class IReactorInThreads(Interface):
    def callInThread(callable: Callable, *args, **kwargs) -> Any: ...

class IReactorThreads(IReactorFromThreads, IReactorInThreads):
    def getThreadPool() -> ThreadPool: ...
    def suggestThreadPoolSize(size: int) -> None: ...

class IReactorCore(Interface):
    """
    Core methods that a Reactor must implement.
    """

    running: bool
    def resolve(name: str, timeout: int = ...): ...
    def run() -> None: ...
    def stop() -> None: ...
    def crash() -> None: ...
    def iterate(delay: int = ...) -> None: ...
    def fireSystemEvent(eventType: str) -> None: ...
    def addSystemEventTrigger(
        phase: str, eventType: str, callable: Callable, *args, **kw
    ): ...
    def removeSystemEventTrigger(triggerID): ...
    def callWhenRunning(callable: Callable, *args, **kw) -> Optional[Any]: ...

class IReactorPluggableResolver(Interface):
    def installResolver(resolver: IResolverSimple) -> IResolverSimple: ...

class IReactorPluggableNameResolver(Interface):

    nameResolver: IHostnameResolver
    def installNameResolver(resolver: IHostnameResolver) -> IHostnameResolver: ...

class IReactorDaemonize(Interface):
    def beforeDaemonize() -> None: ...
    def afterDaemonize() -> None: ...

class IReactorFDSet(Interface):
    def addReader(reader: IReadDescriptor) -> None: ...
    def addWriter(writer: IWriteDescriptor) -> None: ...
    def removeReader(reader: IReadDescriptor) -> None: ...
    def removeWriter(writer: IWriteDescriptor) -> None: ...
    def removeAll() -> List[Union[IReadDescriptor, IWriteDescriptor]]: ...
    def getReaders() -> List[IReadDescriptor]: ...
    def getWriters() -> List[IWriteDescriptor]: ...

class IListeningPort(Interface):
    """
    A listening port.
    """

    def startListening():
        """
        Start listening on this port.

        @raise CannotListenError: If it cannot listen on this port (e.g., it is
                                  a TCP port and it cannot bind to the required
                                  port number).
        """
    def stopListening():
        """
        Stop listening on this port.

        If it does not complete immediately, will return Deferred that fires
        upon completion.
        """
    def getHost():
        """
        Get the host that this port is listening for.

        @return: An L{IAddress} provider.
        """

class ILoggingContext(Interface):
    """
    Give context information that will be used to log events generated by
    this item.
    """

    def logPrefix():
        """
        @return: Prefix used during log formatting to indicate context.
        @rtype: C{str}
        """

class IFileDescriptor(ILoggingContext):
    """
    An interface representing a UNIX-style numeric file descriptor.
    """

    def fileno():
        """
        @raise: If the descriptor no longer has a valid file descriptor
            number associated with it.

        @return: The platform-specified representation of a file descriptor
            number.  Or C{-1} if the descriptor no longer has a valid file
            descriptor number associated with it.  As long as the descriptor
            is valid, calls to this method on a particular instance must
            return the same value.
        """
    def connectionLost(reason):
        """
        Called when the connection was lost.

        This is called when the connection on a selectable object has been
        lost.  It will be called whether the connection was closed explicitly,
        an exception occurred in an event handler, or the other end of the
        connection closed it first.

        See also L{IHalfCloseableDescriptor} if your descriptor wants to be
        notified separately of the two halves of the connection being closed.

        @param reason: A failure instance indicating the reason why the
                       connection was lost.  L{error.ConnectionLost} and
                       L{error.ConnectionDone} are of special note, but the
                       failure may be of other classes as well.
        """

class IReadDescriptor(IFileDescriptor):
    """
    An L{IFileDescriptor} that can read.

    This interface is generally used in conjunction with L{IReactorFDSet}.
    """

    def doRead():
        """
        Some data is available for reading on your descriptor.

        @return: If an error is encountered which causes the descriptor to
            no longer be valid, a L{Failure} should be returned.  Otherwise,
            L{None}.
        """

class IWriteDescriptor(IFileDescriptor):
    """
    An L{IFileDescriptor} that can write.

    This interface is generally used in conjunction with L{IReactorFDSet}.
    """

    def doWrite():
        """
        Some data can be written to your descriptor.

        @return: If an error is encountered which causes the descriptor to
            no longer be valid, a L{Failure} should be returned.  Otherwise,
            L{None}.
        """

class IReadWriteDescriptor(IReadDescriptor, IWriteDescriptor):
    """
    An L{IFileDescriptor} that can both read and write.
    """

class IHalfCloseableDescriptor(Interface):
    """
    A descriptor that can be half-closed.
    """

    def writeConnectionLost(reason):
        """
        Indicates write connection was lost.
        """
    def readConnectionLost(reason):
        """
        Indicates read connection was lost.
        """

class ISystemHandle(Interface):
    """
    An object that wraps a networking OS-specific handle.
    """

    def getHandle():
        """
        Return a system- and reactor-specific handle.

        This might be a socket.socket() object, or some other type of
        object, depending on which reactor is being used. Use and
        manipulate at your own risk.

        This might be used in cases where you want to set specific
        options not exposed by the Twisted APIs.
        """

class IConsumer(Interface):
    """
    A consumer consumes data from a producer.
    """

    def registerProducer(producer, streaming):
        """
        Register to receive data from a producer.

        This sets self to be a consumer for a producer.  When this object runs
        out of data (as when a send(2) call on a socket succeeds in moving the
        last data from a userspace buffer into a kernelspace buffer), it will
        ask the producer to resumeProducing().

        For L{IPullProducer} providers, C{resumeProducing} will be called once
        each time data is required.

        For L{IPushProducer} providers, C{pauseProducing} will be called
        whenever the write buffer fills up and C{resumeProducing} will only be
        called when it empties.

        @type producer: L{IProducer} provider

        @type streaming: C{bool}
        @param streaming: C{True} if C{producer} provides L{IPushProducer},
        C{False} if C{producer} provides L{IPullProducer}.

        @raise RuntimeError: If a producer is already registered.

        @return: L{None}
        """
    def unregisterProducer():
        """
        Stop consuming data from a producer, without disconnecting.
        """
    def write(data):
        """
        The producer will write data by calling this method.

        The implementation must be non-blocking and perform whatever
        buffering is necessary.  If the producer has provided enough data
        for now and it is a L{IPushProducer}, the consumer may call its
        C{pauseProducing} method.
        """

class IProducer(Interface):
    def stopProducing() -> None: ...

class IPushProducer(IProducer):
    def pauseProducing() -> None: ...
    def resumeProducing() -> None: ...

class IPullProducer(IProducer):
    def resumeProducing() -> None: ...

class IProtocol(Interface):
    def dataReceived(data: bytes) -> None: ...
    def connectionLost(reason: Failure) -> None: ...
    def makeConnection(transport) -> None: ...
    def connectionMade() -> None: ...

class IProcessProtocol(Interface):
    """
    Interface for process-related event handlers.
    """

    def makeConnection(process):
        """
        Called when the process has been created.

        @type process: L{IProcessTransport} provider
        @param process: An object representing the process which has been
            created and associated with this protocol.
        """
    def childDataReceived(childFD, data):
        """
        Called when data arrives from the child process.

        @type childFD: L{int}
        @param childFD: The file descriptor from which the data was
            received.

        @type data: L{bytes}
        @param data: The data read from the child's file descriptor.
        """
    def childConnectionLost(childFD):
        """
        Called when a file descriptor associated with the child process is
        closed.

        @type childFD: C{int}
        @param childFD: The file descriptor which was closed.
        """
    def processExited(reason):
        """
        Called when the child process exits.

        @type reason: L{twisted.python.failure.Failure}
        @param reason: A failure giving the reason the child process
            terminated.  The type of exception for this failure is either
            L{twisted.internet.error.ProcessDone} or
            L{twisted.internet.error.ProcessTerminated}.

        @since: 8.2
        """
    def processEnded(reason):
        """
        Called when the child process exits and all file descriptors associated
        with it have been closed.

        @type reason: L{twisted.python.failure.Failure}
        @param reason: A failure giving the reason the child process
            terminated.  The type of exception for this failure is either
            L{twisted.internet.error.ProcessDone} or
            L{twisted.internet.error.ProcessTerminated}.
        """

class IHalfCloseableProtocol(Interface):
    """
    Implemented to indicate they want notification of half-closes.

    TCP supports the notion of half-closing the connection, e.g.
    closing the write side but still not stopping reading. A protocol
    that implements this interface will be notified of such events,
    instead of having connectionLost called.
    """

    def readConnectionLost():
        """
        Notification of the read connection being closed.

        This indicates peer did half-close of write side. It is now
        the responsibility of the this protocol to call
        loseConnection().  In addition, the protocol MUST make sure a
        reference to it still exists (i.e. by doing a callLater with
        one of its methods, etc.)  as the reactor will only have a
        reference to it if it is writing.

        If the protocol does not do so, it might get garbage collected
        without the connectionLost method ever being called.
        """
    def writeConnectionLost():
        """
        Notification of the write connection being closed.

        This will never be called for TCP connections as TCP does not
        support notification of this type of half-close.
        """

class IHandshakeListener(Interface):
    """
    An interface implemented by a L{IProtocol} to indicate that it would like
    to be notified when TLS handshakes complete when run over a TLS-based
    transport.

    This interface is only guaranteed to be called when run over a TLS-based
    transport: non TLS-based transports will not respect this interface.
    """

    def handshakeCompleted():
        """
        Notification of the TLS handshake being completed.

        This notification fires when OpenSSL has completed the TLS handshake.
        At this point the TLS connection is established, and the protocol can
        interrogate its transport (usually an L{ISSLTransport}) for details of
        the TLS connection.

        This notification *also* fires whenever the TLS session is
        renegotiated. As a result, protocols that have certain minimum security
        requirements should implement this interface to ensure that they are
        able to re-evaluate the security of the TLS session if it changes.
        """

class IFileDescriptorReceiver(Interface):
    """
    Protocols may implement L{IFileDescriptorReceiver} to receive file
    descriptors sent to them.  This is useful in conjunction with
    L{IUNIXTransport}, which allows file descriptors to be sent between
    processes on a single host.
    """

    def fileDescriptorReceived(descriptor):
        """
        Called when a file descriptor is received over the connection.

        @param descriptor: The descriptor which was received.
        @type descriptor: C{int}

        @return: L{None}
        """

class IProtocolFactory(Interface):
    """
    Interface for protocol factories.
    """

    def buildProtocol(addr):
        """
        Called when a connection has been established to addr.

        If None is returned, the connection is assumed to have been refused,
        and the Port will close the connection.

        @type addr: (host, port)
        @param addr: The address of the newly-established connection

        @return: None if the connection was refused, otherwise an object
                 providing L{IProtocol}.
        """
    def doStart():
        """
        Called every time this is connected to a Port or Connector.
        """
    def doStop():
        """
        Called every time this is unconnected from a Port or Connector.
        """

class ITransport(Interface):
    def write(data: bytes) -> None: ...
    def writeSequence(data: Iterable[bytes]) -> None: ...
    def loseConnection() -> None: ...
    def getPeer() -> IAddress: ...
    def getHost() -> IAddress: ...

class ITCPTransport(ITransport):
    def loseWriteConnection() -> None: ...
    def abortConnection() -> None: ...
    def getTcpNoDelay() -> bool: ...
    def setTcpNoDelay(enabled: bool) -> None: ...
    def getTcpKeepAlive() -> bool: ...
    def setTcpKeepAlive(enabled: bool) -> None: ...
    def getHost() -> Union[IPv4Address, IPv6Address]: ...
    def getPeer() -> Union[IPv4Address, IPv6Address]: ...

class IUNIXTransport(ITransport):
    """
    Transport for stream-oriented unix domain connections.
    """

    def sendFileDescriptor(descriptor):
        """
        Send a duplicate of this (file, socket, pipe, etc) descriptor to the
        other end of this connection.

        The send is non-blocking and will be queued if it cannot be performed
        immediately.  The send will be processed in order with respect to other
        C{sendFileDescriptor} calls on this transport, but not necessarily with
        respect to C{write} calls on this transport.  The send can only be
        processed if there are also bytes in the normal connection-oriented send
        buffer (ie, you must call C{write} at least as many times as you call
        C{sendFileDescriptor}).

        @param descriptor: An C{int} giving a valid file descriptor in this
            process.  Note that a I{file descriptor} may actually refer to a
            socket, a pipe, or anything else POSIX tries to treat in the same
            way as a file.

        @return: L{None}
        """

class IOpenSSLServerConnectionCreator(Interface):
    """
    A provider of L{IOpenSSLServerConnectionCreator} can create
    L{OpenSSL.SSL.Connection} objects for TLS servers.

    @see: L{twisted.internet.ssl}

    @note: Creating OpenSSL connection objects is subtle, error-prone, and
        security-critical.  Before implementing this interface yourself,
        consider using L{twisted.internet.ssl.CertificateOptions} as your
        C{contextFactory}.  (For historical reasons, that class does not
        actually I{implement} this interface; nevertheless it is usable in all
        Twisted APIs which require a provider of this interface.)
    """

    def serverConnectionForTLS(tlsProtocol):
        """
        Create a connection for the given server protocol.

        @param tlsProtocol: the protocol server making the request.
        @type tlsProtocol: L{twisted.protocols.tls.TLSMemoryBIOProtocol}.

        @return: an OpenSSL connection object configured appropriately for the
            given Twisted protocol.
        @rtype: L{OpenSSL.SSL.Connection}
        """

class IOpenSSLClientConnectionCreator(Interface):
    """
    A provider of L{IOpenSSLClientConnectionCreator} can create
    L{OpenSSL.SSL.Connection} objects for TLS clients.

    @see: L{twisted.internet.ssl}

    @note: Creating OpenSSL connection objects is subtle, error-prone, and
        security-critical.  Before implementing this interface yourself,
        consider using L{twisted.internet.ssl.optionsForClientTLS} as your
        C{contextFactory}.
    """

    def clientConnectionForTLS(tlsProtocol):
        """
        Create a connection for the given client protocol.

        @param tlsProtocol: the client protocol making the request.
        @type tlsProtocol: L{twisted.protocols.tls.TLSMemoryBIOProtocol}.

        @return: an OpenSSL connection object configured appropriately for the
            given Twisted protocol.
        @rtype: L{OpenSSL.SSL.Connection}
        """

class IProtocolNegotiationFactory(Interface):
    """
    A provider of L{IProtocolNegotiationFactory} can provide information about
    the various protocols that the factory can create implementations of. This
    can be used, for example, to provide protocol names for Next Protocol
    Negotiation and Application Layer Protocol Negotiation.

    @see: L{twisted.internet.ssl}
    """

    def acceptableProtocols():
        """
        Returns a list of protocols that can be spoken by the connection
        factory in the form of ALPN tokens, as laid out in the IANA registry
        for ALPN tokens.

        @return: a list of ALPN tokens in order of preference.
        @rtype: L{list} of L{bytes}
        """

class IOpenSSLContextFactory(Interface):
    """
    A provider of L{IOpenSSLContextFactory} is capable of generating
    L{OpenSSL.SSL.Context} classes suitable for configuring TLS on a
    connection. A provider will store enough state to be able to generate these
    contexts as needed for individual connections.

    @see: L{twisted.internet.ssl}
    """

    def getContext():
        """
        Returns a TLS context object, suitable for securing a TLS connection.
        This context object will be appropriately customized for the connection
        based on the state in this object.

        @return: A TLS context object.
        @rtype: L{OpenSSL.SSL.Context}
        """

class ITLSTransport(ITCPTransport):
    """
    A TCP transport that supports switching to TLS midstream.

    Once TLS mode is started the transport will implement L{ISSLTransport}.
    """

    def startTLS(contextFactory):
        """
        Initiate TLS negotiation.

        @param contextFactory: An object which creates appropriately configured
            TLS connections.

            For clients, use L{twisted.internet.ssl.optionsForClientTLS}; for
            servers, use L{twisted.internet.ssl.CertificateOptions}.

        @type contextFactory: L{IOpenSSLClientConnectionCreator} or
            L{IOpenSSLServerConnectionCreator}, depending on whether this
            L{ITLSTransport} is a server or not.  If the appropriate interface
            is not provided by the value given for C{contextFactory}, it must
            be an implementor of L{IOpenSSLContextFactory}.
        """

class ISSLTransport(ITCPTransport):
    """
    A SSL/TLS based transport.
    """

    def getPeerCertificate():
        """
        Return an object with the peer's certificate info.
        """

class INegotiated(ISSLTransport):
    """
    A TLS based transport that supports using ALPN/NPN to negotiate the
    protocol to be used inside the encrypted tunnel.
    """

    negotiatedProtocol = Attribute(
        """
        The protocol selected to be spoken using ALPN/NPN. The result from ALPN
        is preferred to the result from NPN if both were used. If the remote
        peer does not support ALPN or NPN, or neither NPN or ALPN are available
        on this machine, will be L{None}. Otherwise, will be the name of the
        selected protocol as C{bytes}. Note that until the handshake has
        completed this property may incorrectly return L{None}: wait until data
        has been received before trusting it (see
        https://twistedmatrix.com/trac/ticket/6024).
        """
    )

class ICipher(Interface):

    fullName: Text

class IAcceptableCiphers(Interface):
    """
    A list of acceptable ciphers for a TLS context.
    """

    def selectCiphers(availableCiphers):
        """
        Choose which ciphers to allow to be negotiated on a TLS connection.

        @param availableCiphers: A L{list} of L{ICipher} which gives the names
            of all ciphers supported by the TLS implementation in use.

        @return: A L{list} of L{ICipher} which represents the ciphers
            which may be negotiated on the TLS connection.  The result is
            ordered by preference with more preferred ciphers appearing
            earlier.
        """

class IProcessTransport(ITransport):
    """
    A process transport.
    """

    pid = Attribute(
        "From before L{IProcessProtocol.makeConnection} is called to before "
        "L{IProcessProtocol.processEnded} is called, C{pid} is an L{int} "
        "giving the platform process ID of this process.  C{pid} is L{None} "
        "at all other times."
    )
    def closeStdin():
        """
        Close stdin after all data has been written out.
        """
    def closeStdout():
        """
        Close stdout.
        """
    def closeStderr():
        """
        Close stderr.
        """
    def closeChildFD(descriptor):
        """
        Close a file descriptor which is connected to the child process, identified
        by its FD in the child process.
        """
    def writeToChild(childFD, data):
        """
        Similar to L{ITransport.write} but also allows the file descriptor in
        the child process which will receive the bytes to be specified.

        @type childFD: L{int}
        @param childFD: The file descriptor to which to write.

        @type data: L{bytes}
        @param data: The bytes to write.

        @return: L{None}

        @raise KeyError: If C{childFD} is not a file descriptor that was mapped
            in the child when L{IReactorProcess.spawnProcess} was used to create
            it.
        """
    def loseConnection():
        """
        Close stdin, stderr and stdout.
        """
    def signalProcess(signalID):
        """
        Send a signal to the process.

        @param signalID: can be
          - one of C{"KILL"}, C{"TERM"}, or C{"INT"}.
              These will be implemented in a
              cross-platform manner, and so should be used
              if possible.
          - an integer, where it represents a POSIX
              signal ID.

        @raise twisted.internet.error.ProcessExitedAlready: If the process has
            already exited.
        @raise OSError: If the C{os.kill} call fails with an errno different
            from C{ESRCH}.
        """

class IServiceCollection(Interface):
    """
    An object which provides access to a collection of services.
    """

    def getServiceNamed(serviceName):
        """
        Retrieve the named service from this application.

        Raise a C{KeyError} if there is no such service name.
        """
    def addService(service):
        """
        Add a service to this collection.
        """
    def removeService(service):
        """
        Remove a service from this collection.
        """

class IUDPTransport(Interface):
    """
    Transport for UDP DatagramProtocols.
    """

    def write(packet, addr=None):
        """
        Write packet to given address.

        @param addr: a tuple of (ip, port). For connected transports must
                     be the address the transport is connected to, or None.
                     In non-connected mode this is mandatory.

        @raise twisted.internet.error.MessageLengthError: C{packet} was too
        long.
        """
    def connect(host, port):
        """
        Connect the transport to an address.

        This changes it to connected mode. Datagrams can only be sent to
        this address, and will only be received from this address. In addition
        the protocol's connectionRefused method might get called if destination
        is not receiving datagrams.

        @param host: an IP address, not a domain name ('127.0.0.1', not 'localhost')
        @param port: port to connect to.
        """
    def getHost():
        """
        Get this port's host address.

        @return: an address describing the listening port.
        @rtype: L{IPv4Address} or L{IPv6Address}.
        """
    def stopListening():
        """
        Stop listening on this port.

        If it does not complete immediately, will return L{Deferred} that fires
        upon completion.
        """
    def setBroadcastAllowed(enabled):
        """
        Set whether this port may broadcast.

        @param enabled: Whether the port may broadcast.
        @type enabled: L{bool}
        """
    def getBroadcastAllowed():
        """
        Checks if broadcast is currently allowed on this port.

        @return: Whether this port may broadcast.
        @rtype: L{bool}
        """

class IUNIXDatagramTransport(Interface):
    """
    Transport for UDP PacketProtocols.
    """

    def write(packet, address):
        """
        Write packet to given address.
        """
    def getHost():
        """
        Returns L{UNIXAddress}.
        """

class IUNIXDatagramConnectedTransport(Interface):
    """
    Transport for UDP ConnectedPacketProtocols.
    """

    def write(packet):
        """
        Write packet to address we are connected to.
        """
    def getHost():
        """
        Returns L{UNIXAddress}.
        """
    def getPeer():
        """
        Returns L{UNIXAddress}.
        """

class IMulticastTransport(Interface):
    """
    Additional functionality for multicast UDP.
    """

    def getOutgoingInterface():
        """
        Return interface of outgoing multicast packets.
        """
    def setOutgoingInterface(addr):
        """
        Set interface for outgoing multicast packets.

        Returns Deferred of success.
        """
    def getLoopbackMode():
        """
        Return if loopback mode is enabled.
        """
    def setLoopbackMode(mode):
        """
        Set if loopback mode is enabled.
        """
    def getTTL():
        """
        Get time to live for multicast packets.
        """
    def setTTL(ttl):
        """
        Set time to live on multicast packets.
        """
    def joinGroup(addr, interface=""):
        """
        Join a multicast group. Returns L{Deferred} of success or failure.

        If an error occurs, the returned L{Deferred} will fail with
        L{error.MulticastJoinError}.
        """
    def leaveGroup(addr, interface=""):
        """
        Leave multicast group, return L{Deferred} of success.
        """

class IStreamClientEndpoint(Interface):
    def connect(protocolFactory: IProtocolFactory) -> Deferred[IProtocol]: ...

class IStreamServerEndpoint(Interface):
    def listen(protocolFactory: IProtocolFactory) -> Deferred[IListeningPort]: ...

class IStreamServerEndpointStringParser(Interface):

    prefix: str
    def parseStreamServer(
        reactor: IReactorCore, *args, **kwargs
    ) -> IStreamServerEndpoint: ...

class IStreamClientEndpointStringParserWithReactor(Interface):

    prefix: bytes
    def parseStreamClient(
        reactor: IReactorCore, *args, **kwargs
    ) -> IStreamClientEndpoint: ...

class _ISupportsExitSignalCapturing(Interface):
    _exitSignal: Optional[int]
