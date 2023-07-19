Use Factory with reconnecting features for building db connection pool if reconnect flag is set to True.

PR#15956
Use ReconnectingClientFactory for building dbapi.ConnectionPool if the cp_reconnect set to true.

[Based on description of twisted](https://docs.twisted.org/en/twisted-18.7.0/core/howto/clients.html?highlight=ReconnectingClientFactory#reconnection)
>"However, most programs that want this functionality should implement ReconnectingClientFactory instead,
which tries to reconnect if a connection is lost or fails and which exponentially delays
repeated reconnect attempts."

!