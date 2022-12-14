use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::{
    io::Cursor,
    sync::{Arc, Mutex},
    task::{self, Poll},
};

use anyhow::{bail, Error};
use futures::{FutureExt, TryFutureExt};
use futures_util::stream::StreamExt;
use http::Uri;
use hyper::client::connect::Connection;
use hyper::client::connect::{Connected, HttpConnector};
use hyper::server::conn::Http;
use hyper::service::Service;
use hyper::Client;
use hyper_tls::HttpsConnector;
use hyper_tls::MaybeHttpsStream;
use log::info;
use native_tls::TlsConnector;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector as AsyncTlsConnector;
use trust_dns_resolver::error::ResolveErrorKind;

pub struct Endpoint {
    pub host: String,
    pub port: u16,

    pub host_header: String,
    pub tls_name: String,
}

#[derive(Clone)]
pub struct MatrixResolver {
    resolver: trust_dns_resolver::TokioAsyncResolver,
    http_client: Client<HttpsConnector<HttpConnector>>,
}

impl MatrixResolver {
    pub fn new() -> Result<MatrixResolver, Error> {
        let http_client = hyper::Client::builder().build(HttpsConnector::new());

        MatrixResolver::with_client(http_client)
    }

    pub fn with_client(
        http_client: Client<HttpsConnector<HttpConnector>>,
    ) -> Result<MatrixResolver, Error> {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;

        Ok(MatrixResolver {
            resolver,
            http_client,
        })
    }

    /// Does SRV lookup
    pub async fn resolve_server_name_from_uri(&self, uri: &Uri) -> Result<Vec<Endpoint>, Error> {
        let host = uri.host().expect("URI has no host").to_string();
        let port = uri.port_u16();

        self.resolve_server_name_from_host_port(host, port).await
    }

    pub async fn resolve_server_name_from_host_port(
        &self,
        mut host: String,
        mut port: Option<u16>,
    ) -> Result<Vec<Endpoint>, Error> {
        let mut authority = if let Some(p) = port {
            format!("{}:{}", host, p)
        } else {
            host.to_string()
        };

        // If a literal IP or includes port then we shortcircuit.
        if host.parse::<IpAddr>().is_ok() || port.is_some() {
            return Ok(vec![Endpoint {
                host: host.to_string(),
                port: port.unwrap_or(8448),

                host_header: authority.to_string(),
                tls_name: host.to_string(),
            }]);
        }

        // Do well-known delegation lookup.
        if let Some(server) = get_well_known(&self.http_client, &host).await {
            let a = http::uri::Authority::from_str(&server.server)?;
            host = a.host().to_string();
            port = a.port_u16();
            authority = a.to_string();
        }

        // If a literal IP or includes port then we shortcircuit.
        if host.parse::<IpAddr>().is_ok() || port.is_some() {
            return Ok(vec![Endpoint {
                host: host.clone(),
                port: port.unwrap_or(8448),

                host_header: authority.to_string(),
                tls_name: host.clone(),
            }]);
        }

        let result = self
            .resolver
            .srv_lookup(format!("_matrix._tcp.{}", host))
            .await;

        let records = match result {
            Ok(records) => records,
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    return Ok(vec![Endpoint {
                        host: host.clone(),
                        port: 8448,
                        host_header: authority.to_string(),
                        tls_name: host.clone(),
                    }])
                }
                _ => return Err(err.into()),
            },
        };

        let mut priority_map: BTreeMap<u16, Vec<_>> = BTreeMap::new();

        let mut count = 0;
        for record in records {
            count += 1;
            let priority = record.priority();
            priority_map.entry(priority).or_default().push(record);
        }

        let mut results = Vec::with_capacity(count);

        for (_priority, records) in priority_map {
            // TODO: Correctly shuffle records
            results.extend(records.into_iter().map(|record| Endpoint {
                host: record.target().to_utf8(),
                port: record.port(),

                host_header: host.to_string(),
                tls_name: host.to_string(),
            }))
        }

        Ok(results)
    }
}

async fn get_well_known<C>(http_client: &Client<C>, host: &str) -> Option<WellKnownServer>
where
    C: Service<Uri> + Clone + Sync + Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    C::Future: Unpin + Send,
    C::Response: AsyncRead + AsyncWrite + Connection + Unpin + Send + 'static,
{
    // TODO: Add timeout.

    let uri = hyper::Uri::builder()
        .scheme("https")
        .authority(host)
        .path_and_query("/.well-known/matrix/server")
        .build()
        .ok()?;

    let mut body = http_client.get(uri).await.ok()?.into_body();

    let mut vec = Vec::new();
    while let Some(next) = body.next().await {
        let chunk = next.ok()?;
        vec.extend(chunk);
    }

    serde_json::from_slice(&vec).ok()?
}

#[derive(Deserialize)]
struct WellKnownServer {
    #[serde(rename = "m.server")]
    server: String,
}

#[derive(Clone)]
pub struct MatrixConnector {
    resolver: MatrixResolver,
}

impl MatrixConnector {
    pub fn with_resolver(resolver: MatrixResolver) -> MatrixConnector {
        MatrixConnector { resolver }
    }
}

impl Service<Uri> for MatrixConnector {
    type Response = MaybeHttpsStream<TcpStream>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let resolver = self.resolver.clone();

        if dst.scheme_str() != Some("matrix") {
            return HttpsConnector::new()
                .call(dst)
                .map_err(|e| Error::msg(e))
                .boxed();
        }

        async move {
            let endpoints = resolver
                .resolve_server_name_from_host_port(
                    dst.host().expect("hostname").to_string(),
                    dst.port_u16(),
                )
                .await?;

            for endpoint in endpoints {
                match try_connecting(&dst, &endpoint).await {
                    Ok(r) => return Ok(r),
                    // Errors here are not unexpected, and we just move on
                    // with our lives.
                    Err(e) => info!(
                        "Failed to connect to {} via {}:{} because {}",
                        dst.host().expect("hostname"),
                        endpoint.host,
                        endpoint.port,
                        e,
                    ),
                }
            }

            bail!(
                "failed to resolve host: {:?} port {:?}",
                dst.host(),
                dst.port()
            )
        }
        .boxed()
    }
}

/// Attempts to connect to a particular endpoint.
async fn try_connecting(
    dst: &Uri,
    endpoint: &Endpoint,
) -> Result<MaybeHttpsStream<TcpStream>, Error> {
    let tcp = TcpStream::connect((&endpoint.host as &str, endpoint.port)).await?;

    let connector: AsyncTlsConnector = if dst.host().expect("hostname").contains("localhost") {
        TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()?
            .into()
    } else {
        TlsConnector::new().unwrap().into()
    };

    let tls = connector.connect(&endpoint.tls_name, tcp).await?;

    Ok(tls.into())
}

/// A connector that reutrns a connection which returns 200 OK to all connections.
#[derive(Clone)]
pub struct TestConnector;

impl Service<Uri> for TestConnector {
    type Response = TestConnection;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        // This connector is always ready, but others might not be.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _dst: Uri) -> Self::Future {
        let (client, server) = TestConnection::double_ended();

        {
            let service = hyper::service::service_fn(|_| async move {
                Ok(hyper::Response::new(hyper::Body::from("Hello World")))
                    as Result<_, hyper::http::Error>
            });
            let fut = Http::new().serve_connection(server, service);
            tokio::spawn(fut);
        }

        futures::future::ok(client).boxed()
    }
}

#[derive(Default)]
struct TestConnectionInner {
    outbound_buffer: Cursor<Vec<u8>>,
    inbound_buffer: Cursor<Vec<u8>>,
    wakers: Vec<futures::task::Waker>,
}

/// A in memory connection for use with tests.
#[derive(Clone, Default)]
pub struct TestConnection {
    inner: Arc<Mutex<TestConnectionInner>>,
    direction: bool,
}

impl TestConnection {
    pub fn double_ended() -> (TestConnection, TestConnection) {
        let inner: Arc<Mutex<TestConnectionInner>> = Arc::default();

        let a = TestConnection {
            inner: inner.clone(),
            direction: false,
        };

        let b = TestConnection {
            inner,
            direction: true,
        };

        (a, b)
    }
}

impl AsyncRead for TestConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut conn = self.inner.lock().expect("mutex");

        let buffer = if self.direction {
            &mut conn.inbound_buffer
        } else {
            &mut conn.outbound_buffer
        };

        let bytes_read = std::io::Read::read(buffer, buf.initialize_unfilled())?;
        buf.advance(bytes_read);
        if bytes_read > 0 {
            Poll::Ready(Ok(()))
        } else {
            conn.wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl AsyncWrite for TestConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut conn = self.inner.lock().expect("mutex");

        if self.direction {
            conn.outbound_buffer.get_mut().extend_from_slice(buf);
        } else {
            conn.inbound_buffer.get_mut().extend_from_slice(buf);
        }

        for waker in conn.wakers.drain(..) {
            waker.wake()
        }

        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut conn = self.inner.lock().expect("mutex");

        if self.direction {
            Pin::new(&mut conn.outbound_buffer).poll_flush(cx)
        } else {
            Pin::new(&mut conn.inbound_buffer).poll_flush(cx)
        }
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut conn = self.inner.lock().expect("mutex");

        if self.direction {
            Pin::new(&mut conn.outbound_buffer).poll_shutdown(cx)
        } else {
            Pin::new(&mut conn.inbound_buffer).poll_shutdown(cx)
        }
    }
}

impl Connection for TestConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

#[tokio::test]
async fn test_memory_connection() {
    let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(TestConnector);

    let response = client
        .get("http://localhost".parse().unwrap())
        .await
        .unwrap();

    assert!(response.status().is_success());

    let bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(&bytes[..], b"Hello World");
}
