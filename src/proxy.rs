use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::block_page::BLOCK_RESPONSE;
use crate::blocklist::{Blocklist, Verdict};
use crate::ca::Ca;
use crate::config::load_blocklist;
use crate::uri::{absolute_target, split_host_port};

pub const PROXY_HOST: &str = "127.0.0.1";
pub const PROXY_PORT: u16 = 8080;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const RELAY_BUF: usize = 32 * 1024;
const HEAD_MAX: usize = 64 * 1024;
const MAX_HEADERS: usize = 96;

const CONNECTED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BAD_GATEWAY: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

pub(crate) struct Proxy {
    list: watch::Sender<Arc<Blocklist>>,
    pub(crate) ca: Option<Ca>,
    connector: TlsConnector,
}

impl Proxy {
    pub(crate) fn new(list: Blocklist) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca = Ca::load(provider.clone())?;
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            list: watch::channel(Arc::new(list)).0,
            ca,
            connector: TlsConnector::from(Arc::new(client)),
        })
    }

    fn list(&self) -> Arc<Blocklist> {
        self.list.borrow().clone()
    }

    pub(crate) fn reload(&self) {
        match load_blocklist() {
            Ok(list) => {
                self.list.send_replace(Arc::new(list));
                info!("blocklist reloaded");
            }
            Err(e) => warn!("reload failed, keeping previous blocklist: {e:#}"),
        }
    }

    pub(crate) async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle(stream).await {
                            debug!("{peer}: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle(&self, mut client: TcpStream) -> Result<()> {
        client.set_nodelay(true)?;
        let (buf, end) = read_head(&mut client).await?;
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(&buf[..end])?;
        let target = req.path.context("missing request target")?;
        if req
            .method
            .is_some_and(|method| method.eq_ignore_ascii_case("CONNECT"))
        {
            self.connect(client, target).await
        } else {
            self.http(client, &req, target, &buf[end..]).await
        }
    }

    async fn connect(&self, mut client: TcpStream, target: &str) -> Result<()> {
        let (host, port) = split_host_port(target, 443);
        let list = self.list();
        match (list.verdict(host, None), &self.ca) {
            (Verdict::Block, Some(ca)) => {
                info!("blocked CONNECT {target}");
                client.write_all(CONNECTED).await?;
                let mut tls = accept(ca, host, client).await?;
                read_head(&mut tls).await?;
                tls.write_all(&BLOCK_RESPONSE).await?;
                tls.shutdown().await?;
                Ok(())
            }
            (Verdict::Block, None) => {
                info!("blocked CONNECT {target}");
                client.write_all(&BLOCK_RESPONSE).await?;
                Ok(())
            }
            (Verdict::Inspect, Some(ca)) => self.inspect(ca, client, host, port, &list).await,
            (verdict, _) => {
                if verdict == Verdict::Inspect {
                    warn!("{host}: path rules need the CA, tunnelling unfiltered");
                }
                let upstream = dial_or_502(&mut client, host, port).await?;
                client.write_all(CONNECTED).await?;
                relay(client, upstream).await
            }
        }
    }

    async fn inspect(
        &self,
        ca: &Ca,
        mut client: TcpStream,
        host: &str,
        port: u16,
        list: &Blocklist,
    ) -> Result<()> {
        client.write_all(CONNECTED).await?;
        let mut tls = accept(ca, host, client).await?;
        let (buf, end) = read_head(&mut tls).await?;
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(&buf[..end])?;
        let path = req.path.context("missing request target")?;

        if list.verdict(host, Some(path)) == Verdict::Block {
            info!("blocked https://{host}{path}");
            tls.write_all(&BLOCK_RESPONSE).await?;
            tls.shutdown().await?;
            return Ok(());
        }
        let mut upstream = match self.upstream(host, port).await {
            Ok(upstream) => upstream,
            Err(e) => {
                tls.write_all(BAD_GATEWAY).await?;
                return Err(e);
            }
        };
        upstream.write_all(&forward_head(&req, path)).await?;
        upstream.write_all(&buf[end..]).await?;
        relay(tls, upstream).await
    }

    async fn upstream(
        &self,
        host: &str,
        port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = dial(host, port).await?;
        let name = ServerName::try_from(host.to_owned())?;
        let tls = timeout(CONNECT_TIMEOUT, self.connector.connect(name, tcp)).await??;
        Ok(tls)
    }

    async fn http(
        &self,
        mut client: TcpStream,
        req: &httparse::Request<'_, '_>,
        target: &str,
        body: &[u8],
    ) -> Result<()> {
        let (host, port, path) = match absolute_target(target) {
            Some(parts) => parts,
            None => {
                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .context("missing host header")?;
                let (host, port) = split_host_port(host, 80);
                (host, port, Cow::Borrowed(target))
            }
        };
        if self.list().verdict(host, Some(&*path)) == Verdict::Block {
            info!("blocked http://{host}{path}");
            client.write_all(&BLOCK_RESPONSE).await?;
            return Ok(());
        }
        let mut upstream = dial_or_502(&mut client, host, port).await?;
        upstream.write_all(&forward_head(req, &path)).await?;
        upstream.write_all(body).await?;
        relay(client, upstream).await
    }
}

async fn accept(
    ca: &Ca,
    host: &str,
    stream: TcpStream,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    let acceptor = ca.acceptor(host)?;
    let tls = timeout(CONNECT_TIMEOUT, acceptor.accept(stream)).await??;
    Ok(tls)
}

async fn dial(host: &str, port: u16) -> Result<TcpStream> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect {host}:{port} timed out"))?
        .with_context(|| format!("connect {host}:{port}"))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn dial_or_502(client: &mut TcpStream, host: &str, port: u16) -> Result<TcpStream> {
    match dial(host, port).await {
        Ok(stream) => Ok(stream),
        Err(e) => {
            client.write_all(BAD_GATEWAY).await?;
            Err(e)
        }
    }
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(Vec<u8>, usize)> {
    let mut buf = Vec::with_capacity(2048);
    loop {
        let scanned = buf.len().saturating_sub(3);
        let read = timeout(CONNECT_TIMEOUT, stream.read_buf(&mut buf)).await??;
        ensure!(read > 0, "connection closed before request head");
        if let Some(i) = buf[scanned..].windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok((buf, scanned + i + 4));
        }
        ensure!(buf.len() < HEAD_MAX, "request head too large");
    }
}

async fn relay<A, B>(a: A, b: B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let (up, down) = tokio::join!(pipe(a_read, b_write), pipe(b_read, a_write));
    up.and(down)?;
    Ok(())
}

async fn pipe<R, W>(mut from: R, mut to: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let read = timeout(IDLE_TIMEOUT, from.read(&mut buf)).await??;
        if read == 0 {
            return to.shutdown().await;
        }
        to.write_all(&buf[..read]).await?;
    }
}

fn forward_head(req: &httparse::Request<'_, '_>, target: &str) -> Vec<u8> {
    let upgrade = req
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade"));
    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(req.method.unwrap_or("GET").as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for header in req.headers.iter() {
        let name = header.name;
        let proxy_only = name
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("proxy-"));
        let hop_by_hop = !upgrade
            && (name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("keep-alive"));
        if proxy_only || hop_by_hop {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value);
        out.extend_from_slice(b"\r\n");
    }
    if !upgrade {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}