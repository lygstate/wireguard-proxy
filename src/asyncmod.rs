use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::sync::atomic::{self, AtomicI32};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_rustls::{rustls, rustls::Certificate, rustls::PrivateKey, webpki, TlsConnector};

use crate::*;

pub struct TcpUdpPipe {
    duplex: DuplexStream,
    rd: Receiver<Vec<u8>>,
    wr: Sender<Vec<u8>>,
}

fn from(_: sync::mpsc::error::SendError<Vec<u8>>) -> std::io::Error {
    return std::io::Error::last_os_error();
}

impl TcpUdpPipe {
    pub fn create_pair() -> (TcpUdpPipe, TcpUdpPipe) {
        let (duplex_0, duplex_1) = tokio::io::duplex(131_072);

        let (snd_0, rcv_0) = mpsc::channel::<Vec<u8>>(1_1024);
        let (snd_1, rcv_1) = mpsc::channel::<Vec<u8>>(1_1024);

        let a = TcpUdpPipe {
            duplex: duplex_0,
            rd: rcv_0,
            wr: snd_1,
        };

        let b = TcpUdpPipe {
            duplex: duplex_1,
            rd: rcv_1,
            wr: snd_0,
        };

        (a, b)
    }

    pub fn create_buf() -> [u8; 2050] {
        [0u8; 2050] // 2048 + 2 for len
    }

    pub async fn shuffle(self) -> std::io::Result<usize> {
        let mut udp_rd = self.rd;
        let mut recv_buf = TcpUdpPipe::create_buf();
        let tcp_stream = self.duplex;
        let (mut tcp_rd, mut tcp_wr) = tokio::io::split(tcp_stream);

        let udp_rd_future = async move {
            loop {
                while let Some(bytes) = udp_rd.recv().await {
                    let len = bytes.len();
                    recv_buf[0] = ((len >> 8) & 0xFF) as u8;
                    recv_buf[1] = (len & 0xFF) as u8;
                    recv_buf[2..(len + 2)].copy_from_slice(bytes.as_slice());
                    tcp_wr.write_all(&recv_buf[..(len + 2)]).await?;
                }
            }

            // Sometimes, the rust type inferencer needs
            // a little help
            #[allow(unreachable_code)]
            {
                unsafe {
                    std::hint::unreachable_unchecked();
                }
                Ok::<_, std::io::Error>(())
            }
        };

        let mut send_buf = TcpUdpPipe::create_buf();
        let udp_wr = self.wr;
        let udp_wr_future = async move {
            loop {
                tcp_rd.read_exact(&mut send_buf[..2]).await?;
                let len = ((send_buf[0] as usize) << 8) + send_buf[1] as usize;
                #[cfg(feature = "verbose")]
                println!("tcp expecting len: {}", len);
                tcp_rd.read_exact(&mut send_buf[..len]).await?;
                #[cfg(feature = "verbose")]
                println!("tcp got len: {}", len);
                if let Err(e) = udp_wr.send(send_buf[..len].to_vec()).await {
                    return Err(from(e));
                }
            }

            #[allow(unreachable_code)]
            {
                unsafe {
                    std::hint::unreachable_unchecked();
                }
                Ok::<_, std::io::Error>(())
            }
        };
        let join_result = tokio::try_join!(udp_rd_future, udp_wr_future);
        match join_result {
            Err(err) => Err(err),
            Ok(_) => Ok(0),
        }
    }
}

enum TcpConnection {
    // not pub because intern implementation
    Normal(tokio::net::TcpStream),
    Secure(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

impl TcpConnection {
    pub fn from_tcp_stream(tcp_stream: tokio::net::TcpStream) -> TcpConnection {
        TcpConnection::Normal(tcp_stream)
    }

    pub fn from_tls_tcp_stream(
        tls_tcp_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    ) -> TcpConnection {
        TcpConnection::Secure(tls_tcp_stream)
    }

    pub async fn connect(client: ProxyClient) -> std::io::Result<TcpConnection> {
        let tcp_stream = tokio::net::TcpStream::connect(&client.tcp_target).await?;
        if client.is_tls {
            let root_cert_store = rustls::RootCertStore::empty();
            let mut config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth(); // i guess this was previously the default?
            config
                .dangerous()
                .set_certificate_verifier(match client.pinnedpubkey {
                    Some(pinnedpubkey) => Arc::new(PinnedpubkeyCertVerifier {
                        pinnedpubkey: pinnedpubkey.to_owned(),
                    }),
                    None => Arc::new(DummyCertVerifier {}),
                });

            let default_server_name = "dummy.hostname";
            let server_name: rustls::ServerName = client
                .hostname
                .as_deref()
                .unwrap_or(default_server_name)
                .try_into()
                .unwrap_or(default_server_name.try_into().unwrap());
            //println!("hostname: {:?}", hostname);

            let connector = TlsConnector::from(Arc::new(config));
            let tcp_stream = connector.connect(server_name, tcp_stream).await?;
            Ok(TcpConnection::from_tls_tcp_stream(tcp_stream))
        } else {
            Ok(TcpConnection::from_tcp_stream(tcp_stream))
        }
    }
}

type WireguardConnectoinMap = HashMap<SocketAddr, (Sender<Vec<u8>>, Arc<AtomicI32>)>;

impl ProxyClient {
    pub fn update_connection_map(connection_map: &mut WireguardConnectoinMap) {
        let mut timeout_addresses = Vec::<SocketAddr>::new();
        for (k, (_, task_done)) in connection_map.into_iter() {
            if task_done.load(atomic::Ordering::Acquire) == 0 {
                timeout_addresses.push(*k);
            }
        }
        for k in timeout_addresses {
            connection_map.remove(&k);
        }
        connection_map.clear();
    }

    pub async fn start_async(&self) -> std::io::Result<usize> {
        let mut connection_map = WireguardConnectoinMap::new();

        let udp_socket = Arc::new(tokio::net::UdpSocket::bind(&self.udp_host).await?);
        let buf = &mut TcpUdpPipe::create_buf();
        loop {
            let recv_result =
                tokio::time::timeout(self.socket_timeout, udp_socket.recv_from(&mut buf[..])).await;
            if let Ok(Ok((len, src_addr))) = recv_result {
                if !connection_map.contains_key(&src_addr) {
                    let udp_socket_cloned = udp_socket.clone();
                    let src_addr_cloned = src_addr.clone();

                    let (pipe_outer, pipe_inner) = TcpUdpPipe::create_pair();
                    let outer_duplex = pipe_outer.duplex;
                    let rd = pipe_outer.rd;
                    let client_info = self.clone();
                    let task_done = Arc::new(AtomicI32::new(1));
                    let task_done_cloned = task_done.clone();
                    tokio::spawn(async move {
                        client_info
                            .shuffle(
                                udp_socket_cloned,
                                task_done_cloned,
                                src_addr_cloned,
                                outer_duplex,
                                pipe_inner,
                                rd,
                            )
                            .await
                    });

                    connection_map.insert(src_addr, (pipe_outer.wr, task_done));
                }
                if let Some((wr, _)) = connection_map.get(&src_addr) {
                    if let Err(e) = wr.send(buf[..len].to_vec()).await {
                        return Err(from(e));
                    }
                }
            } else if let Err(e) = recv_result {
                println!(
                    "There is udp socket receive timeout {} map size: {}",
                    e,
                    connection_map.len()
                );
                ProxyClient::update_connection_map(&mut connection_map);
            } else if let Ok(Err(e)) = recv_result {
                println!(
                    "There is udp socket error {} map size: {}",
                    e,
                    connection_map.len()
                );
                ProxyClient::update_connection_map(&mut connection_map);
            }
        }

        #[allow(unreachable_code)]
        {
            unsafe {
                std::hint::unreachable_unchecked();
            }
            Ok::<_, std::io::Error>(0)
        }
    }

    pub async fn shuffle(
        self,
        udp_socket: Arc<UdpSocket>,
        task_done: Arc<AtomicI32>,
        src_addr: SocketAddr,
        mut outer_duplex: DuplexStream,
        pipe_inner: TcpUdpPipe,
        mut rd: Receiver<Vec<u8>>,
    ) -> std::io::Result<usize> {
        println!("first packet from {}, connecting to that", src_addr);
        let socket_timeout = self.socket_timeout;
        let tcp_connection = TcpConnection::connect(self).await?;
        let (future0, future0_abort) = futures::future::abortable(async move {
            match tcp_connection {
                TcpConnection::Normal(mut tcp_stream) => {
                    tokio::io::copy_bidirectional(&mut tcp_stream, &mut outer_duplex).await
                }
                TcpConnection::Secure(mut tls_tcp_stream) => {
                    tokio::io::copy_bidirectional(&mut tls_tcp_stream, &mut outer_duplex).await
                }
            }
        });
        let (future1, future1_abort) = futures::future::abortable(async move {
            if let Err(e) = pipe_inner.shuffle().await {
                println!("wireguard shuffle finished with {}", e);
            }
        });
        let (future2, future2_abort) = futures::future::abortable(async move {
            loop {
                let recv_result = tokio::time::timeout(socket_timeout, rd.recv()).await;
                if let Ok(Some(v)) = recv_result {
                    udp_socket.send_to(&v, src_addr).await?;
                } else if let Err(e) = recv_result {
                    /* Receive timeout */
                    rd.close();
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        e.to_string(),
                    ));
                }
            }
            #[allow(unreachable_code)]
            {
                unsafe {
                    std::hint::unreachable_unchecked();
                }
                Ok::<_, std::io::Error>(())
            }
        });
        let join_result = tokio::try_join!(future0, future1, future2);
        let ret = match join_result {
            Ok(_) => Ok(0),
            Err(e) => {
                println!("shuffle done for {} {}", src_addr, e);
                Ok(0)
            }
        };
        task_done.store(0, atomic::Ordering::Release);
        future0_abort.abort();
        future1_abort.abort();
        future2_abort.abort();

        ret
    }

    pub fn start(&self) -> std::io::Result<usize> {
        let rt = Runtime::new()?;

        rt.block_on(async { self.start_async().await })
    }
}

struct DummyCertVerifier;

impl rustls::client::ServerCertVerifier for DummyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> core::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        // verify nothing, subject to MITM
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

struct PinnedpubkeyCertVerifier {
    pinnedpubkey: String,
}

fn pki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => rustls::Error::InvalidCertificateEncoding,
        InvalidSignatureForPublicKey => rustls::Error::InvalidCertificateSignature,
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            rustls::Error::InvalidCertificateSignatureType
        }
        e => rustls::Error::InvalidCertificateData(format!("invalid peer certificate: {}", e)),
    }
}

impl rustls::client::ServerCertVerifier for PinnedpubkeyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        certs: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> core::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        if certs.is_empty() {
            return Err(rustls::Error::NoCertificatesPresented);
        }
        let cert = webpki::TrustAnchor::try_from_cert_der(&certs[0].0).map_err(pki_error)?;

        //println!("spki.len(): {}", cert.spki.len());
        //println!("spki: {:?}", cert.spki);
        // todo: what is wrong with webpki? it returns *almost* the right answer but missing these leading bytes:
        // guess I'll open an issue... (I assume this is some type of algorithm identifying header or something)
        let mut pubkey: Vec<u8> = vec![48, 130, 1, 34];
        pubkey.extend(cert.spki);

        let pubkey = ring::digest::digest(&ring::digest::SHA256, &pubkey);
        let pubkey = base64::encode(pubkey);
        let pubkey = ["sha256//", &pubkey].join("");

        for key in self.pinnedpubkey.split(";") {
            if key == pubkey {
                return Ok(rustls::client::ServerCertVerified::assertion());
            }
        }

        Err(rustls::Error::General(format!(
            "pubkey '{}' not found in allowed list '{}'",
            pubkey, self.pinnedpubkey
        )))
    }
}

fn load_certs(path: &str) -> io::Result<Vec<Certificate>> {
    use rustls_pemfile::certs;
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &str) -> io::Result<Vec<PrivateKey>> {
    use rustls_pemfile::pkcs8_private_keys;
    pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

impl ProxyServer {
    pub async fn start_async(&self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(&self.tcp_host).await?;
        println!("Listening for connections on {}", &self.tcp_host);

        loop {
            let (stream, _) = listener.accept().await?;
            let client_handler = self.client_handler.clone();
            tokio::spawn(async move {
                client_handler
                    .handle_client_async(stream)
                    .await
                    .expect("error handling connection");
            });
        }

        #[allow(unreachable_code)]
        {
            unsafe {
                std::hint::unreachable_unchecked();
            }
            Ok(())
        }
    }

    pub fn start(&self) -> std::io::Result<()> {
        let rt = Runtime::new()?;

        rt.block_on(async { self.start_async().await })
    }

    pub async fn start_tls_async(&self, tls_key: &str, tls_cert: &str) -> std::io::Result<()> {
        let certs = load_certs(tls_key)?;
        let mut keys = load_keys(tls_cert)?;
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind(&self.tcp_host).await?;
        println!("Listening for TLS connections on {}", &self.tcp_host);

        loop {
            let (stream, _) = listener.accept().await?;
            let client_handler = self.client_handler.clone();
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let stream = acceptor
                    .accept(stream)
                    .await
                    .expect("failed to wrap with TLS?");

                client_handler
                    .handle_client_async(stream)
                    .await
                    .expect("error handling connection");
            });
        }

        #[allow(unreachable_code)]
        {
            unsafe {
                std::hint::unreachable_unchecked();
            }
            Ok(())
        }
    }

    pub fn start_tls(&self, tls_key: &str, tls_cert: &str) -> std::io::Result<()> {
        let rt = Runtime::new()?;

        rt.block_on(async { self.start_tls_async(tls_key, tls_cert).await })
    }
}

impl ProxyServerClientHandler {
    pub async fn handle_client_async<
        T: AsyncReadExt + AsyncWriteExt + std::marker::Unpin + std::marker::Send + 'static,
    >(
        &self,
        tcp_stream: T,
    ) -> std::io::Result<usize> {
        let _udp_socket =
            UdpSocket::from_std(self.udp_bind()?).expect("how could this tokio udp fail?");

        Ok(0)
    }
}
