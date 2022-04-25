use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio_rustls::{rustls, rustls::Certificate, rustls::PrivateKey, webpki, TlsConnector};

use std::convert::TryInto;
use std::fs::File;
use std::io::{self, BufReader};

use crate::*;

pub struct TcpUdpPipe<
    T: AsyncReadExt + AsyncWriteExt + std::marker::Unpin + std::marker::Send + 'static,
> {
    buf: [u8; 2050], // 2048 + 2 for len
    tcp_stream: T,
    udp_socket: UdpSocket,
}

impl<T: AsyncReadExt + AsyncWriteExt + std::marker::Unpin + std::marker::Send + 'static>
    TcpUdpPipe<T>
{
    pub fn new(tcp_stream: T, udp_socket: UdpSocket) -> TcpUdpPipe<T> {
        TcpUdpPipe {
            tcp_stream,
            udp_socket,
            buf: [0u8; 2050],
        }
    }

    pub async fn shuffle_after_first_udp(mut self) -> std::io::Result<usize> {
        let (len, src_addr) = self.udp_socket.recv_from(&mut self.buf[2..]).await?;

        println!("first packet from {}, connecting to that", src_addr);
        self.udp_socket.connect(src_addr).await?;

        send_udp(&mut self.buf, &mut self.tcp_stream, len).await?;

        self.shuffle().await
    }

    pub async fn shuffle(self) -> std::io::Result<usize> {
        // todo: investigate https://docs.rs/tokio/0.2.22/tokio/net/struct.TcpStream.html#method.into_split
        let (mut tcp_rd, mut tcp_wr) = tokio::io::split(self.tcp_stream);
        let udp_rd = Arc::new(self.udp_socket);
        let udp_wr = udp_rd.clone();
        let mut recv_buf = self.buf.clone(); // or zeroed or?

        tokio::spawn(async move {
            loop {
                let len = udp_rd.recv(&mut recv_buf[2..]).await?;
                send_udp(&mut recv_buf, &mut tcp_wr, len).await?;
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
        });

        let mut send_buf = self.buf.clone(); // or zeroed or?

        loop {
            tcp_rd.read_exact(&mut send_buf[..2]).await?;
            let len = ((send_buf[0] as usize) << 8) + send_buf[1] as usize;
            #[cfg(feature = "verbose")]
            println!("tcp expecting len: {}", len);
            tcp_rd.read_exact(&mut send_buf[..len]).await?;
            #[cfg(feature = "verbose")]
            println!("tcp got len: {}", len);
            udp_wr.send(&send_buf[..len]).await?;
        }

        #[allow(unreachable_code)]
        {
            unsafe {
                std::hint::unreachable_unchecked();
            }
            Ok(0)
        }
    }
}

async fn send_udp<T: AsyncWriteExt + std::marker::Unpin + 'static>(
    buf: &mut [u8; 2050],
    tcp_stream: &mut T,
    len: usize,
) -> std::io::Result<()> {
    #[cfg(feature = "verbose")]
    println!("udp got len: {}", len);

    buf[0] = ((len >> 8) & 0xFF) as u8;
    buf[1] = (len & 0xFF) as u8;

    // todo: tcp_stream.write_all(&buf[..len + 2]).await
    Ok(tcp_stream.write_all(&buf[..len + 2]).await?)
    // todo: do this? self.tcp_stream.flush()
}

impl ProxyClient {
    pub async fn start_async(&self) -> std::io::Result<usize> {
        let tcp_stream = self.tcp_connect().await?;

        let udp_socket = self.udp_bind().await?;

        TcpUdpPipe::new(tcp_stream, udp_socket)
            .shuffle_after_first_udp()
            .await
    }

    pub fn start(&self) -> std::io::Result<usize> {
        let rt = Runtime::new()?;

        rt.block_on(async { self.start_async().await })
    }

    pub async fn start_tls_async(
        &self,
        hostname: Option<&str>,
        pinnedpubkey: Option<&str>,
    ) -> std::io::Result<usize> {
        let root_cert_store = rustls::RootCertStore::empty();
        let mut config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(); // i guess this was previously the default?
        config
            .dangerous()
            .set_certificate_verifier(match pinnedpubkey {
                Some(pinnedpubkey) => Arc::new(PinnedpubkeyCertVerifier {
                    pinnedpubkey: pinnedpubkey.to_owned(),
                }),
                None => Arc::new(DummyCertVerifier {}),
            });

        let default_server_name = "dummy.hostname";
        let server_name: rustls::ServerName = hostname
            .unwrap_or("dummy.hostname")
            .try_into()
            .unwrap_or(default_server_name.try_into().unwrap());
        //println!("hostname: {:?}", hostname);

        let connector = TlsConnector::from(Arc::new(config));

        let tcp_stream = self.tcp_connect().await?;

        let tcp_stream = connector.connect(server_name, tcp_stream).await?;

        let udp_socket = self.udp_bind().await?;

        // we want to wait for first udp packet from client first, to set the target to respond to
        TcpUdpPipe::new(tcp_stream, udp_socket)
            .shuffle_after_first_udp()
            .await
    }

    pub fn start_tls(
        &self,
        hostname: Option<&str>,
        pinnedpubkey: Option<&str>,
    ) -> std::io::Result<usize> {
        let rt = Runtime::new()?;

        rt.block_on(async { self.start_tls_async(hostname, pinnedpubkey).await })
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
        TcpUdpPipe::new(
            tcp_stream,
            UdpSocket::from_std(self.udp_bind()?).expect("how could this tokio udp fail?"),
        )
        .shuffle()
        .await
    }
}
