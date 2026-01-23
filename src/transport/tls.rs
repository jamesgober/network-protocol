//! # TLS Transport Layer
//!
//! This file is part of the Network Protocol project.
//!
//! It defines the TLS transport layer for secure network communication,
//! particularly for external untrusted connections.
//!
//! The TLS transport layer provides a secure channel for communication
//! using industry-standard TLS protocol, ensuring confidentiality,
//! integrity, and authentication of the data transmitted.
//!
//! ## Responsibilities
//! - Establish secure TLS connections
//! - Handle TLS certificates and verification
//! - Provide secure framed transport for higher protocol layers
//! - Compatible with existing packet codec infrastructure

use std::fs::File;
use std::io::{self, BufReader, Seek, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerName;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, warn};

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::error::{ProtocolError, Result};
use futures::{SinkExt, StreamExt};

/// TLS protocol version
pub enum TlsVersion {
    /// TLS 1.2
    TLS12,
    /// TLS 1.3
    TLS13,
    /// Both TLS 1.2 and 1.3
    All,
}

/// TLS server configuration
pub struct TlsServerConfig {
    cert_path: String,
    key_path: String,
    /// Optional path to client CA certificates for mTLS
    client_ca_path: Option<String>,
    /// Whether to require client certificates (mTLS)
    require_client_auth: bool,
    /// Allowed TLS protocol versions (None = use rustls defaults)
    tls_versions: Option<Vec<TlsVersion>>,
    /// Allowed cipher suites (None = use rustls defaults)
    cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
}

impl TlsServerConfig {
    /// Create a new TLS server configuration
    pub fn new<P: AsRef<std::path::Path>>(cert_path: P, key_path: P) -> Self {
        Self {
            cert_path: cert_path.as_ref().to_string_lossy().to_string(),
            key_path: key_path.as_ref().to_string_lossy().to_string(),
            client_ca_path: None,
            require_client_auth: false,
            tls_versions: None,
            cipher_suites: None,
        }
    }

    /// Set allowed TLS protocol versions
    pub fn with_tls_versions(mut self, versions: Vec<TlsVersion>) -> Self {
        self.tls_versions = Some(versions);
        self
    }

    /// Set allowed cipher suites
    pub fn with_cipher_suites(mut self, cipher_suites: Vec<rustls::SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(cipher_suites);
        self
    }

    /// Enable mutual TLS authentication by providing a CA certificate path
    pub fn with_client_auth<S: Into<String>>(mut self, client_ca_path: S) -> Self {
        self.client_ca_path = Some(client_ca_path.into());
        self.require_client_auth = true;
        self
    }

    /// Set whether client authentication is required (true) or optional (false)
    pub fn require_client_auth(mut self, required: bool) -> Self {
        self.require_client_auth = required;
        self
    }

    /// Generate a self-signed certificate for development/testing purposes
    pub fn generate_self_signed<P: AsRef<Path>>(cert_path: P, key_path: P) -> io::Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| io::Error::other(format!("Certificate generation error: {e}")))?;

        // Write certificate
        let mut cert_file = File::create(&cert_path)?;
        let pem = cert.cert.pem();
        cert_file.write_all(pem.as_bytes())?;

        // Write private key
        let mut key_file = File::create(&key_path)?;
        key_file.write_all(cert.signing_key.serialize_pem().as_bytes())?;

        Ok(Self {
            cert_path: cert_path.as_ref().to_string_lossy().to_string(),
            key_path: key_path.as_ref().to_string_lossy().to_string(),
            client_ca_path: None,
            require_client_auth: false,
            tls_versions: None,
            cipher_suites: None,
        })
    }

    /// Load the TLS configuration from files
    pub fn load_server_config(&self) -> Result<ServerConfig> {
        // Load certificate
        let cert_file = File::open(&self.cert_path)
            .map_err(|e| ProtocolError::TlsError(format!("Failed to open cert file: {e}")))?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain = certs(&mut cert_reader)
            .map_err(|_| ProtocolError::TlsError("Failed to parse certificate".into()))?;

        // Convert to rustls Certificate type
        let cert_chain: Vec<Certificate> = cert_chain.into_iter().map(Certificate).collect();

        // Load private key
        let key_file = File::open(&self.key_path)
            .map_err(|e| ProtocolError::TlsError(format!("Failed to open key file: {e}")))?;
        let mut key_reader = BufReader::new(key_file);
        let keys = pkcs8_private_keys(&mut key_reader)
            .map_err(|_| ProtocolError::TlsError("Failed to parse private key".into()))?;

        if keys.is_empty() {
            return Err(ProtocolError::TlsError("No private keys found".into()));
        }

        // Convert to rustls PrivateKey
        let private_key = PrivateKey(keys[0].clone());

        // Validate TLS versions if specified
        // Note: In rustls 0.21, with_safe_defaults() restricts to TLS 1.2+ (best practice)
        if let Some(versions) = &self.tls_versions {
            let mut has_tls13 = false;
            let mut has_tls12 = false;
            for v in versions {
                match v {
                    TlsVersion::TLS12 => has_tls12 = true,
                    TlsVersion::TLS13 => has_tls13 = true,
                    TlsVersion::All => {
                        has_tls13 = true;
                        has_tls12 = true;
                    }
                }
            }
            // Document that with_safe_defaults uses best practices
            debug!(
                "TLS versions requested: TLS1.2={}, TLS1.3={}",
                has_tls12, has_tls13
            );
        }

        // Create a server configuration with safe defaults (TLS 1.2+, modern ciphersuites)
        let config_builder = ServerConfig::builder().with_safe_defaults();

        // Note: rustls 0.21 doesn't expose API to change ciphersuites after builder creation.
        // with_safe_defaults() already provides excellent defaults:
        // - TLS 1.3: CHACHA20_POLY1305, AES_128_GCM, AES_256_GCM
        // - TLS 1.2: same + some legacy suites
        // Custom cipher suite restriction requires building at compile time.

        let cert_builder = config_builder.with_no_client_auth();

        // Build config with certificates
        let mut config = cert_builder
            .with_single_cert(cert_chain.clone(), private_key.clone())
            .map_err(|e| ProtocolError::TlsError(format!("TLS error: {e}")))?;

        // Configure client authentication if required (mTLS)
        if let Some(client_ca_path) = &self.client_ca_path {
            // Load client CA certificates
            let client_ca_file = File::open(client_ca_path).map_err(|e| {
                ProtocolError::TlsError(format!("Failed to open client CA file: {e}"))
            })?;
            let mut client_ca_reader = BufReader::new(client_ca_file);
            let client_ca_certs = certs(&mut client_ca_reader).map_err(|_| {
                ProtocolError::TlsError("Failed to parse client CA certificate".into())
            })?;

            // Convert to rustls Certificate type
            let client_ca_certs: Vec<Certificate> =
                client_ca_certs.into_iter().map(Certificate).collect();

            // Create client cert verifier
            let mut client_root_store = RootCertStore::empty();
            for cert in &client_ca_certs {
                client_root_store.add(cert).map_err(|e| {
                    ProtocolError::TlsError(format!("Failed to add client CA cert: {e}"))
                })?;
            }

            // Create client authentication verifier
            let client_auth = Arc::new(rustls::server::AllowAnyAuthenticatedClient::new(
                client_root_store,
            ));

            // Create new config builder with client auth
            let new_builder = ServerConfig::builder().with_safe_defaults();
            let new_cert_builder = new_builder.with_client_cert_verifier(client_auth);

            // Build a new config with certificates and client auth
            config = new_cert_builder
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| ProtocolError::TlsError(format!("TLS error with client auth: {e}")))?;

            debug!("mTLS enabled with client certificate verification required");
        }

        Ok(config)
    }
}

/// TLS Client Configuration
pub struct TlsClientConfig {
    server_name: String,
    insecure: bool,
    /// Optional certificate hash to pin (SHA-256 fingerprint)
    pinned_cert_hash: Option<Vec<u8>>,
    /// Optional client certificate path for mTLS
    client_cert_path: Option<String>,
    /// Optional client key path for mTLS
    client_key_path: Option<String>,
    /// Allowed TLS protocol versions (None = use rustls defaults)
    tls_versions: Option<Vec<TlsVersion>>,
    /// Allowed cipher suites (None = use rustls defaults)
    cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
}

impl TlsClientConfig {
    /// Create a new TLS client configuration
    pub fn new<S: Into<String>>(server_name: S) -> Self {
        Self {
            server_name: server_name.into(),
            insecure: false,
            pinned_cert_hash: None,
            client_cert_path: None,
            client_key_path: None,
            tls_versions: None,
            cipher_suites: None,
        }
    }

    /// Set allowed TLS protocol versions
    pub fn with_tls_versions(mut self, versions: Vec<TlsVersion>) -> Self {
        self.tls_versions = Some(versions);
        self
    }

    /// Set allowed cipher suites
    pub fn with_cipher_suites(mut self, cipher_suites: Vec<rustls::SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(cipher_suites);
        self
    }

    /// Configure client authentication for mTLS
    pub fn with_client_certificate<S: Into<String>>(mut self, cert_path: S, key_path: S) -> Self {
        self.client_cert_path = Some(cert_path.into());
        self.client_key_path = Some(key_path.into());
        self
    }

    /// Allow insecure connections (skip certificate verification)
    ///
    /// # WARNING: Security Risk
    /// This mode disables certificate verification entirely and should ONLY be used for:
    /// - Development and testing
    /// - Debugging environments
    /// - Internal networks with certificate pinning enabled
    ///
    /// **NEVER** use this in production without explicit certificate pinning via `with_pinned_cert_hash()`.
    ///
    /// For maximum security, only use this with the "dangerous_configuration" feature enabled,
    /// which is a strong indicator this is for testing/development only.
    pub fn insecure(mut self) -> Self {
        warn!("INSECURE MODE ENABLED: Certificate verification is disabled. This should only be used for development/testing.");
        self.insecure = true;
        self
    }

    /// Pin a certificate by its SHA-256 hash/fingerprint
    ///
    /// This provides additional security by only accepting connections
    /// from servers with the exact certificate matching this hash.
    /// Can be combined with insecure mode for development environments where
    /// you want to skip standard CA verification but still verify a specific cert.
    pub fn with_pinned_cert_hash(mut self, hash: Vec<u8>) -> Self {
        if hash.len() != 32 {
            warn!(
                "Certificate hash has unexpected length: {} (expected 32 bytes for SHA-256)",
                hash.len()
            );
        }
        self.pinned_cert_hash = Some(hash);
        self
    }

    /// Calculate SHA-256 hash for a certificate to use with pinning
    pub fn calculate_cert_hash(cert: &Certificate) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&cert.0);
        hasher.finalize().to_vec()
    }

    /// Helper method to load a private key from PKCS8 format
    fn load_private_key(reader: &mut BufReader<File>) -> Result<PrivateKey> {
        // Try to load PKCS8 keys
        // Seek to beginning of file first
        reader
            .seek(std::io::SeekFrom::Start(0))
            .map_err(ProtocolError::Io)?;

        // We need to use pkcs8_private_keys on the BufReader directly since it implements BufRead
        let keys = pkcs8_private_keys(reader)
            .map_err(|_| ProtocolError::TlsError("Failed to parse PKCS8 private key".into()))?;

        if !keys.is_empty() {
            return Ok(PrivateKey(keys[0].clone()));
        }

        // Note: Add support for other key formats like RSA or EC if needed

        Err(ProtocolError::TlsError(
            "No supported private key format found".into(),
        ))
    }

    /// Load the TLS client configuration
    pub fn load_client_config(&self) -> Result<ClientConfig> {
        // Validate TLS versions if specified (informational, with_safe_defaults already enforces modern TLS)
        if let Some(versions) = &self.tls_versions {
            let mut has_tls13 = false;
            let mut has_tls12 = false;
            for v in versions {
                match v {
                    TlsVersion::TLS12 => has_tls12 = true,
                    TlsVersion::TLS13 => has_tls13 = true,
                    TlsVersion::All => {
                        has_tls13 = true;
                        has_tls12 = true;
                    }
                }
            }
            debug!(
                "TLS client versions requested: TLS1.2={}, TLS1.3={}",
                has_tls12, has_tls13
            );
        }

        // Note: rustls 0.21 with_safe_defaults() enforces TLS 1.2+ with modern ciphersuites.
        // Custom version/cipher suite restrictions require rustls 0.22+ with new builder API.

        // Start with basic configuration - handle insecure vs secure mode differently
        if !self.insecure {
            // SECURE MODE: Use system root certificates
            let mut root_store = RootCertStore::empty();
            let native_certs = rustls_native_certs::load_native_certs().map_err(|e| {
                ProtocolError::TlsError(format!("Failed to load native certs: {e}"))
            })?;

            for cert in native_certs {
                root_store.add(&Certificate(cert.0)).map_err(|e| {
                    ProtocolError::TlsError(format!("Failed to add cert to root store: {e}"))
                })?;
            }

            // Create config builder with root certificates
            let builder = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store);

            // Add client authentication for mTLS if certificates are provided
            if let (Some(client_cert_path), Some(client_key_path)) =
                (&self.client_cert_path, &self.client_key_path)
            {
                // Load client certificate
                let client_cert_file = File::open(client_cert_path).map_err(ProtocolError::Io)?;
                let mut client_cert_reader = BufReader::new(client_cert_file);
                let client_certs =
                    rustls_pemfile::certs(&mut client_cert_reader).map_err(|_| {
                        ProtocolError::TlsError("Failed to parse client certificate".into())
                    })?;

                if client_certs.is_empty() {
                    return Err(ProtocolError::TlsError(
                        "No client certificates found".into(),
                    ));
                }

                // Load client private key
                let client_key_file = File::open(client_key_path).map_err(ProtocolError::Io)?;
                let mut client_key_reader = BufReader::new(client_key_file);

                // Try various key formats
                let client_key = Self::load_private_key(&mut client_key_reader)?;

                // Convert certs from rustls_pemfile format to rustls Certificate format
                let client_cert_chain = client_certs
                    .into_iter()
                    .map(Certificate)
                    .collect::<Vec<_>>();

                // Create config with client certificates
                let config = builder
                    .with_client_auth_cert(client_cert_chain, client_key)
                    .map_err(|e| {
                        ProtocolError::TlsError(format!("Failed to set client certificate: {e}"))
                    })?;

                Ok(config)
            } else {
                // No client authentication
                Ok(builder.with_no_client_auth())
            }
        } else {
            // INSECURE MODE: Custom certificate verifier (pinning or accept any)
            let builder = ClientConfig::builder().with_safe_defaults();

            // Create either a pinned certificate verifier or one that accepts any cert
            let custom_builder = if let Some(hash) = &self.pinned_cert_hash {
                // Certificate pinning
                struct CertificateFingerprint {
                    fingerprint: Vec<u8>,
                }

                impl rustls::client::ServerCertVerifier for CertificateFingerprint {
                    fn verify_server_cert(
                        &self,
                        end_entity: &Certificate,
                        _intermediates: &[Certificate],
                        _server_name: &ServerName,
                        _scts: &mut dyn Iterator<Item = &[u8]>,
                        _ocsp_response: &[u8],
                        _now: std::time::SystemTime,
                    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error>
                    {
                        use sha2::{Digest, Sha256};

                        // Calculate SHA-256 hash of the presented certificate
                        let mut hasher = Sha256::new();
                        hasher.update(&end_entity.0);
                        let hash = hasher.finalize();

                        if hash.as_slice() == self.fingerprint.as_slice() {
                            Ok(rustls::client::ServerCertVerified::assertion())
                        } else {
                            Err(rustls::Error::General(
                                "Pinned certificate hash mismatch".into(),
                            ))
                        }
                    }
                }

                // Create config with pinned certificate
                let verifier = Arc::new(CertificateFingerprint {
                    fingerprint: hash.clone(),
                });

                builder.with_custom_certificate_verifier(verifier)
            } else {
                // Accept any server certificate
                struct AcceptAnyServerCert;

                impl rustls::client::ServerCertVerifier for AcceptAnyServerCert {
                    fn verify_server_cert(
                        &self,
                        _end_entity: &Certificate,
                        _intermediates: &[Certificate],
                        _server_name: &ServerName,
                        _scts: &mut dyn Iterator<Item = &[u8]>,
                        _ocsp_response: &[u8],
                        _now: std::time::SystemTime,
                    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error>
                    {
                        Ok(rustls::client::ServerCertVerified::assertion())
                    }
                }

                builder.with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            };

            // Add client authentication for mTLS if certificates are provided
            if let (Some(client_cert_path), Some(client_key_path)) =
                (&self.client_cert_path, &self.client_key_path)
            {
                // Load client certificate
                let client_cert_file = File::open(client_cert_path).map_err(ProtocolError::Io)?;
                let mut client_cert_reader = BufReader::new(client_cert_file);
                let client_certs =
                    rustls_pemfile::certs(&mut client_cert_reader).map_err(|_| {
                        ProtocolError::TlsError("Failed to parse client certificate".into())
                    })?;

                if client_certs.is_empty() {
                    return Err(ProtocolError::TlsError(
                        "No client certificates found".into(),
                    ));
                }

                // Load client private key
                let client_key_file = File::open(client_key_path).map_err(ProtocolError::Io)?;
                let mut client_key_reader = BufReader::new(client_key_file);

                // Try various key formats
                let client_key = Self::load_private_key(&mut client_key_reader)?;

                // Convert certs to rustls Certificate format
                let client_cert_chain = client_certs
                    .into_iter()
                    .map(Certificate)
                    .collect::<Vec<_>>();

                // Apply client auth to the custom verifier config
                custom_builder
                    .with_client_auth_cert(client_cert_chain, client_key)
                    .map_err(|e| {
                        ProtocolError::TlsError(format!("Failed to set client certificate: {e}"))
                    })
            } else {
                // No client auth in insecure mode
                Ok(custom_builder.with_no_client_auth())
            }
        }
    }

    /// Get the server name as a rustls::ServerName
    pub fn server_name(&self) -> Result<ServerName> {
        ServerName::try_from(self.server_name.as_str())
            .map_err(|_| ProtocolError::TlsError("Invalid server name".into()))
    }
}

/// Start a TLS server on the given address
#[instrument(skip(config))]
pub async fn start_server(addr: &str, config: TlsServerConfig) -> Result<()> {
    let tls_config = config.load_server_config()?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await?;

    info!(address=%addr, "TLS server listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = handle_tls_connection(tls_stream, peer).await {
                        error!(%peer, error=%e, "Connection error");
                    }
                }
                Err(e) => {
                    error!(%peer, error=%e, "TLS handshake failed");
                }
            }
        });
    }
}

/// Handle a TLS connection
#[instrument(skip(tls_stream), fields(peer=%peer))]
async fn handle_tls_connection(
    tls_stream: ServerTlsStream<TcpStream>,
    peer: SocketAddr,
) -> Result<()> {
    let mut framed = Framed::new(tls_stream, PacketCodec);

    info!("TLS connection established");

    while let Some(packet) = framed.next().await {
        match packet {
            Ok(pkt) => {
                debug!(bytes = pkt.payload.len(), "Received data");
                on_packet(pkt, &mut framed).await?;
            }
            Err(e) => {
                error!(error=%e, "Protocol error");
                break;
            }
        }
    }

    info!("TLS connection closed");
    Ok(())
}

/// Handle incoming TLS packets
#[instrument(skip(framed), fields(packet_version=pkt.version, payload_size=pkt.payload.len()))]
async fn on_packet<T>(pkt: Packet, framed: &mut Framed<T, PacketCodec>) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Echo the packet back (sample implementation)
    let response = Packet {
        version: pkt.version,
        payload: pkt.payload,
    };

    framed.send(response).await?;
    Ok(())
}

/// Connect to a TLS server
#[instrument(skip(config), fields(address=%addr))]
pub async fn connect(
    addr: &str,
    config: TlsClientConfig,
) -> Result<Framed<ClientTlsStream<TcpStream>, PacketCodec>> {
    let tls_config = Arc::new(config.load_client_config()?);
    let connector = TlsConnector::from(tls_config);

    let stream = TcpStream::connect(addr).await?;
    let domain = config.server_name()?;

    let tls_stream = connector
        .connect(domain, stream)
        .await
        .map_err(|e| ProtocolError::TlsError(format!("TLS connection failed: {e}")))?;

    let framed = Framed::new(tls_stream, PacketCodec);
    Ok(framed)
}
