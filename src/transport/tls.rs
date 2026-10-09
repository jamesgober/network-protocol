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

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, warn};

use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::error::{ProtocolError, Result};
use crate::utils::timeout::HANDSHAKE_TIMEOUT;
use futures::{SinkExt, StreamExt};

// Custom certificate verifiers.
//
// Both verifiers replace only the certificate *validation* step (chain building and
// hostname checks). They still verify the handshake signature with the provider's
// signature algorithms, which is what proves that the server holds the private key
// for the certificate it presented. Without that check a pinned certificate, which is
// public, could be replayed by any server.

/// Accepts only a server certificate whose SHA-256 fingerprint matches the pin.
#[derive(Debug)]
struct CertificateFingerprint {
    fingerprint: Vec<u8>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CertificateFingerprint {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(end_entity);
        let hash = hasher.finalize();

        if hash.as_slice() == self.fingerprint.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Pinned certificate hash mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Full CA and hostname validation through webpki, plus a pinned SHA-256 fingerprint
/// of the end-entity certificate. Used when a pin is set without `insecure()`, so the
/// pin narrows normal validation instead of replacing it.
#[derive(Debug)]
struct PinnedWebPkiVerifier {
    inner: Arc<WebPkiServerVerifier>,
    fingerprint: Vec<u8>,
}

impl ServerCertVerifier for PinnedWebPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if TlsServerConfig::calculate_cert_hash(end_entity) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Pinned certificate hash mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Accepts any server certificate (insecure mode without a pin), but still requires a
/// valid handshake signature from the key in that certificate.
#[derive(Debug)]
struct AcceptAnyServerCert {
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// The crypto provider used by every TLS config and verifier in this module.
///
/// rustls APIs without a `_with_provider` suffix fall back to the process-level default
/// provider, which panics when more than one rustls crypto backend is compiled in and
/// none has been installed. Always pass this provider explicitly instead.
fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Resolves the versions and cipher suites requested with `with_tls_versions()` and
/// `with_cipher_suites()` into the protocol versions to enable and a provider whose
/// cipher suites are restricted to the requested ones.
///
/// `None` means the rustls defaults. Cipher suites are matched by their IANA identifier
/// against the suites of [`crypto_provider()`], keeping that provider's preference order.
/// Requests that leave nothing usable are rejected here rather than falling back to the
/// defaults.
fn resolve_protocol_settings(
    tls_versions: Option<&[TlsVersion]>,
    cipher_suites: Option<&[rustls::SupportedCipherSuite]>,
) -> Result<(
    Arc<CryptoProvider>,
    Vec<&'static rustls::SupportedProtocolVersion>,
)> {
    let versions: Vec<&'static rustls::SupportedProtocolVersion> = match tls_versions {
        None => rustls::DEFAULT_VERSIONS.to_vec(),
        Some(requested) => {
            let mut has_tls13 = false;
            let mut has_tls12 = false;
            for v in requested {
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
                "TLS versions requested: TLS1.2={}, TLS1.3={}",
                has_tls12, has_tls13
            );

            let mut versions = Vec::with_capacity(2);
            if has_tls13 {
                versions.push(&rustls::version::TLS13);
            }
            if has_tls12 {
                versions.push(&rustls::version::TLS12);
            }
            if versions.is_empty() {
                return Err(ProtocolError::TlsError(
                    "No TLS protocol versions configured: with_tls_versions() was given an empty list"
                        .into(),
                ));
            }
            versions
        }
    };

    let mut provider = CryptoProvider::clone(&crypto_provider());
    if let Some(requested) = cipher_suites {
        for suite in requested {
            if !provider
                .cipher_suites
                .iter()
                .any(|s| s.suite() == suite.suite())
            {
                warn!(suite = ?suite.suite(), "Requested cipher suite is not supported and was ignored");
            }
        }
        provider
            .cipher_suites
            .retain(|s| requested.iter().any(|r| r.suite() == s.suite()));
        if provider.cipher_suites.is_empty() {
            return Err(ProtocolError::TlsError(
                "No supported cipher suites configured: none of the suites given to with_cipher_suites() are available"
                    .into(),
            ));
        }
        debug!(
            suites = ?provider.cipher_suites.iter().map(|s| s.suite()).collect::<Vec<_>>(),
            "TLS cipher suites restricted"
        );
    }

    if !provider
        .cipher_suites
        .iter()
        .any(|s| versions.contains(&s.version()))
    {
        return Err(ProtocolError::TlsError(
            "None of the configured cipher suites can be used with the configured TLS versions"
                .into(),
        ));
    }

    Ok((Arc::new(provider), versions))
}

/// Helper function to load a private key from PKCS8 format
fn load_private_key(reader: &mut BufReader<File>) -> Result<PrivateKeyDer<'static>> {
    // Try to load PKCS8 keys
    // Seek to beginning of file first
    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(ProtocolError::Io)?;

    // Collect every PKCS8 private key section in the PEM input
    let keys: std::result::Result<Vec<_>, _> =
        PrivatePkcs8KeyDer::pem_reader_iter(reader).collect();
    let keys =
        keys.map_err(|_| ProtocolError::TlsError("Failed to parse PKCS8 private key".into()))?;

    if !keys.is_empty() {
        return Ok(PrivateKeyDer::Pkcs8(keys[0].clone_key()));
    }

    // Note: Add support for other key formats like RSA or EC if needed

    Err(ProtocolError::TlsError(
        "No supported private key found: the key file must hold a PEM \"PRIVATE KEY\" (PKCS#8) block"
            .into(),
    ))
}

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
    /// ALPN protocols to advertise (default: ["h2", "http/1.1"])
    alpn_protocols: Option<Vec<Vec<u8>>>,
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
            alpn_protocols: Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        }
    }

    /// Set allowed TLS protocol versions
    ///
    /// Only the listed versions are enabled. An empty list is rejected when the
    /// config is loaded.
    pub fn with_tls_versions(mut self, versions: Vec<TlsVersion>) -> Self {
        self.tls_versions = Some(versions);
        self
    }

    /// Set allowed cipher suites
    ///
    /// Only the listed suites are enabled, matched by suite identifier and kept in this
    /// crate's preference order. Loading the config fails if none of them is supported,
    /// or if none of them can be used with the enabled TLS versions.
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
    ///
    /// Client certificates are verified against the CA given to `with_client_auth()`,
    /// which also sets this to `true`. Call it after `with_client_auth()` to make client
    /// authentication optional: clients without a certificate are then accepted, but a
    /// certificate that is presented must still be signed by the client CA.
    ///
    /// `require_client_auth(true)` without `with_client_auth()` has no CA to verify
    /// against, so `load_server_config()` returns an error instead of silently accepting
    /// clients without a certificate.
    pub fn require_client_auth(mut self, required: bool) -> Self {
        self.require_client_auth = required;
        self
    }

    /// Set ALPN protocols to advertise during TLS handshake
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = Some(protocols);
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

        // Write private key, readable by the owner only on Unix
        let mut key_file = create_private_key_file(key_path.as_ref())?;
        key_file.write_all(cert.signing_key.serialize_pem().as_bytes())?;

        Ok(Self {
            cert_path: cert_path.as_ref().to_string_lossy().to_string(),
            key_path: key_path.as_ref().to_string_lossy().to_string(),
            client_ca_path: None,
            require_client_auth: false,
            tls_versions: None,
            cipher_suites: None,
            alpn_protocols: Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        })
    }

    /// Load the TLS configuration from files
    ///
    /// # Errors
    /// Returns `ProtocolError::TlsError` if a file cannot be read or parsed, if the
    /// version or cipher-suite settings leave nothing usable, or if client
    /// authentication is required without a client CA (see `require_client_auth()`).
    pub fn load_server_config(&self) -> Result<ServerConfig> {
        // Required client authentication needs a CA to verify client certificates
        // against. Without one, rustls would be built with no client auth at all and
        // every client would be accepted, so refuse the configuration instead.
        if self.require_client_auth && self.client_ca_path.is_none() {
            return Err(ProtocolError::TlsError(
                "client authentication is required but no client CA is configured: call \
                 with_client_auth(\"<client-ca.pem>\") with the CA that signs client \
                 certificates, or drop require_client_auth(true)"
                    .into(),
            ));
        }

        // Load certificate
        let cert_file = File::open(&self.cert_path)
            .map_err(|e| ProtocolError::TlsError(format!("Failed to open cert file: {e}")))?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain: std::result::Result<Vec<_>, _> =
            CertificateDer::pem_reader_iter(&mut cert_reader).collect();
        let cert_chain: Vec<CertificateDer<'static>> = cert_chain
            .map_err(|_| ProtocolError::TlsError("Failed to parse certificate".into()))?;

        if cert_chain.is_empty() {
            return Err(ProtocolError::TlsError("No certificates found".into()));
        }

        // Load private key
        let key_file = File::open(&self.key_path)
            .map_err(|e| ProtocolError::TlsError(format!("Failed to open key file: {e}")))?;
        let mut key_reader = BufReader::new(key_file);
        let private_key = load_private_key(&mut key_reader)?;

        let (provider, versions) =
            resolve_protocol_settings(self.tls_versions.as_deref(), self.cipher_suites.as_deref())?;
        let config_builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .map_err(|e| {
                ProtocolError::TlsError(format!("Failed to configure TLS protocol versions: {e}"))
            })?;

        // Configure client authentication (mTLS) if a client CA was given
        let cert_builder = if let Some(client_ca_path) = &self.client_ca_path {
            // Load client CA certificates
            let client_ca_file = File::open(client_ca_path).map_err(|e| {
                ProtocolError::TlsError(format!("Failed to open client CA file: {e}"))
            })?;
            let mut client_ca_reader = BufReader::new(client_ca_file);
            let client_ca_certs: std::result::Result<Vec<_>, _> =
                CertificateDer::pem_reader_iter(&mut client_ca_reader).collect();
            let client_ca_certs: Vec<CertificateDer<'static>> = client_ca_certs.map_err(|_| {
                ProtocolError::TlsError("Failed to parse client CA certificate".into())
            })?;

            if client_ca_certs.is_empty() {
                return Err(ProtocolError::TlsError(
                    "No client CA certificates found".into(),
                ));
            }

            // Create client cert verifier
            let mut client_root_store = RootCertStore::empty();
            for cert in client_ca_certs {
                client_root_store.add(cert).map_err(|e| {
                    ProtocolError::TlsError(format!("Failed to add client CA cert: {e}"))
                })?;
            }

            // Create client authentication verifier using WebPkiClientVerifier.
            // The provider is passed explicitly: `WebPkiClientVerifier::builder` uses the
            // process-level default, which panics when it cannot be chosen automatically.
            let mut verifier_builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(client_root_store),
                provider,
            );
            if !self.require_client_auth {
                // Optional client auth: a client without a certificate is accepted, but a
                // certificate that is presented must still chain to the client CA.
                verifier_builder = verifier_builder.allow_unauthenticated();
            }
            let client_auth = verifier_builder.build().map_err(|e| {
                ProtocolError::TlsError(format!("Failed to build client verifier: {e}"))
            })?;

            if self.require_client_auth {
                debug!("mTLS enabled with client certificate verification required");
            } else {
                debug!("mTLS enabled with optional client certificate verification");
            }
            config_builder.with_client_cert_verifier(client_auth)
        } else {
            config_builder.with_no_client_auth()
        };

        // Build config with certificates
        let mut config = cert_builder
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| ProtocolError::TlsError(format!("TLS error: {e}")))?;

        // Configure ALPN protocols if specified
        if let Some(protocols) = &self.alpn_protocols {
            config.alpn_protocols = protocols.clone();
            debug!(
                protocol_count = protocols.len(),
                "ALPN protocols configured"
            );
        }

        Ok(config)
    }

    /// Calculate SHA-256 hash for a certificate to use with pinning
    pub fn calculate_cert_hash(cert: &CertificateDer<'_>) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        hasher.finalize().to_vec()
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
    /// Optional CA certificate file to trust instead of the system roots
    root_ca_path: Option<String>,
    /// Allowed TLS protocol versions (None = use rustls defaults)
    tls_versions: Option<Vec<TlsVersion>>,
    /// Allowed cipher suites (None = use rustls defaults)
    cipher_suites: Option<Vec<rustls::SupportedCipherSuite>>,
}

/// Length of a certificate pin: a SHA-256 digest.
const PIN_LEN: usize = 32;

impl TlsClientConfig {
    /// Create a new TLS client configuration
    pub fn new<S: Into<String>>(server_name: S) -> Self {
        Self {
            server_name: server_name.into(),
            insecure: false,
            pinned_cert_hash: None,
            client_cert_path: None,
            client_key_path: None,
            root_ca_path: None,
            tls_versions: None,
            cipher_suites: None,
        }
    }

    /// Set allowed TLS protocol versions
    ///
    /// Only the listed versions are enabled. An empty list is rejected when the
    /// config is loaded.
    pub fn with_tls_versions(mut self, versions: Vec<TlsVersion>) -> Self {
        self.tls_versions = Some(versions);
        self
    }

    /// Set allowed cipher suites
    ///
    /// Only the listed suites are enabled, matched by suite identifier and kept in this
    /// crate's preference order. Loading the config fails if none of them is supported,
    /// or if none of them can be used with the enabled TLS versions.
    pub fn with_cipher_suites(mut self, cipher_suites: Vec<rustls::SupportedCipherSuite>) -> Self {
        self.cipher_suites = Some(cipher_suites);
        self
    }

    /// Trust the CA certificates in `ca_path` (PEM) instead of the system roots
    ///
    /// Use this for servers with certificates from a private CA. Only the given CAs are
    /// trusted; the system root store is not loaded. Hostname and chain validation
    /// still apply, and a pin set with `with_pinned_cert_hash()` is checked on top.
    ///
    /// Cannot be combined with `insecure()`, which skips CA validation:
    /// `load_client_config()` returns an error for that combination.
    pub fn with_root_ca<S: Into<String>>(mut self, ca_path: S) -> Self {
        self.root_ca_path = Some(ca_path.into());
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
    /// This mode skips certificate validation (no CA chain or hostname checks), so any
    /// certificate is accepted unless one is pinned with `with_pinned_cert_hash()`. The
    /// server must still prove that it holds the private key for the certificate it
    /// presents: the handshake signature is always verified. This mode should ONLY be used for:
    /// - Development and testing
    /// - Debugging environments
    /// - Internal networks with certificate pinning enabled
    ///
    /// **NEVER** use this in production without explicit certificate pinning via `with_pinned_cert_hash()`.
    /// For a server with a private CA, trust that CA with `with_root_ca()` instead.
    pub fn insecure(mut self) -> Self {
        warn!("INSECURE MODE ENABLED: Certificate verification is disabled. This should only be used for development/testing.");
        self.insecure = true;
        self
    }

    /// Pin a certificate by its SHA-256 hash/fingerprint
    ///
    /// Only a server presenting the certificate with exactly this hash is accepted.
    /// Compute the hash with `TlsServerConfig::calculate_cert_hash()`: it is the 32-byte
    /// SHA-256 digest of the DER certificate, as raw bytes (not hex).
    ///
    /// Without `insecure()` the pin is checked in addition to normal CA and hostname
    /// validation. With `insecure()` it replaces them, for development setups with a
    /// self-signed certificate. Either way the handshake signature is verified against
    /// the pinned certificate's public key, so a server that has the certificate but not
    /// its private key is rejected.
    ///
    /// A hash that is not 32 bytes long can never match, so `load_client_config()`
    /// returns an error for it.
    pub fn with_pinned_cert_hash(mut self, hash: Vec<u8>) -> Self {
        self.pinned_cert_hash = Some(hash);
        self
    }

    /// Load the TLS client configuration
    ///
    /// # Errors
    /// Returns `ProtocolError::TlsError` if a pinned hash is not 32 bytes, if
    /// `with_root_ca()` is combined with `insecure()`, if a certificate or key file
    /// cannot be read or parsed, or if the version or cipher-suite settings leave
    /// nothing usable.
    pub fn load_client_config(&self) -> Result<ClientConfig> {
        if let Some(hash) = &self.pinned_cert_hash {
            if hash.len() != PIN_LEN {
                return Err(ProtocolError::TlsError(format!(
                    "pinned certificate hash must be {PIN_LEN} bytes (the SHA-256 digest of the \
                     DER certificate), got {} bytes: compute it with \
                     TlsServerConfig::calculate_cert_hash(&cert)",
                    hash.len()
                )));
            }
        }
        if self.insecure && self.root_ca_path.is_some() {
            return Err(ProtocolError::TlsError(
                "with_root_ca() has no effect with insecure(), which skips CA validation: \
                 remove insecure() to validate against the CA, or remove with_root_ca()"
                    .into(),
            ));
        }
        if self.insecure {
            self.build_insecure_client_config()
        } else {
            self.build_secure_client_config()
        }
    }

    /// Start a client config builder with the configured provider, versions and suites
    fn client_config_builder(
        &self,
    ) -> Result<(
        Arc<CryptoProvider>,
        rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
    )> {
        let (provider, versions) =
            resolve_protocol_settings(self.tls_versions.as_deref(), self.cipher_suites.as_deref())?;
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .map_err(|e| {
                ProtocolError::TlsError(format!("Failed to configure TLS protocol versions: {e}"))
            })?;
        Ok((provider, builder))
    }

    /// Build secure client config with system root CAs (or the `with_root_ca()` CAs)
    fn build_secure_client_config(&self) -> Result<ClientConfig> {
        let (provider, builder) = self.client_config_builder()?;
        let root_store = match &self.root_ca_path {
            Some(path) => load_root_ca(path)?,
            None => self.load_system_root_certificates()?,
        };
        let builder = match &self.pinned_cert_hash {
            // A pin narrows CA validation: webpki checks the chain and hostname, then the
            // fingerprint must match too.
            Some(hash) => {
                let inner =
                    WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider)
                        .build()
                        .map_err(|e| {
                            ProtocolError::TlsError(format!(
                                "Failed to build server certificate verifier: {e}"
                            ))
                        })?;
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedWebPkiVerifier {
                        inner,
                        fingerprint: hash.clone(),
                    }))
            }
            None => builder.with_root_certificates(root_store),
        };

        // Apply client auth directly
        if let (Some(client_cert_path), Some(client_key_path)) =
            (&self.client_cert_path, &self.client_key_path)
        {
            let (cert_chain, key) =
                self.load_client_credentials(client_cert_path, client_key_path)?;
            builder.with_client_auth_cert(cert_chain, key).map_err(|e| {
                ProtocolError::TlsError(format!("Failed to set client certificate: {e}"))
            })
        } else {
            Ok(builder.with_no_client_auth())
        }
    }

    /// Build insecure client config with custom verifier
    fn build_insecure_client_config(&self) -> Result<ClientConfig> {
        let (provider, builder) = self.client_config_builder()?;
        let verifier = self.create_custom_verifier(&provider);
        let custom_builder = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier);

        // Apply client auth directly
        if let (Some(client_cert_path), Some(client_key_path)) =
            (&self.client_cert_path, &self.client_key_path)
        {
            let (cert_chain, key) =
                self.load_client_credentials(client_cert_path, client_key_path)?;
            custom_builder
                .with_client_auth_cert(cert_chain, key)
                .map_err(|e| {
                    ProtocolError::TlsError(format!("Failed to set client certificate: {e}"))
                })
        } else {
            Ok(custom_builder.with_no_client_auth())
        }
    }

    /// Load system root certificates
    fn load_system_root_certificates(&self) -> Result<RootCertStore> {
        let mut root_store = RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        if let Some(e) = native_certs.errors.first() {
            return Err(ProtocolError::TlsError(format!(
                "Failed to load native certs: {e}"
            )));
        }

        for cert in native_certs.certs {
            root_store.add(cert).map_err(|e| {
                ProtocolError::TlsError(format!("Failed to add cert to root store: {e}"))
            })?;
        }

        if root_store.is_empty() {
            return Err(ProtocolError::TlsError(
                "No trusted root certificates found in the system store: install the system \
                 CA bundle, or trust a CA explicitly with with_root_ca(\"<ca.pem>\")"
                    .into(),
            ));
        }

        Ok(root_store)
    }

    /// Create custom certificate verifier (pinning or accept-any)
    ///
    /// Handshake signatures are checked with the same provider's signature algorithms.
    fn create_custom_verifier(&self, provider: &CryptoProvider) -> Arc<dyn ServerCertVerifier> {
        let supported_algs = provider.signature_verification_algorithms;
        if let Some(hash) = &self.pinned_cert_hash {
            Arc::new(CertificateFingerprint {
                fingerprint: hash.clone(),
                supported_algs,
            })
        } else {
            Arc::new(AcceptAnyServerCert { supported_algs })
        }
    }

    /// Load client certificate and private key
    fn load_client_credentials(
        &self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Load certificate
        let cert_file = File::open(cert_path).map_err(ProtocolError::Io)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs_result: std::result::Result<Vec<_>, _> =
            CertificateDer::pem_reader_iter(&mut cert_reader).collect();
        let certs: Vec<CertificateDer<'static>> = certs_result
            .map_err(|_| ProtocolError::TlsError("Failed to parse client certificate".into()))?;

        if certs.is_empty() {
            return Err(ProtocolError::TlsError(
                "No client certificates found".into(),
            ));
        }

        // Load private key
        let key_file = File::open(key_path).map_err(ProtocolError::Io)?;
        let mut key_reader = BufReader::new(key_file);
        let key = load_private_key(&mut key_reader)?;

        Ok((certs, key))
    }

    /// Get the server name as a rustls::ServerName
    pub fn server_name(&self) -> Result<ServerName<'_>> {
        ServerName::try_from(self.server_name.as_str())
            .map_err(|_| ProtocolError::TlsError("Invalid server name".into()))
    }

    /// Get the server name as an owned String
    pub fn server_name_string(&self) -> String {
        self.server_name.clone()
    }

    /// Everything that determines the rustls client config this builds, as a string.
    /// Two configs with the same key build equivalent rustls configs (as long as the
    /// files they name are unchanged), so `SessionCache` can reuse one.
    pub(crate) fn resumption_key(&self) -> String {
        let versions = self.tls_versions.as_ref().map(|versions| {
            versions
                .iter()
                .map(|v| match v {
                    TlsVersion::TLS12 => "1.2",
                    TlsVersion::TLS13 => "1.3",
                    TlsVersion::All => "all",
                })
                .collect::<Vec<_>>()
        });
        let suites = self
            .cipher_suites
            .as_ref()
            .map(|suites| suites.iter().map(|s| s.suite()).collect::<Vec<_>>());
        format!(
            "{:?}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            self.server_name,
            self.insecure,
            self.pinned_cert_hash,
            self.client_cert_path,
            self.client_key_path,
            self.root_ca_path,
            versions,
            suites
        )
    }

    /// The server name as an owned `ServerName<'static>`, as `TlsConnector::connect`
    /// needs.
    pub(crate) fn owned_server_name(&self) -> Result<ServerName<'static>> {
        ServerName::try_from(self.server_name.clone())
            .map_err(|_| ProtocolError::TlsError("Invalid server name".into()))
    }
}

/// Load the CA certificates in the PEM file at `path` into a root store.
fn load_root_ca(path: &str) -> Result<RootCertStore> {
    let file = File::open(path)
        .map_err(|e| ProtocolError::TlsError(format!("Failed to open root CA file: {e}")))?;
    let mut reader = BufReader::new(file);
    let certs: std::result::Result<Vec<_>, _> =
        CertificateDer::pem_reader_iter(&mut reader).collect();
    let certs =
        certs.map_err(|_| ProtocolError::TlsError("Failed to parse root CA certificate".into()))?;
    if certs.is_empty() {
        return Err(ProtocolError::TlsError(
            "No root CA certificates found".into(),
        ));
    }
    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| ProtocolError::TlsError(format!("Failed to add root CA cert: {e}")))?;
    }
    Ok(store)
}

/// Create a file for a private key. On Unix it is created with mode 0600 so the key
/// is not readable by other users; elsewhere the platform default applies.
fn create_private_key_file(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
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
            // A client that never finishes the handshake must not hold the connection
            // open indefinitely.
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => {
                    if let Err(e) = handle_tls_connection(tls_stream, peer).await {
                        error!(%peer, error=%e, "Connection error");
                    }
                }
                Ok(Err(e)) => {
                    error!(%peer, error=%e, "TLS handshake failed");
                }
                Err(_) => {
                    warn!(%peer, "TLS handshake timed out");
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
pub async fn connect(
    addr: &str,
    config: TlsClientConfig,
) -> Result<Framed<ClientTlsStream<TcpStream>, PacketCodec>> {
    let tls_config = Arc::new(config.load_client_config()?);
    let connector = TlsConnector::from(tls_config);

    let domain = config.owned_server_name()?;

    let stream = TcpStream::connect(addr).await?;

    let tls_stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, stream))
        .await
        .map_err(|_| ProtocolError::Timeout)?
        .map_err(|e| ProtocolError::TlsError(format!("TLS connection failed: {e}")))?;

    let framed = Framed::new(tls_stream, PacketCodec);
    Ok(framed)
}
