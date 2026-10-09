use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;

use network_protocol::error::Result;
use network_protocol::protocol::message::Message;
use network_protocol::service::tls_client::TlsClient;
use network_protocol::transport::tls::{TlsClientConfig, TlsServerConfig};

const TEST_PORT: u16 = 49152; // Use a high port number for tests
const TEST_PORT_TAMPER: u16 = 49153; // Second port for tampering test
const CERT_PATH: &str = "tests/test_cert.pem";
const KEY_PATH: &str = "tests/test_key.pem";

// Helper to generate test certificates
#[allow(clippy::expect_used)]
fn generate_test_certificates() -> Result<(PathBuf, PathBuf)> {
    let cert_path = PathBuf::from(CERT_PATH);
    let key_path = PathBuf::from(KEY_PATH);

    // Generate certificates if they don't exist
    if !cert_path.exists() || !key_path.exists() {
        TlsServerConfig::generate_self_signed(&cert_path, &key_path)
            .expect("Failed to generate test certificates");
    }

    Ok((cert_path, key_path))
}

// Test a basic TLS server and client exchange
#[tokio::test]
async fn test_tls_communication() -> Result<()> {
    // Generate test certificates
    let (cert_path, key_path) = generate_test_certificates()?;

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Start TLS server with shutdown capability
    let server_addr = format!("127.0.0.1:{TEST_PORT}");
    let server_handle = tokio::spawn(async move {
        let config = TlsServerConfig::new(cert_path, key_path);
        let _ = network_protocol::service::tls_daemon::start_with_shutdown(
            &server_addr,
            config,
            shutdown_rx,
        )
        .await;
    });

    // Wait for server to start
    sleep(Duration::from_millis(100)).await;

    // Connect with TLS client, using insecure mode since we're using self-signed certs
    let config = TlsClientConfig::new("localhost").insecure();
    let mut client = TlsClient::connect(&format!("127.0.0.1:{TEST_PORT}"), config).await?;

    // Test ping/pong
    let response = client.request(Message::Ping).await?;
    assert!(matches!(response, Message::Pong));

    // Echo test
    let test_message = Message::Custom {
        command: "ECHO".to_string(),
        payload: vec![1, 2, 3, 4],
    };
    let response = client.request(test_message.clone()).await?;

    if let Message::Custom { command, payload } = response {
        assert_eq!(command, "ECHO");
        assert_eq!(payload, vec![1, 2, 3, 4]);
    } else {
        #[allow(clippy::panic)]
        {
            panic!("Expected Custom message, got: {response:?}");
        }
    }

    // We're done, so drop the client which will close the connection
    drop(client);

    // Allow the server to process the disconnection
    sleep(Duration::from_millis(100)).await;

    // Signal the server to shut down gracefully
    let _ = shutdown_tx.send(()).await;

    // Wait for server to fully shut down
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;

    Ok(())
}

// Test TLS against tampering
#[tokio::test]
async fn test_tls_tampering_protection() -> Result<()> {
    // This test demonstrates that TLS protects against message tampering
    // For a real implementation, we would need to set up a proxy to modify messages
    // Here we just validate that the connection is protected by TLS

    let (cert_path, key_path) = generate_test_certificates()?;

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Start TLS server with shutdown capability
    let server_addr = format!("127.0.0.1:{TEST_PORT_TAMPER}");
    let server_addr_clone = server_addr.clone();
    let server_handle = tokio::spawn(async move {
        let config = TlsServerConfig::new(cert_path, key_path);
        let _ = network_protocol::service::tls_daemon::start_with_shutdown(
            &server_addr_clone,
            config,
            shutdown_rx,
        )
        .await;
    });

    // Wait for server to start
    sleep(Duration::from_millis(100)).await;

    // Connect with TLS client
    let config = TlsClientConfig::new("localhost").insecure();
    let mut client = TlsClient::connect(&server_addr, config).await?;

    // Verify the connection works
    let response = client.request(Message::Ping).await?;
    assert!(matches!(response, Message::Pong));

    // With TLS, any tampering with the encrypted data would cause the connection
    // to fail, as the TLS layer would detect the integrity violation

    // Clean up
    drop(client);
    sleep(Duration::from_millis(100)).await;

    // Signal the server to shut down gracefully
    let _ = shutdown_tx.send(()).await;

    // Wait for server to fully shut down
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;

    Ok(())
}

// PEM loading for server certs, client CA (mTLS) and client credentials
#[test]
fn test_tls_pem_loading() -> Result<()> {
    let (cert_path, key_path) = generate_test_certificates()?;

    let server = TlsServerConfig::new(cert_path.clone(), key_path.clone())
        .with_client_auth(CERT_PATH)
        .require_client_auth(true);
    assert!(server.load_server_config().is_ok());

    let client = TlsClientConfig::new("localhost")
        .insecure()
        .with_client_certificate(CERT_PATH, KEY_PATH);
    assert!(client.load_client_config().is_ok());

    // A key file has no CERTIFICATE section and a cert file has no PRIVATE KEY section
    let swapped = TlsServerConfig::new(key_path, cert_path);
    assert!(swapped.load_server_config().is_err());

    let swapped_client = TlsClientConfig::new("localhost")
        .insecure()
        .with_client_certificate(KEY_PATH, CERT_PATH);
    assert!(swapped_client.load_client_config().is_err());

    Ok(())
}

// mTLS tests. None of these install a process-level rustls CryptoProvider: the test
// build enables both the ring and aws-lc-rs backends (see dev-dependencies), so any
// code path that relies on the process default panics here.

type TestResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Writes a CA, a server cert and a client cert signed by that CA, plus a client cert
/// signed by an unrelated CA, into a fresh directory. Returns the directory.
fn generate_mtls_pki(name: &str) -> TestResult<PathBuf> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };

    let dir = std::env::temp_dir().join(format!(
        "network-protocol-mtls-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;

    let make_ca = |cn: &str| -> TestResult<(Issuer<'static, KeyPair>, String)> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate()?;
        let pem = params.self_signed(&key)?.pem();
        Ok((Issuer::new(params, key), pem))
    };

    let make_leaf = |cn: &str,
                     sans: Vec<String>,
                     usage: ExtendedKeyUsagePurpose,
                     issuer: &Issuer<'_, KeyPair>,
                     file: &str|
     -> TestResult<()> {
        let mut params = CertificateParams::new(sans)?;
        params.distinguished_name.push(DnType::CommonName, cn);
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, issuer)?;
        std::fs::write(dir.join(format!("{file}.pem")), cert.pem())?;
        std::fs::write(dir.join(format!("{file}.key")), key.serialize_pem())?;
        Ok(())
    };

    let (ca, ca_pem) = make_ca("network-protocol test CA")?;
    std::fs::write(dir.join("ca.pem"), ca_pem)?;
    let (rogue_ca, _) = make_ca("network-protocol untrusted CA")?;

    make_leaf(
        "localhost",
        vec!["localhost".into()],
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        "server",
    )?;
    make_leaf(
        "trusted client",
        Vec::new(),
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        "client",
    )?;
    make_leaf(
        "untrusted client",
        Vec::new(),
        ExtendedKeyUsagePurpose::ClientAuth,
        &rogue_ca,
        "rogue_client",
    )?;

    Ok(dir)
}

fn mtls_server_config(dir: &std::path::Path) -> TlsServerConfig {
    TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"))
        .with_client_auth(dir.join("ca.pem").to_string_lossy())
}

/// Client config that pins the test server certificate, optionally presenting the
/// client certificate stored under `client_cert`.
fn mtls_client_config(
    dir: &std::path::Path,
    client_cert: Option<&str>,
) -> TestResult<TlsClientConfig> {
    use rustls::pki_types::pem::PemObject;
    let server_cert = rustls::pki_types::CertificateDer::from_pem_file(dir.join("server.pem"))?;
    let mut config = TlsClientConfig::new("localhost")
        .insecure()
        .with_pinned_cert_hash(TlsServerConfig::calculate_cert_hash(&server_cert));
    if let Some(name) = client_cert {
        config = config.with_client_certificate(
            dir.join(format!("{name}.pem"))
                .to_string_lossy()
                .into_owned(),
            dir.join(format!("{name}.key"))
                .to_string_lossy()
                .into_owned(),
        );
    }
    Ok(config)
}

/// Runs one mTLS handshake followed by a 4-byte echo. Returns the server-side and
/// client-side outcomes.
async fn mtls_exchange(
    server: TlsServerConfig,
    client: TlsClientConfig,
) -> TestResult<(std::io::Result<()>, std::io::Result<()>)> {
    let (server_result, client_result) = tls_exchange(server.load_server_config()?, client).await?;
    Ok((server_result.map(|_| ()), client_result))
}

/// Protocol version and cipher suite seen by the server for a completed handshake
type Negotiated = (rustls::ProtocolVersion, rustls::CipherSuite);

/// Runs one TLS handshake followed by a 4-byte echo against `server_config`. Returns the
/// server-side outcome (with the negotiated version and cipher suite) and the client-side
/// outcome.
async fn tls_exchange(
    server_config: rustls::ServerConfig,
    client: TlsClientConfig,
) -> TestResult<(std::io::Result<Negotiated>, std::io::Result<()>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
    let connector =
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(client.load_client_config()?));
    let server_name = client.server_name()?.to_owned();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut tls = acceptor.accept(stream).await?;
        let conn = tls.get_ref().1;
        let negotiated = (
            conn.protocol_version()
                .ok_or_else(|| std::io::Error::other("no protocol version"))?,
            conn.negotiated_cipher_suite()
                .ok_or_else(|| std::io::Error::other("no cipher suite"))?
                .suite(),
        );
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await?;
        tls.write_all(&buf).await?;
        tls.shutdown().await?;
        Ok::<Negotiated, std::io::Error>(negotiated)
    });

    let client_exchange = async {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        let mut tls = connector.connect(server_name, stream).await?;
        tls.write_all(b"ping").await?;
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await?;
        if &buf != b"ping" {
            return Err(std::io::Error::other("echo mismatch"));
        }
        Ok(())
    };
    let client_result = tokio::time::timeout(Duration::from_secs(10), client_exchange)
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("client timed out")));

    let server_result = tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .map_err(|_| "server timed out")??;

    Ok((server_result, client_result))
}

#[test]
fn test_mtls_server_config_builds_without_process_provider() -> TestResult<()> {
    let dir = generate_mtls_pki("config")?;
    let result = mtls_server_config(&dir).load_server_config();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    Ok(())
}

#[tokio::test]
async fn test_mtls_handshake_accepts_trusted_client() -> TestResult<()> {
    let dir = generate_mtls_pki("trusted")?;
    let result = match mtls_client_config(&dir, Some("client")) {
        Ok(client) => mtls_exchange(mtls_server_config(&dir), client).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(server.is_ok(), "server side failed: {server:?}");
    assert!(client.is_ok(), "client side failed: {client:?}");
    Ok(())
}

#[tokio::test]
async fn test_mtls_handshake_rejects_client_without_cert() -> TestResult<()> {
    let dir = generate_mtls_pki("nocert")?;
    let result = match mtls_client_config(&dir, None) {
        Ok(client) => mtls_exchange(mtls_server_config(&dir), client).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(
        format!("{server:?}").contains("NoCertificatesPresented"),
        "expected rejection for a missing client certificate, got: {server:?}"
    );
    assert!(
        client.is_err(),
        "client completed an exchange without a certificate"
    );
    Ok(())
}

#[tokio::test]
async fn test_mtls_handshake_rejects_untrusted_client_cert() -> TestResult<()> {
    let dir = generate_mtls_pki("untrusted")?;
    let result = match mtls_client_config(&dir, Some("rogue_client")) {
        Ok(client) => mtls_exchange(mtls_server_config(&dir), client).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(
        format!("{server:?}").contains("UnknownIssuer"),
        "expected rejection for an untrusted client certificate, got: {server:?}"
    );
    assert!(
        client.is_err(),
        "client completed an exchange with an untrusted cert"
    );
    Ok(())
}

// Optional client authentication: `require_client_auth(false)` after `with_client_auth(..)`.

#[tokio::test]
async fn test_mtls_required_rejects_client_without_cert() -> TestResult<()> {
    let dir = generate_mtls_pki("required")?;
    let server = mtls_server_config(&dir).require_client_auth(true);
    let result = match mtls_client_config(&dir, None) {
        Ok(client) => mtls_exchange(server, client).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(
        format!("{server:?}").contains("NoCertificatesPresented"),
        "expected rejection for a missing client certificate, got: {server:?}"
    );
    assert!(
        client.is_err(),
        "client completed an exchange without a certificate"
    );
    Ok(())
}

#[tokio::test]
async fn test_mtls_optional_accepts_client_without_cert() -> TestResult<()> {
    let dir = generate_mtls_pki("optional-nocert")?;
    let server = mtls_server_config(&dir).require_client_auth(false);
    let result = match mtls_client_config(&dir, None) {
        Ok(client) => mtls_exchange(server, client).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(server.is_ok(), "server side failed: {server:?}");
    assert!(client.is_ok(), "client side failed: {client:?}");
    Ok(())
}

#[tokio::test]
async fn test_mtls_optional_accepts_trusted_client_cert() -> TestResult<()> {
    let dir = generate_mtls_pki("optional-trusted")?;
    let server = mtls_server_config(&dir).require_client_auth(false);
    let result = match mtls_client_config(&dir, Some("client")) {
        Ok(client) => mtls_exchange(server, client).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(server.is_ok(), "server side failed: {server:?}");
    assert!(client.is_ok(), "client side failed: {client:?}");
    Ok(())
}

#[tokio::test]
async fn test_mtls_optional_rejects_untrusted_client_cert() -> TestResult<()> {
    let dir = generate_mtls_pki("optional-untrusted")?;
    let server = mtls_server_config(&dir).require_client_auth(false);
    let result = match mtls_client_config(&dir, Some("rogue_client")) {
        Ok(client) => mtls_exchange(server, client).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(
        format!("{server:?}").contains("UnknownIssuer"),
        "expected rejection for an untrusted client certificate, got: {server:?}"
    );
    assert!(
        client.is_err(),
        "client completed an exchange with an untrusted cert"
    );
    Ok(())
}

// Certificate pinning must prove possession of the private key, not just the certificate.

/// Always serves the same certificate chain and signing key, without checking that
/// they belong together.
#[derive(Debug)]
struct FixedCert(std::sync::Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// A server that presents the real server certificate from `dir` but signs the
/// handshake with an unrelated key of the same type, as an attacker who copied the
/// (public) certificate would.
fn impostor_server_config(
    dir: &std::path::Path,
    version: &'static rustls::SupportedProtocolVersion,
) -> TestResult<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let server_cert = CertificateDer::from_pem_file(dir.join("server.pem"))?;
    let other_key = rcgen::KeyPair::generate()?;
    let other_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(other_key.serialize_der()));
    let signing_key = provider.key_provider.load_private_key(other_key)?;
    let certified = rustls::sign::CertifiedKey::new(vec![server_cert], signing_key);

    Ok(rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])?
        .with_no_client_auth()
        .with_cert_resolver(std::sync::Arc::new(FixedCert(std::sync::Arc::new(
            certified,
        )))))
}

#[tokio::test]
async fn test_pinned_cert_accepts_real_server() -> TestResult<()> {
    let dir = generate_mtls_pki("pin-real")?;
    let result = match mtls_client_config(&dir, None) {
        Ok(client) => {
            let server = TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
            mtls_exchange(server, client).await
        }
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(server.is_ok(), "server side failed: {server:?}");
    assert!(client.is_ok(), "client side failed: {client:?}");
    Ok(())
}

#[tokio::test]
async fn test_pinned_cert_rejects_impostor_without_private_key() -> TestResult<()> {
    let dir = generate_mtls_pki("pin-impostor")?;
    let mut outcomes = Vec::new();
    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let result = match (
            impostor_server_config(&dir, version),
            mtls_client_config(&dir, None),
        ) {
            (Ok(server), Ok(client)) => tls_exchange(server, client).await,
            (Err(e), _) | (_, Err(e)) => Err(e),
        };
        outcomes.push((version.version, result));
    }
    let _ = std::fs::remove_dir_all(&dir);

    for (version, result) in outcomes {
        let (server, client) = result?;
        assert!(
            format!("{client:?}").contains("BadSignature"),
            "{version:?}: expected the pinned client to reject the impostor's handshake signature, got: {client:?}"
        );
        assert!(
            server.is_err(),
            "{version:?}: impostor server completed the handshake"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_insecure_mode_rejects_bad_handshake_signature() -> TestResult<()> {
    let dir = generate_mtls_pki("insecure-impostor")?;
    let result = match impostor_server_config(&dir, &rustls::version::TLS13) {
        Ok(server) => tls_exchange(server, TlsClientConfig::new("localhost").insecure()).await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(
        format!("{client:?}").contains("BadSignature"),
        "expected insecure mode to reject an invalid handshake signature, got: {client:?}"
    );
    assert!(server.is_err(), "impostor server completed the handshake");
    Ok(())
}

// with_tls_versions() and with_cipher_suites() are applied to the rustls configs.

#[tokio::test]
async fn test_tls13_only_server_rejects_tls12_only_client() -> TestResult<()> {
    use network_protocol::transport::tls::TlsVersion;

    let dir = generate_mtls_pki("tls13-only")?;
    let server = TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"))
        .with_tls_versions(vec![TlsVersion::TLS13]);
    let result = match (server.load_server_config(), mtls_client_config(&dir, None)) {
        (Ok(server), Ok(client)) => {
            tls_exchange(server, client.with_tls_versions(vec![TlsVersion::TLS12])).await
        }
        (Err(e), _) => Err(e.into()),
        (_, Err(e)) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(
        format!("{server:?}").contains("PeerIncompatible"),
        "expected the TLS 1.3-only server to reject a TLS 1.2-only client, got: {server:?}"
    );
    assert!(client.is_err(), "TLS 1.2-only client connected");
    Ok(())
}

#[tokio::test]
async fn test_tls12_only_client_negotiates_tls12() -> TestResult<()> {
    use network_protocol::transport::tls::TlsVersion;

    let dir = generate_mtls_pki("tls12-only")?;
    let server = TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
    let result = match (server.load_server_config(), mtls_client_config(&dir, None)) {
        (Ok(server), Ok(client)) => {
            tls_exchange(server, client.with_tls_versions(vec![TlsVersion::TLS12])).await
        }
        (Err(e), _) => Err(e.into()),
        (_, Err(e)) => Err(e),
    };
    let _ = std::fs::remove_dir_all(&dir);

    let (server, client) = result?;
    assert!(client.is_ok(), "client side failed: {client:?}");
    let (version, _) = server?;
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    Ok(())
}

#[tokio::test]
async fn test_cipher_suite_restriction_is_negotiated() -> TestResult<()> {
    use network_protocol::transport::tls::TlsVersion;
    use rustls::crypto::ring::cipher_suite;

    let dir = generate_mtls_pki("ciphers")?;
    let server_cfg = || TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
    let cases = [
        // Server-side restriction to a suite the client does not prefer
        (
            server_cfg().with_cipher_suites(vec![cipher_suite::TLS13_CHACHA20_POLY1305_SHA256]),
            mtls_client_config(&dir, None),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
        // Client-side restriction
        (
            server_cfg(),
            mtls_client_config(&dir, None)
                .map(|c| c.with_cipher_suites(vec![cipher_suite::TLS13_AES_128_GCM_SHA256])),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        ),
        // TLS 1.2 suite together with a version restriction
        (
            server_cfg()
                .with_tls_versions(vec![TlsVersion::TLS12])
                .with_cipher_suites(vec![
                    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                ]),
            mtls_client_config(&dir, None),
            rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
    ];

    let mut outcomes = Vec::new();
    for (server, client, expected) in cases {
        let result = match (server.load_server_config(), client) {
            (Ok(server), Ok(client)) => tls_exchange(server, client).await,
            (Err(e), _) => Err(e.into()),
            (_, Err(e)) => Err(e),
        };
        outcomes.push((expected, result));
    }
    let _ = std::fs::remove_dir_all(&dir);

    for (expected, result) in outcomes {
        let (server, client) = result?;
        assert!(
            client.is_ok(),
            "{expected:?}: client side failed: {client:?}"
        );
        let (_, suite) = server?;
        assert_eq!(suite, expected);
    }
    Ok(())
}

#[test]
fn test_tls_version_and_cipher_suite_config_errors() -> TestResult<()> {
    use network_protocol::transport::tls::TlsVersion;
    use rustls::crypto::ring::cipher_suite;

    let (cert_path, key_path) = generate_test_certificates()?;
    let server = || TlsServerConfig::new(cert_path.clone(), key_path.clone());
    let client = || TlsClientConfig::new("localhost").insecure();

    let expect_err = |message: String, needle: &str| {
        assert!(
            message.contains(needle),
            "expected an error containing {needle:?}, got: {message}"
        );
    };
    let server_err = |config: TlsServerConfig| format!("{:?}", config.load_server_config().err());
    let client_err = |config: TlsClientConfig| format!("{:?}", config.load_client_config().err());

    // Empty version list
    expect_err(
        server_err(server().with_tls_versions(Vec::new())),
        "No TLS protocol versions configured",
    );
    expect_err(
        client_err(client().with_tls_versions(Vec::new())),
        "No TLS protocol versions configured",
    );

    // Empty cipher suite list
    expect_err(
        server_err(server().with_cipher_suites(Vec::new())),
        "No supported cipher suites configured",
    );
    expect_err(
        client_err(client().with_cipher_suites(Vec::new())),
        "No supported cipher suites configured",
    );

    // Only TLS 1.2 suites with only TLS 1.3 enabled
    let tls12_suite = cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    expect_err(
        server_err(
            server()
                .with_tls_versions(vec![TlsVersion::TLS13])
                .with_cipher_suites(vec![tls12_suite]),
        ),
        "None of the configured cipher suites can be used",
    );
    expect_err(
        client_err(
            client()
                .with_tls_versions(vec![TlsVersion::TLS13])
                .with_cipher_suites(vec![tls12_suite]),
        ),
        "None of the configured cipher suites can be used",
    );

    // Suites are matched by identifier, so a suite taken from another provider works
    assert!(server()
        .with_cipher_suites(vec![
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
        ])
        .load_server_config()
        .is_ok());
    assert!(server()
        .with_tls_versions(vec![TlsVersion::All])
        .load_server_config()
        .is_ok());
    Ok(())
}

// Settings that would otherwise be accepted and ignored now fail closed.

#[test]
#[allow(clippy::panic)]
fn test_required_client_auth_without_ca_is_a_config_error() -> TestResult<()> {
    let dir = generate_mtls_pki("auth-no-ca")?;
    let server = || TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
    let required = server().require_client_auth(true).load_server_config();
    let optional = server().require_client_auth(false).load_server_config();
    let with_ca = mtls_server_config(&dir)
        .require_client_auth(true)
        .load_server_config();
    let _ = std::fs::remove_dir_all(&dir);

    let message = match required {
        Err(network_protocol::error::ProtocolError::TlsError(message)) => message,
        other => panic!("expected a TlsError, got: {:?}", other.map(|_| ())),
    };
    assert!(
        message.contains("client authentication is required but no client CA is configured"),
        "{message}"
    );
    assert!(message.contains("with_client_auth("), "{message}");
    assert!(optional.is_ok(), "no client auth was requested");
    assert!(with_ca.is_ok(), "required client auth with a CA is valid");
    Ok(())
}

#[test]
fn test_pinned_hash_must_be_32_bytes() -> TestResult<()> {
    for len in [0usize, 1, 31, 33, 64] {
        let err = TlsClientConfig::new("localhost")
            .insecure()
            .with_pinned_cert_hash(vec![0xAB; len])
            .load_client_config()
            .err();
        let message = format!("{err:?}");
        assert!(
            message.contains("must be 32 bytes") && message.contains(&format!("got {len} bytes")),
            "length {len}: {message}"
        );
        assert!(message.contains("calculate_cert_hash"), "{message}");
    }
    // The same check applies without insecure(): a bad pin never silently matches nothing.
    assert!(TlsClientConfig::new("localhost")
        .with_pinned_cert_hash(vec![0; 31])
        .load_client_config()
        .is_err());
    assert!(TlsClientConfig::new("localhost")
        .insecure()
        .with_pinned_cert_hash(vec![0; 32])
        .load_client_config()
        .is_ok());
    Ok(())
}

#[test]
fn test_root_ca_with_insecure_is_a_config_error() -> TestResult<()> {
    let dir = generate_mtls_pki("root-ca-insecure")?;
    let result = TlsClientConfig::new("localhost")
        .insecure()
        .with_root_ca(dir.join("ca.pem").to_string_lossy())
        .load_client_config();
    let missing = TlsClientConfig::new("localhost")
        .with_root_ca(dir.join("missing.pem").to_string_lossy())
        .load_client_config();
    let _ = std::fs::remove_dir_all(&dir);

    let message = format!("{:?}", result.err());
    assert!(
        message.contains("with_root_ca() has no effect with insecure()"),
        "{message}"
    );
    assert!(missing.is_err(), "a missing root CA file must be an error");
    Ok(())
}

fn ca_client(dir: &std::path::Path, server_name: &str) -> TlsClientConfig {
    TlsClientConfig::new(server_name).with_root_ca(dir.join("ca.pem").to_string_lossy())
}

fn cert_hash(path: std::path::PathBuf) -> TestResult<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    let cert = rustls::pki_types::CertificateDer::from_pem_file(path)?;
    Ok(TlsServerConfig::calculate_cert_hash(&cert))
}

#[tokio::test]
async fn test_root_ca_validates_server_certificate() -> TestResult<()> {
    let dir = generate_mtls_pki("root-ca")?;
    let server = || TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
    let trusted = mtls_exchange(server(), ca_client(&dir, "localhost")).await;
    // Same CA, wrong host name: hostname validation still applies.
    let wrong_name = mtls_exchange(server(), ca_client(&dir, "example.com")).await;
    let _ = std::fs::remove_dir_all(&dir);

    let (server_side, client_side) = trusted?;
    assert!(server_side.is_ok(), "server side failed: {server_side:?}");
    assert!(client_side.is_ok(), "client side failed: {client_side:?}");
    let (_, client_side) = wrong_name?;
    assert!(
        client_side.is_err(),
        "certificate for localhost accepted for example.com"
    );
    Ok(())
}

/// Before 1.3.0 a pin without `insecure()` was dropped, so any CA-valid certificate
/// for the host was accepted.
#[tokio::test]
async fn test_pin_is_enforced_with_ca_validation() -> TestResult<()> {
    let dir = generate_mtls_pki("pin-secure")?;
    let server = || TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
    let outcome = async {
        let right_pin =
            ca_client(&dir, "localhost").with_pinned_cert_hash(cert_hash(dir.join("server.pem"))?);
        // A valid pin of some other certificate.
        let wrong_pin =
            ca_client(&dir, "localhost").with_pinned_cert_hash(cert_hash(dir.join("client.pem"))?);
        // The right pin does not excuse a host name the certificate does not cover.
        let right_pin_wrong_name = ca_client(&dir, "example.com")
            .with_pinned_cert_hash(cert_hash(dir.join("server.pem"))?);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((
            mtls_exchange(server(), right_pin).await?,
            mtls_exchange(server(), wrong_pin).await?,
            mtls_exchange(server(), right_pin_wrong_name).await?,
        ))
    }
    .await;
    let _ = std::fs::remove_dir_all(&dir);

    let (right, wrong, wrong_name) = outcome?;
    assert!(right.1.is_ok(), "matching pin rejected: {:?}", right.1);
    assert!(
        format!("{:?}", wrong.1).contains("Pinned certificate hash mismatch"),
        "mismatched pin accepted: {:?}",
        wrong.1
    );
    assert!(
        wrong.0.is_err(),
        "server completed a handshake the pin forbids"
    );
    assert!(
        wrong_name.1.is_err(),
        "pinned certificate accepted for the wrong host name"
    );
    Ok(())
}

/// Runs a TLS echo server that records how each handshake went, for `count`
/// connections.
async fn handshake_kind_server(
    server_config: rustls::ServerConfig,
    count: usize,
) -> TestResult<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<std::io::Result<Vec<Option<rustls::HandshakeKind>>>>,
)> {
    use futures::{SinkExt, StreamExt};
    use network_protocol::core::codec::PacketCodec;

    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let mut kinds = Vec::new();
        for _ in 0..count {
            let (stream, _) = listener.accept().await?;
            let tls = acceptor.accept(stream).await?;
            kinds.push(tls.get_ref().1.handshake_kind());
            let mut framed = tokio_util::codec::Framed::new(tls, PacketCodec);
            if let Some(Ok(packet)) = framed.next().await {
                framed
                    .send(packet)
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
        }
        Ok(kinds)
    });
    Ok((addr, handle))
}

#[tokio::test]
async fn test_session_cache_resumes_tls_sessions() -> TestResult<()> {
    use network_protocol::transport::session_cache::SessionCache;
    use std::sync::Arc;

    let dir = generate_mtls_pki("resume")?;
    let outcome = async {
        let server_config = TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"))
            .load_server_config()?;

        // With a shared cache, the second connection resumes.
        let (addr, server) = handshake_kind_server(server_config.clone(), 2).await?;
        let cache = Arc::new(SessionCache::new(16, Duration::from_secs(60)));
        for _ in 0..2 {
            let mut client = TlsClient::connect_with_session(
                &addr.to_string(),
                ca_client(&dir, "localhost"),
                Some(cache.clone()),
            )
            .await?;
            let _ = client.request(Message::Ping).await?;
        }
        let with_cache = server.await??;

        // Without one, every connection is a full handshake.
        let (addr, server) = handshake_kind_server(server_config, 2).await?;
        for _ in 0..2 {
            let mut client =
                TlsClient::connect(&addr.to_string(), ca_client(&dir, "localhost")).await?;
            let _ = client.request(Message::Ping).await?;
        }
        let without_cache = server.await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((with_cache, without_cache))
    }
    .await;
    let _ = std::fs::remove_dir_all(&dir);

    let (with_cache, without_cache) = outcome?;
    assert_eq!(
        with_cache,
        vec![
            Some(rustls::HandshakeKind::Full),
            Some(rustls::HandshakeKind::Resumed)
        ]
    );
    assert_eq!(
        without_cache,
        vec![
            Some(rustls::HandshakeKind::Full),
            Some(rustls::HandshakeKind::Full)
        ]
    );
    Ok(())
}

/// `tls_daemon::start` used to drop its own shutdown sender, so the server stopped
/// about half a second after it started.
#[tokio::test]
async fn test_tls_daemon_start_keeps_serving() -> TestResult<()> {
    use network_protocol::service::tls_daemon;

    let dir = generate_mtls_pki("daemon-start")?;
    let addr = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        probe.local_addr()?.to_string()
    };
    let server = TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
    let server_addr = addr.clone();
    let daemon = tokio::spawn(async move { tls_daemon::start(&server_addr, server).await });

    // Well past the point where the old server had already returned.
    sleep(Duration::from_millis(1500)).await;
    let finished_early = daemon.is_finished();
    let reply = async {
        let mut client = TlsClient::connect(&addr, ca_client(&dir, "localhost")).await?;
        client.request(Message::Ping).await
    }
    .await;
    daemon.abort();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(!finished_early, "tls_daemon::start returned on its own");
    assert!(matches!(reply, Ok(Message::Pong)), "got: {reply:?}");
    Ok(())
}

/// A client that connects and never sends a ClientHello is dropped after the
/// handshake timeout instead of holding the connection forever.
#[tokio::test]
#[allow(clippy::panic)]
async fn test_tls_daemon_drops_stalled_handshake() -> TestResult<()> {
    use network_protocol::service::tls_daemon;
    use tokio::io::AsyncReadExt;

    let dir = generate_mtls_pki("daemon-stall")?;
    let addr = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
        probe.local_addr()?.to_string()
    };
    let server = TlsServerConfig::new(dir.join("server.pem"), dir.join("server.key"));
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let server_addr = addr.clone();
    let daemon = tokio::spawn(async move {
        tls_daemon::start_with_shutdown(&server_addr, server, shutdown_rx).await
    });
    sleep(Duration::from_millis(300)).await;

    let mut stalled = tokio::net::TcpStream::connect(&addr).await?;
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(20), stalled.read(&mut buf)).await;
    let _ = shutdown_tx.send(()).await;
    let _ = tokio::time::timeout(Duration::from_secs(15), daemon).await;
    let _ = std::fs::remove_dir_all(&dir);

    match closed {
        Ok(Ok(0)) | Ok(Err(_)) => Ok(()),
        Ok(Ok(n)) => panic!("server sent {n} bytes to a client that never said hello"),
        Err(_) => panic!("stalled handshake was still open after 20 s"),
    }
}
