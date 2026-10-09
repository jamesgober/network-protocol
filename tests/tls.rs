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
