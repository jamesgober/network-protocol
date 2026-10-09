//! `ServerConfig` settings the daemon used to accept and ignore (or misapply).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use network_protocol::config::{ClientConfig, ServerConfig};
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::service::client::Client;
use network_protocol::service::daemon::start_daemon_no_signals;
use tokio::io::AsyncReadExt;

fn free_addr() -> String {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().to_string()
}

fn server_config(addr: &str) -> ServerConfig {
    ServerConfig {
        address: addr.to_string(),
        ..Default::default()
    }
}

fn client_config(addr: &str) -> ClientConfig {
    ClientConfig {
        address: addr.to_string(),
        ..Default::default()
    }
}

fn echo_dispatcher(reply: &'static str) -> Arc<Dispatcher> {
    let dispatcher = Arc::new(Dispatcher::new());
    dispatcher
        .register("ECHO", move |_| Ok(Message::Echo(reply.to_string())))
        .unwrap();
    dispatcher
}

/// The dispatcher passed to `start_daemon_no_signals` is the one that answers.
/// Before 1.3.0 it was ignored and the server used its own default handlers.
#[tokio::test]
async fn start_daemon_no_signals_uses_the_given_dispatcher() {
    let addr = free_addr();
    let mut daemon = start_daemon_no_signals(server_config(&addr), echo_dispatcher("custom"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = Client::connect_with_config(client_config(&addr))
        .await
        .unwrap();
    client.send(Message::Echo("hello".into())).await.unwrap();
    let reply = client.recv().await.unwrap();
    daemon.shutdown().await.unwrap();

    assert!(
        matches!(&reply, Message::Echo(text) if text == "custom"),
        "got {reply:?}"
    );
}

/// `connection_timeout` bounds the handshake. It used to wrap the whole session, so
/// every connection was cut off once it was older than the timeout.
#[tokio::test]
async fn session_outlives_connection_timeout() {
    let addr = free_addr();
    let config = ServerConfig {
        connection_timeout: Duration::from_millis(500),
        ..server_config(&addr)
    };
    let mut daemon = start_daemon_no_signals(config, echo_dispatcher("still here"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = Client::connect_with_config(client_config(&addr))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    client.send(Message::Echo("ping".into())).await.unwrap();
    let reply = client.recv().await;
    daemon.shutdown().await.unwrap();

    assert!(
        matches!(&reply, Ok(Message::Echo(text)) if text == "still here"),
        "session was cut off after connection_timeout: {reply:?}"
    );
}

/// A connection beyond `max_connections` is closed straight away; once a slot frees
/// up, new connections are served again.
#[tokio::test]
async fn max_connections_is_enforced() {
    let addr = free_addr();
    let config = ServerConfig {
        max_connections: 1,
        ..server_config(&addr)
    };
    let mut daemon = start_daemon_no_signals(config, echo_dispatcher("ok"))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut first = Client::connect_with_config(client_config(&addr))
        .await
        .unwrap();

    // The second connection is accepted by the OS and then closed by the server.
    let mut second = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "connection over the limit was not closed: {closed:?}"
    );

    // The first connection is unaffected.
    first.send(Message::Echo("x".into())).await.unwrap();
    assert!(matches!(first.recv().await, Ok(Message::Echo(_))));

    // Free the slot; a new client is served.
    first.send(Message::Disconnect).await.unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut third = Client::connect_with_config(client_config(&addr))
        .await
        .unwrap();
    third.send(Message::Echo("y".into())).await.unwrap();
    assert!(matches!(third.recv().await, Ok(Message::Echo(_))));

    daemon.shutdown().await.unwrap();
}
