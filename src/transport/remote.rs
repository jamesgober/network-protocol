//! # Remote Transport Layer
//!
//! This file is part of the Network Protocol project.
//!
//! It defines the remote transport layer for network communication,
//! including TCP-based client-server interactions.
//!
//! The remote transport layer is responsible for handling the actual data transmission
//! between nodes in a network, ensuring that packets are sent and received correctly.
//!
//! It abstracts the underlying network details,
//! allowing higher-level protocol logic to focus on message routing and processing.
//!
//! The remote transport layer is designed to be modular and extensible,
//! supporting various transport mechanisms such as TCP, UDP, and custom protocols.
//!
//! ## Responsibilities
//! - Send and receive packets over the network
//! - Handle connection management
//! - Provide a unified interface for different transport protocols
//!
//! This module is essential for processing protocol packets in a networked environment,
//! ensuring correct parsing and serialization.
//!
//! It is designed to be efficient, minimal, and easy to integrate into the protocol layer.
use crate::core::codec::PacketCodec;
use crate::core::packet::Packet;
use crate::error::Result;
use futures::SinkExt;
use futures::StreamExt;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument};

/// Starts a TCP server at the given address
#[instrument(skip(addr), fields(address = %addr))]
pub async fn start_server(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;

    info!(address = %addr, "Server listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer).await {
                error!(error = %e, peer = %peer, "Connection error");
            }
        });
    }
}

/// Handles a single client connection
#[instrument(skip(stream), fields(peer = %peer))]
async fn handle_connection(stream: TcpStream, peer: SocketAddr) -> Result<()> {
    let mut framed = Framed::new(stream, PacketCodec);

    info!("Client connected");

    while let Some(packet) = framed.next().await {
        match packet {
            Ok(pkt) => {
                debug!(bytes = pkt.payload.len(), "Packet received");
                on_packet(pkt, &mut framed).await?;
            }
            Err(e) => {
                error!(error = %e, "Protocol error");
                break;
            }
        }
    }

    info!("Client disconnected");
    Ok(())
}

/// Placeholder: handles incoming packets
#[instrument(skip(framed), fields(packet_version = pkt.version, payload_size = pkt.payload.len()))]
async fn on_packet(pkt: Packet, framed: &mut Framed<TcpStream, PacketCodec>) -> Result<()> {
    // Echo the packet back
    let response = Packet {
        version: pkt.version,
        payload: pkt.payload,
    };

    framed.send(response).await?;
    Ok(())
}

/// Connect to a remote server and return the framed transport
#[instrument(skip(addr), fields(address = %addr))]
pub async fn connect(addr: &str) -> Result<Framed<TcpStream, PacketCodec>> {
    let stream = TcpStream::connect(addr).await?;
    let framed = Framed::new(stream, PacketCodec);
    Ok(framed)
}
