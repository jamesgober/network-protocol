use std::collections::HashMap;
// No need for Arc in this module
use std::time::{Duration, Instant};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tracing::{debug, info, instrument, warn};

use crate::protocol::message::Message;
use crate::service::client::Client;
//use crate::error::Result;

#[derive(Debug, Clone)]
pub struct ClusterNode {
    pub id: String,
    pub addr: String,
    pub last_seen: Option<Instant>,
}

pub struct Cluster {
    peers: HashMap<String, ClusterNode>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl Cluster {
    pub fn new(peers: Vec<(String, String)>) -> Self {
        let peers = peers
            .into_iter()
            .map(|(id, addr)| {
                (
                    id.clone(),
                    ClusterNode {
                        id,
                        addr,
                        last_seen: None,
                    },
                )
            })
            .collect();

        Self {
            peers,
            shutdown_tx: None,
        }
    }

    #[instrument(skip(self), fields(interval_ms = %heartbeat_interval.as_millis()))]
    pub async fn start_heartbeat(&mut self, heartbeat_interval: Duration) -> mpsc::Sender<()> {
        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Clone necessary data for the heartbeat task
        let peers = self.peers.clone();

        // Store the sender for shutdown
        self.shutdown_tx = Some(shutdown_tx.clone());

        // Spawn the heartbeat task
        tokio::spawn(async move {
            let mut interval_timer = interval(heartbeat_interval);

            loop {
                select! {
                    // Check for shutdown signal
                    _ = shutdown_rx.recv() => {
                        info!("Received shutdown signal, stopping heartbeat");
                        break;
                    }

                    // Run heartbeat on interval
                    _ = interval_timer.tick() => {
                        for (id, node) in peers.iter() {
                            match Client::connect(&node.addr).await {
                                Ok(mut client) => {
                                    match client.send_and_wait(Message::Ping).await {
                                        Ok(Message::Pong) => {
                                            debug!(node_id = %id, "Peer alive");
                                        }
                                        _ => {
                                            warn!(node_id = %id, "Peer timeout");
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(node_id = %id, error = ?e, "Peer unreachable");
                                }
                            }
                        }
                    }
                }
            }

            info!("Heartbeat task shut down gracefully");
        });

        // Return the shutdown sender so the caller can trigger shutdown
        shutdown_tx
    }

    pub fn get_peers(&self) -> Vec<&ClusterNode> {
        self.peers.values().collect()
    }

    /// Gracefully shut down the cluster's heartbeat task
    #[instrument(skip(self))]
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            if tx.send(()).await.is_err() {
                info!("Heartbeat task already stopped");
            } else {
                info!("Shutdown signal sent to heartbeat task");
                // Give heartbeat task time to finish
                sleep(Duration::from_millis(100)).await;
            }
        } else {
            info!("No active heartbeat to shut down");
        }
    }
}
