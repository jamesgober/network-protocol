# Deployment Patterns

This guide provides architectural patterns and best practices for deploying network-protocol in production environments.

## Table of Contents

- [Deployment Topologies](#deployment-topologies)
- [Single-Node Deployment](#single-node-deployment)
- [Cluster Deployment](#cluster-deployment)
- [Edge Computing](#edge-computing)
- [Circuit Breaker Pattern](#circuit-breaker-pattern)
- [Monitoring and Observability](#monitoring-and-observability)
- [Security Considerations](#security-considerations)
- [Disaster Recovery](#disaster-recovery)

---

## Deployment Topologies

### Overview

The library supports three primary deployment patterns:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Single-Node    │    │    Cluster      │    │   Edge/Hybrid   │
│                 │    │                 │    │                 │
│  ┌──────────┐   │    │  ┌────┐ ┌────┐ │    │  ┌────┐  Cloud  │
│  │  Server  │   │    │  │ N1 │─│ N2 │ │    │  │Edge│────┐    │
│  └──────────┘   │    │  └────┘ └────┘ │    │  └────┘    ▼    │
│       │         │    │    │       │    │    │    │    ┌────┐  │
│  ┌────┴────┐    │    │  ┌─┴───────┴─┐  │    │    └───▶│Hub │  │
│  │Clients  │    │    │  │  Clients  │  │    │         └────┘  │
│  └─────────┘    │    │  └───────────┘  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

---

## Single-Node Deployment

### Use Cases

- Development and testing
- Low-traffic applications (<10k concurrent connections)
- Stateful applications with session affinity
- Cost-sensitive deployments

### Architecture

```rust
use network_protocol::service::tls_daemon;
use network_protocol::transport::tls::TlsServerConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    network_protocol::init();

    // Configure TLS
    let tls_config = TlsServerConfig::new("cert.pem", "key.pem");

    // Start server; runs until Ctrl+C (SIGINT)
    tls_daemon::start("0.0.0.0:8443", tls_config).await?;

    Ok(())
}
```

The TLS daemon does not take a `ServerConfig`, so settings such as `max_connections` and `backpressure_limit` do not apply to it. They apply to `service::daemon`, which secures connections with the crate's own ECDH handshake instead of TLS:

```rust
use network_protocol::config::ServerConfig;
use network_protocol::service::daemon;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    network_protocol::init();

    let config = ServerConfig {
        address: "0.0.0.0:9000".to_string(),
        max_connections: 1000, // Connections over the limit are closed on accept
        ..Default::default()
    };

    // Serves PING and ECHO until Ctrl+C (SIGINT)
    daemon::start_with_config(config).await?;

    Ok(())
}
```

Both servers shut down gracefully on SIGINT only. systemd and `docker stop` send SIGTERM by default, so set `KillSignal=SIGINT` in the unit (or `STOPSIGNAL SIGINT` in the Dockerfile), or handle SIGTERM in your binary and call `Daemon::shutdown()` or the `start_with_shutdown` channel yourself. A server started with `daemon::start_daemon_no_signals()` installs no signal handler at all and stops only on `Daemon::shutdown()`.

### Deployment Checklist

- [ ] Set up systemd service (Linux) or launchd (macOS)
- [ ] Configure log rotation
- [ ] Set resource limits (ulimit, memory)
- [ ] Enable automatic restart on failure
- [ ] Configure firewall rules
- [ ] Set up monitoring alerts
- [ ] Configure TLS certificates with auto-renewal
- [ ] Test graceful shutdown

### Systemd Service Example (Linux)

```ini
[Unit]
Description=Network Protocol Server
After=network.target

[Service]
Type=simple
User=netprotocol
Group=netprotocol
WorkingDirectory=/opt/network-protocol
ExecStart=/opt/network-protocol/bin/server
Restart=always
RestartSec=10
LimitNOFILE=65536
# The built-in servers shut down gracefully on SIGINT
KillSignal=SIGINT

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/network-protocol

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable network-protocol
sudo systemctl start network-protocol

# Check status
sudo systemctl status network-protocol

# View logs
sudo journalctl -u network-protocol -f
```

### Resource Requirements

**Minimum:**
- CPU: 1 core
- RAM: 512 MB
- Disk: 100 MB (plus logs)
- Network: 100 Mbps

**Recommended (1000 concurrent connections):**
- CPU: 4 cores
- RAM: 4 GB
- Disk: 10 GB (with log rotation)
- Network: 1 Gbps

---

## Cluster Deployment

### Use Cases

- High availability requirements (99.9%+ uptime)
- High traffic (10k+ concurrent connections)
- Geographic distribution
- Load balancing and failover

### Architecture

```
                    ┌──────────────┐
                    │ Load Balancer│
                    │   (HAProxy)  │
                    └───────┬──────┘
                            │
           ┌────────────────┼────────────────┐
           │                │                │
     ┌─────▼─────┐    ┌─────▼─────┐   ┌─────▼─────┐
     │  Node 1   │    │  Node 2   │   │  Node 3   │
     │  Primary  │────│  Replica  │───│  Replica  │
     └───────────┘    └───────────┘   └───────────┘
           │                │                │
     ┌─────▼────────────────▼────────────────▼─────┐
     │         Shared State (Redis/etcd)            │
     └──────────────────────────────────────────────┘
```

### Load Balancer Configuration (HAProxy)

```haproxy
global
    maxconn 10000
    log /dev/log local0

defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    log global
    option tcplog

frontend network_protocol_frontend
    bind *:8443
    default_backend network_protocol_backend

backend network_protocol_backend
    balance roundrobin
    option tcp-check
    
    server node1 10.0.1.10:8443 check inter 2s rise 2 fall 3
    server node2 10.0.1.11:8443 check inter 2s rise 2 fall 3
    server node3 10.0.1.12:8443 check inter 2s rise 2 fall 3
```

### Session Affinity

For stateful applications requiring session persistence:

```haproxy
backend network_protocol_backend
    balance source  # Use client IP for routing
    hash-type consistent  # Consistent hashing
    
    # Or use cookie-based session affinity
    cookie SERVERID insert indirect nocache
    server node1 10.0.1.10:8443 check cookie node1
    server node2 10.0.1.11:8443 check cookie node2
```

### Health Checks

The library has no HTTP endpoints of its own. Implement health check endpoints next to the protocol server, here with axum 0.7 (`axum = "0.7"`):

```rust
use axum::{extract::State, http::StatusCode, routing::get, Router};
use network_protocol::config::ServerConfig;
use network_protocol::protocol::dispatcher::Dispatcher;
use network_protocol::protocol::message::Message;
use network_protocol::service::daemon;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

async fn health_check() -> &'static str {
    "OK"
}

async fn readiness_check(State(ready): State<Arc<AtomicBool>>) -> (StatusCode, &'static str) {
    // Check if server is ready to accept connections
    if ready.load(Ordering::Relaxed) {
        (StatusCode::OK, "READY")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "NOT_READY")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ready = Arc::new(AtomicBool::new(false));

    let health_router = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .with_state(ready.clone());

    // Run health check server on separate port
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tokio::spawn(async move { axum::serve(listener, health_router).await });

    // Start main protocol server
    let dispatcher = Arc::new(Dispatcher::new());
    dispatcher.register("PING", |_| Ok(Message::Pong))?;
    let config = ServerConfig {
        address: "0.0.0.0:8443".to_string(),
        ..Default::default()
    };
    let mut server = daemon::start_daemon_no_signals(config, dispatcher).await?;
    ready.store(true, Ordering::Relaxed);

    // Report not ready while shutting down
    tokio::signal::ctrl_c().await?;
    ready.store(false, Ordering::Relaxed);
    server.shutdown().await?;
    Ok(())
}
```

`start_daemon_no_signals()` returns once the server task is spawned, before the listener is bound, and a bind failure is only logged by that task. For a stricter readiness check, also try a TCP connect to the protocol port.

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: network-protocol
spec:
  replicas: 3
  selector:
    matchLabels:
      app: network-protocol
  template:
    metadata:
      labels:
        app: network-protocol
    spec:
      containers:
      - name: server
        image: myregistry/network-protocol:latest
        ports:
        - containerPort: 8443
          name: protocol
        - containerPort: 8080
          name: health
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: network-protocol
spec:
  type: LoadBalancer
  selector:
    app: network-protocol
  ports:
  - port: 8443
    targetPort: 8443
    protocol: TCP
```

---

## Edge Computing

### Use Cases

- IoT deployments
- Mobile edge computing
- Content delivery networks
- Latency-sensitive applications

### Architecture

```
     Edge Nodes                     Regional Hub                 Central Cloud
┌─────────────────┐            ┌──────────────────┐        ┌─────────────────┐
│  ┌────┐ ┌────┐  │            │   ┌──────────┐   │        │  ┌──────────┐   │
│  │E1  │ │E2  │  │───────────▶│   │Regional  │   │───────▶│  │  Cloud   │   │
│  └────┘ └────┘  │            │   │   Hub    │   │        │  │ Services │   │
│       Local     │            │   └──────────┘   │        │  └──────────┘   │
│    Processing   │            │   Aggregation    │        │   Long-term     │
└─────────────────┘            └──────────────────┘        │    Storage      │
                                                            └─────────────────┘
```

### Edge Node Configuration

There is no edge-specific config type. An edge node combines the local transport for sensors with a `Client` for the hub, using `ClientConfig` for the timeouts:

```rust
use network_protocol::config::ClientConfig;
use network_protocol::service::client::Client;
use network_protocol::transport::local;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start local IPC server for sensors (a named pipe on Windows)
    tokio::spawn(local::start_server("/tmp/sensor.sock"));

    // Upstream connection to hub, with aggressive timeouts for edge
    let config = ClientConfig {
        address: "hub.example.com:9000".to_string(),
        connection_timeout: Duration::from_secs(5),
        operation_timeout: Duration::from_secs(2),
        ..Default::default()
    };

    // Client does not reconnect by itself, so retry here
    loop {
        match Client::connect_with_config(config.clone()).await {
            Ok(client) => {
                handle_hub_connection(client).await;
            }
            Err(e) => {
                eprintln!("Hub connection failed: {}. Retrying...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn handle_hub_connection(_client: Client) {
    // Forward sensor data until a send fails, then return to reconnect
}
```

### Offline-First Design

```rust
use network_protocol::error::ProtocolError;
use network_protocol::protocol::message::Message;
use network_protocol::service::client::Client;
use std::collections::VecDeque;

struct OfflineBuffer {
    buffer: VecDeque<Message>,
    max_size: usize,
}

impl OfflineBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(max_size),
            max_size,
        }
    }
    
    fn push(&mut self, message: Message) {
        if self.buffer.len() >= self.max_size {
            // Drop oldest message when full
            self.buffer.pop_front();
        }
        self.buffer.push_back(message);
    }
    
    async fn flush_to_hub(&mut self, hub: &mut Client) -> Result<(), ProtocolError> {
        while let Some(message) = self.buffer.pop_front() {
            hub.send(message).await?;
        }
        Ok(())
    }
}
```

---

## Circuit Breaker Pattern

Prevent cascade failures in distributed systems:

### Implementation

```rust
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct CircuitBreaker {
    failure_count: Arc<AtomicU64>,
    last_failure: Arc<AtomicU64>,
    is_open: Arc<AtomicBool>,
    threshold: u64,
    timeout: Duration,
}

impl CircuitBreaker {
    fn new(threshold: u64, timeout: Duration) -> Self {
        Self {
            failure_count: Arc::new(AtomicU64::new(0)),
            last_failure: Arc::new(AtomicU64::new(0)),
            is_open: Arc::new(AtomicBool::new(false)),
            threshold,
            timeout,
        }
    }
    
    async fn call<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        // Check if circuit is open
        if self.is_open.load(Ordering::Relaxed) {
            let elapsed = self.elapsed_since_failure();
            if elapsed < self.timeout {
                return Err(/* Circuit open error */);
            } else {
                // Try to close circuit (half-open state)
                self.is_open.store(false, Ordering::Relaxed);
            }
        }
        
        // Execute function
        match f() {
            Ok(result) => {
                // Success - reset failure count
                self.failure_count.store(0, Ordering::Relaxed);
                Ok(result)
            }
            Err(e) => {
                // Failure - increment counter
                let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                self.last_failure.store(
                    Instant::now().elapsed().as_secs(),
                    Ordering::Relaxed
                );
                
                // Open circuit if threshold exceeded
                if failures >= self.threshold {
                    self.is_open.store(true, Ordering::Relaxed);
                }
                
                Err(e)
            }
        }
    }
    
    fn elapsed_since_failure(&self) -> Duration {
        let last = self.last_failure.load(Ordering::Relaxed);
        let now = Instant::now().elapsed().as_secs();
        Duration::from_secs(now - last)
    }
}
```

### Usage

```rust
let circuit_breaker = CircuitBreaker::new(
    5,  // Open after 5 failures
    Duration::from_secs(30)  // Try again after 30 seconds
);

loop {
    match circuit_breaker.call(|| connect_to_service()).await {
        Ok(connection) => {
            // Use connection
        }
        Err(e) if circuit_breaker.is_open() => {
            // Circuit open - use fallback
            use_fallback_service().await;
        }
        Err(e) => {
            // Regular error - handle normally
            handle_error(e);
        }
    }
}
```

---

## Monitoring and Observability

### Metrics to Track

#### Application Metrics

`utils::metrics::global_metrics()` returns a process-wide set of atomic counters, and `snapshot()` reads them all at once. In 1.3.0 the library does not update these counters itself: the client, the daemons and the transports never call them, so they stay at zero unless your own code records events with the methods shown below.

```rust
use network_protocol::utils::metrics::global_metrics;
use std::time::Duration;

// Call these from your own connection and message handling code
fn on_message_sent(bytes: u64) {
    global_metrics().message_sent(bytes);
}

// Periodically export metrics; `export_metric` is your own exporter
fn start_metrics_export(export_metric: fn(&str, u64)) {
    tokio::spawn(async move {
        loop {
            let stats = global_metrics().snapshot();

            // Export to monitoring system
            export_metric("handshakes_total", stats.handshakes_total);
            export_metric("messages_sent", stats.messages_sent);
            export_metric("messages_received", stats.messages_received);
            export_metric("connections_active", stats.connections_active);
            export_metric("errors_total", stats.connection_errors + stats.protocol_errors);

            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}
```

The recording methods are `connection_established()`, `connection_closed()`, `handshake_attempt()`, `handshake_success()`, `handshake_failed()`, `message_sent(bytes)`, `message_received(bytes)`, `compression_attempt()`, `compression_success()`, `encryption_attempt()`, `encryption_success()`, `replay_cache_hit()`, `replay_cache_miss()`, `connection_error()` and `protocol_error()`. `log_metrics()` writes a snapshot to the log at INFO level.

`ConnectionPool` does keep its own metrics up to date. `pool.metrics()` returns `PoolMetrics` with connections created, reused and evicted, acquisition errors, active and idle connections, plus `average_wait_time_us()` and `utilization_percent()`.

#### System Metrics

Monitor host-level metrics:

- **CPU**: Usage per core, load average
- **Memory**: RSS, heap usage, page faults
- **Network**: Bandwidth, packets/sec, errors
- **Disk**: I/O operations, latency, space

### Prometheus Integration

```rust
use prometheus::{Encoder, TextEncoder, Registry, Counter, Gauge};

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();
    static ref CONNECTIONS: Gauge = Gauge::new("connections_active", "Active connections")
        .expect("metric creation");
    static ref MESSAGES: Counter = Counter::new("messages_total", "Total messages")
        .expect("metric creation");
}

fn init_metrics() {
    REGISTRY.register(Box::new(CONNECTIONS.clone())).unwrap();
    REGISTRY.register(Box::new(MESSAGES.clone())).unwrap();
}

async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
```

### Alert Configuration

Example Prometheus alert rules:

```yaml
groups:
- name: network_protocol_alerts
  rules:
  # High error rate
  - alert: HighErrorRate
    expr: rate(errors_total[5m]) > 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"
      
  # Service down
  - alert: ServiceDown
    expr: up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Service is down"
      
  # High latency
  - alert: HighLatency
    expr: histogram_quantile(0.99, rate(request_duration_seconds_bucket[5m])) > 1
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "P99 latency above 1 second"
```

---

## Security Considerations

### TLS Configuration

Always use TLS in production:

```rust
use network_protocol::transport::tls::{TlsServerConfig, TlsVersion};

fn server_tls_config() -> Result<TlsServerConfig, Box<dyn std::error::Error>> {
    // Load certificates
    let tls_config = TlsServerConfig::new("fullchain.pem", "privkey.pem")
        .with_client_auth("client-ca.pem") // mTLS: client certificates signed by this CA
        .require_client_auth(false)        // Optional: also accept clients without a certificate
        .with_tls_versions(vec![TlsVersion::TLS13]);

    // Check the configuration at startup rather than on the first connection
    tls_config.load_server_config()?;
    Ok(tls_config)
}
```

Notes for 1.3.0:

- `require_client_auth(true)` without `with_client_auth(..)` is now a configuration error. It used to accept every client.
- Clients must finish the TLS handshake within 10 seconds, so stalled connections are dropped.
- The key file must hold a PEM `PRIVATE KEY` (PKCS#8) block. A key that starts with `RSA PRIVATE KEY` or `EC PRIVATE KEY` is not loaded; convert it with `openssl pkcs8 -topk8 -nocrypt -in privkey.pem -out privkey-pkcs8.pem`.

On the client side, trust a private CA with `with_root_ca(..)` and, if you want to tie clients to one certificate, pin it on top of CA validation:

```rust
use network_protocol::service::tls_client::TlsClient;
use network_protocol::transport::tls::TlsClientConfig;

// `pin` is 32 raw bytes from TlsServerConfig::calculate_cert_hash(&server_cert)
async fn connect_internal(pin: Vec<u8>) -> Result<TlsClient, Box<dyn std::error::Error>> {
    let config = TlsClientConfig::new("internal.example.com")
        .with_root_ca("internal-ca.pem")                         // Instead of the system roots
        .with_client_certificate("client.pem", "client-key.pem") // mTLS
        .with_pinned_cert_hash(pin);                             // Checked on top of CA validation

    Ok(TlsClient::connect("10.0.1.10:8443", config).await?)
}
```

Do not use `insecure()` in production. It skips CA and hostname validation; it exists for development servers with self-signed certificates.

### Certificate Management

```bash
# Let's Encrypt with certbot
sudo certbot certonly --standalone -d example.com

# Auto-renewal (cron)
0 0 1 * * certbot renew --quiet && systemctl reload network-protocol
```

### Network Segmentation

```
  Internet
      │
      ▼
┌──────────┐
│ Firewall │ (Allow 8443/tcp)
└────┬─────┘
     │
     ▼
┌──────────┐
│   DMZ    │ (Public-facing nodes)
└────┬─────┘
     │
     ▼
┌──────────┐
│ Internal │ (Backend services)
└──────────┘
```

### Firewall Rules (iptables)

```bash
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow protocol port
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
```

---

## Disaster Recovery

### Backup Strategy

**What to backup:**
- Configuration files
- TLS certificates and keys
- Application logs (if needed)
- State databases (if applicable)

```bash
#!/bin/bash
# Daily backup script

BACKUP_DIR="/backup/network-protocol/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp -r /etc/network-protocol "$BACKUP_DIR/"

# Backup certificates
cp -r /etc/letsencrypt "$BACKUP_DIR/"

# Compress
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"

# Upload to S3 (optional)
aws s3 cp "$BACKUP_DIR.tar.gz" s3://backups/network-protocol/
```

### Disaster Recovery Plan

1. **Detection**: Monitor alerts for service degradation
2. **Assessment**: Determine scope of failure
3. **Failover**: Switch to standby nodes/region
4. **Recovery**: Restore service from backups
5. **Post-mortem**: Document incident and improve

### Testing DR Procedures

```bash
# Quarterly DR drill
1. Simulate node failure
2. Verify automatic failover
3. Test backup restoration
4. Measure recovery time (RTO)
5. Document results
```

---

## Best Practices Summary

### Do's ✅

- Use TLS for all production traffic
- Implement health checks and monitoring
- Configure resource limits
- Use circuit breakers for external dependencies
- Implement graceful shutdown
- Log structured data
- Test disaster recovery procedures
- Document configuration changes

### Don'ts ❌

- Don't run as root
- Don't use self-signed certs in production
- Don't ignore security updates
- Don't skip load testing
- Don't deploy without monitoring
- Don't hardcode secrets
- Don't skip backups

---

## Additional Resources

- [Performance Tuning Guide](./TUNING.md)
- [Security Model](../THREAT_MODEL.md)
- [Architecture Overview](../ARCHITECTURE.md)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)

---

## Appendix: Container & Orchestration Examples

### Docker Container

**Dockerfile** (production-ready):

```dockerfile
FROM rust:1.75-alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 protocol
COPY --from=builder /app/target/release/daemon /app/daemon
USER protocol
EXPOSE 8443
CMD ["/app/daemon", "--config", "/app/config.toml"]
```

### Systemd Service

**/etc/systemd/system/network-protocol.service**:

```ini
[Unit]
Description=Network Protocol Service
After=network.target

[Service]
Type=simple
User=protocol
ExecStart=/opt/network-protocol/bin/daemon --config /etc/network-protocol/config.toml
Restart=on-failure
NoNewPrivileges=true
LimitNOFILE=65536
MemoryMax=2G

[Install]
WantedBy=multi-user.target
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: network-protocol
spec:
  replicas: 3
  selector:
    matchLabels:
      app: network-protocol
  template:
    metadata:
      labels:
        app: network-protocol
    spec:
      containers:
      - name: server
        image: network-protocol:1.3.0
        ports:
        - containerPort: 8443
        resources:
          limits:
            memory: "1Gi"
            cpu: "1000m"
          requests:
            memory: "256Mi"
            cpu: "250m"
        livenessProbe:
          tcpSocket:
            port: 8443
          periodSeconds: 30
        readinessProbe:
          tcpSocket:
            port: 8443
          periodSeconds: 10
```

### Connection Pooling Configuration

```rust
use network_protocol::service::pool::{ConnectionPool, PoolConfig};
use std::time::Duration;

let config = PoolConfig {
    min_size: 10,          // Pre-warm connections
    max_size: 100,         // Maximum idle connections kept in the pool
    idle_timeout: Duration::from_secs(300),   // 5 min
    max_lifetime: Duration::from_secs(3600),  // 1 hour, counted from creation
    ..Default::default()
};

let pool = ConnectionPool::new(factory, config)?;
let conn = pool.acquire().await?;  // Reuses existing or creates new
```

`max_size` limits how many idle connections the pool keeps, not how many are in use: a connection released while the pool is full is closed. `max_lifetime` counts from when the connection was created, so connections in steady use are still retired. Both behave this way from 1.3.0.

---

For specific deployment scenarios or questions, please file an issue on GitHub.
