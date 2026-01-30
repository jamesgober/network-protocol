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
use network_protocol::{service::daemon, transport::tls, config::Config};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    network_protocol::init();
    
    // Configure TLS
    let tls_config = tls::ServerConfig::builder()
        .with_cert_and_key("cert.pem", "key.pem")
        .build()?;
    
    // Configure server
    let config = Config {
        bind_addr: "0.0.0.0:8443".parse()?,
        max_connections: 1000,
        tls: Some(Arc::new(tls_config)),
        ..Default::default()
    };
    
    // Start server
    daemon::start_with_config(config).await?;
    
    Ok(())
}
```

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

Implement health check endpoints:

```rust
use axum::{routing::get, Router};

async fn health_check() -> &'static str {
    "OK"
}

async fn readiness_check() -> &'static str {
    // Check if server is ready to accept connections
    if is_ready() {
        "READY"
    } else {
        "NOT_READY"
    }
}

#[tokio::main]
async fn main() {
    let health_router = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check));
    
    // Run health check server on separate port
    tokio::spawn(async {
        axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
            .serve(health_router.into_make_service())
            .await
    });
    
    // Start main protocol server
    network_protocol::service::daemon::start("0.0.0.0:8443").await.unwrap();
}
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

```rust
use network_protocol::{transport::local, config::EdgeConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = EdgeConfig {
        // Local IPC for sensors
        local_socket: "/tmp/sensor.sock",
        
        // Upstream connection to hub
        hub_address: "hub.example.com:8443",
        
        // Aggressive timeouts for edge
        connection_timeout_ms: 5000,
        
        // Buffer for offline operation
        offline_buffer_size: 10000,
    };
    
    // Start edge server
    start_edge_node(config).await?;
    
    Ok(())
}

async fn start_edge_node(config: EdgeConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Start local IPC server for sensors
    tokio::spawn(async move {
        local::start_server(config.local_socket).await
    });
    
    // Connect to regional hub with retry logic
    loop {
        match connect_to_hub(&config).await {
            Ok(connection) => {
                handle_hub_connection(connection).await;
            }
            Err(e) => {
                eprintln!("Hub connection failed: {}. Retrying...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
}
```

### Offline-First Design

```rust
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
    
    async fn flush_to_hub(&mut self, hub: &mut Connection) -> Result<(), Error> {
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

```rust
use network_protocol::utils::metrics;

// Periodically export metrics
tokio::spawn(async {
    loop {
        let stats = metrics::get_stats();
        
        // Export to monitoring system
        export_metric("handshakes_total", stats.handshakes_completed);
        export_metric("messages_sent", stats.messages_sent);
        export_metric("messages_received", stats.messages_received);
        export_metric("connections_active", stats.connections_active);
        export_metric("errors_total", stats.errors_total);
        
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
});
```

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
use network_protocol::transport::tls;

// Load certificates
let tls_config = tls::ServerConfig::builder()
    .with_cert_and_key("fullchain.pem", "privkey.pem")
    .with_client_auth_optional() // For mTLS
    .build()?;
```

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

For specific deployment scenarios or questions, please file an issue on GitHub.
