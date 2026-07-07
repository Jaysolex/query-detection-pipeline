# Architecture

## 1. Current Lab Implementation

```mermaid
flowchart LR
    A[Attacker] --> B[HTTP QUERY Request]
    B --> C[Flask Listener]
    C --> D[normalize.py]
    D --> E[Wazuh]
    E --> F[Shuffle]
    F --> G[TheHive]
    G --> H[Analyst]
```

## 2. Enterprise Deployment Path

```mermaid
flowchart LR
    A[Internet] --> B[Cloudflare]
    B --> C[NGINX]
    C --> D[API Gateway]
    D --> E[Kubernetes]
    E --> F[Microservices]
    F --> G[Logging Layer]
    G --> H[Elastic]
    H --> I[SIEM]
    I --> J[SOAR]
    J --> K[Analyst]
```

Shows where a QUERY request travels in a production environment, vs. the single-host lab setup above — the same normalize.py logic would sit as a sidecar/middleware at the API Gateway or ingress layer rather than a standalone Flask listener.

## 3. Detection Pipeline (Data Flow)

```mermaid
flowchart TD
    A[QUERY Request] --> B[Normalization]
    B --> C[Recursive Decode]
    C --> D[JSON Flatten]
    D --> E[IOC Scan]
    E --> F[Behavior Engine]
    F --> G[Risk Score]
    G --> H1[Sigma]
    G --> H2[KQL]
    G --> H3[Splunk]
    G --> H4[Wazuh]
    H4 --> I[SOAR]
```

## 4. SOAR Workflow (PB-11)

```mermaid
flowchart LR
    A[Wazuh Alert] --> B[Webhook]
    B --> C[Shuffle]
    C --> D[AbuseIPDB]
    C --> E[VirusTotal]
    C --> F[GreyNoise]
    D --> G[Risk Score]
    E --> G
    F --> G
    G --> H[TheHive Case]
    H --> I[Slack Notification]
    I --> J[Analyst]
    J --> K[Containment]
```

Note: VirusTotal and GreyNoise enrichment nodes are roadmap items — current implementation uses AbuseIPDB only. See Roadmap in main README.

## 5. Behavior Model (Anomaly Scoring)

```mermaid
flowchart TD
    A[Body Size] --> F[Anomaly Score]
    B[JSON Depth] --> F
    C[Entropy] --> F
    D[Request Frequency] --> F
    E[Per-Endpoint Baseline] --> F
    F --> G[Composite Risk Score]
```
