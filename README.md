# NetGuard - Network Threat Intelligence Platform

[![Architecture](https://via.placeholder.com/1200x600/0d1b2e/ffffff?text=NetGuard+Architecture)](https://github.com/yourusername/EECS_592_Capstone)

NetGuard is a **real-time network monitoring and threat detection platform** that:

1. **Captures** live packets from your network interface
2. **Extracts** metadata (IPs, ports, protocols, timestamps)
3. **Evaluates** detection rules locally 
4. **Forwards** intelligence to **AWS** (S3 partitioned logs + Lambda rules engine)
5. **Serves** a **live dashboard** showing local + cloud alerts/stats

**Local → Cloud → Dashboard** full-stack system. Runs with **one command** locally.

## 🎯 Features

- **Live Packet Capture** (Scapy, any interface)
- **SQLite Persistence** (local packets)
- **YAML Detection Rules** (10+ rules, local + AWS)
- **Flask API** (unifies local/cloud data)
- **React-like Dashboard** (live tables/charts, local+AWS)
- **AWS Pipeline** (API→S3→Rules→Alerts→SNS/Email)
- **TLS 1.3 Forwarding** to API Gateway
- **Partitioned S3 Storage** (year/month/day/hour)

## 🛠 Quick Start (Local Development)

### Prerequisites
```bash
Python 3.10+
macOS/Linux (packet capture requires sudo/admin)
```

### 1. Clone & Virtual Environment
```bash
cd /path/to/EECS_592_Capstone
python -m venv netguard
source netguard/bin/activate  # macOS/Linux
# netguard\Scripts\activate  # Windows
```

### 2. Install Dependencies
```bash
pip install scapy flask flask-cors boto3 pyyaml
```

### 3. AWS (Optional but Recommended)
Set environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-2
export LOG_BUCKET=monitoring-pcap-storage  # Your S3 bucket
```

### 4. Run Everything
```bash
cd src
python app.py
```

**✅ That's it!** Flask API + capture + dashboard backend starts at `http://localhost:5000`

### 5. Open Dashboard
```bash
open dashboard.html  # Auto-opens in browser
# OR visit: http://localhost:5000 (API docs)
```

**Live view**: Packet feed, stats, local events, AWS alerts (if configured).

**Stop**: Ctrl+C

## 🏗 Architecture Overview

```
Network Interface ── sniff ──> capture_packet.py ── queue ──> 
Metadata_extraction.py ── SQLite ──> database.py 
                           │
                           └─── forward_to_cloud.py ── POST ──> AWS API Gateway
                                                                   │
                                                      AWS Lambda (ingest_metadata.py)
                                                                   │
                                                              S3: ingested/logs/Y/M/D/H/
                                                                   │
                                                      AWS Lambda (rules_engine.py)
                                                                   │
                                                              S3: alerts/YYYYMMDDTHHMMSSZ-
                                                                   │
                                                      AWS Lambda (alert_gen.py) ──> SNS/Email

LOCAL: Flask app.py serves API + dashboard.html (local DB + S3 data)
```

## 📁 Components

### Core Packet Pipeline (`src/`)

| File | Purpose | Key Functions |
|------|---------|---------------|
| `capture_packet.py` | **Live sniffing** from `en0`/`eth0` | `start_sniffer()`, `handle(pkt)` → queue |
| `Metadata_extraction.py` | **Extracts** metadata (IP/port/proto/time) from queue | `extract_metadata()`, `main()` → DB + AWS |
| `database.py` | **SQLite** `packets.db` | `PacketDatabase.insert_metadata()`, `get_all_packets()` |
| `forward_to_cloud.py` | **HTTPS POST** metadata to AWS API Gateway (TLS 1.3) | `forward_metadata()` → `https://gfxxlediud.../ingest` |
| `rules_parser.py` | **Loads/evaluates** YAML rules from `src/rules/` | `load_rules()`, `Rule` class |

**Database Schema** (`src/packets.db`):
```sql
CREATE TABLE packets (
  id INTEGER PRIMARY KEY,
  timestamp DATETIME,
  src_ip TEXT, dst_ip TEXT,
  src_port INT, dst_port INT,
  protocol TEXT  -- TCP/UDP/OTHER
);
```

### Flask API + Dashboard (`src/`)

| File | Purpose |
|------|---------|
| `app.py` | **Central server**: Capture + local rules + DB + AWS S3 reader → JSON API (`/api/packets`, `/api/stats`, `/api/events/local`, `/api/aws/*`) |
| `dashboard.html` | **Live UI**: Realtime tables/charts (packets, proto donut, top IPs/ports, local+AWS alerts) |
| `index.html` | **Landing page** |
| `login.html` | **Demo login** → dashboard (admin@netguard.io/netguard2026) |

**Endpoints**:
- `GET /api/packets` → Recent 500 packets
- `GET /api/stats` → TCP/UDP counts, top ports/IPs
- `GET /api/events/local` → Local rule matches
- `GET /api/aws/alerts` → S3 `alerts/` JSONs
- `GET /api/aws/stats` → Cloud severity breakdown

### AWS Lambda Pipeline (`aws/`)

| File | Trigger | Purpose | Output |
|------|---------|---------|--------|
| `ingest_metadata.py` | **API Gateway** (`POST /ingest`) | Partition/normalize → S3 | `ingested/logs/year=YYYY/month=MM/.../*.json` |
| `rules_engine.py` | **S3 Create** (`ingested/logs/`) | Load S3 rules → evaluate → alert | `alerts/YYYYMMDDTHHMMSSZ-rule-ip.json` |
| `alert_gen.py` | **S3 Create** (`alerts/`) | Format → **SNS** | Email notifications via SNS topic |

**Deploy**: Zip + upload to Lambda (or use SAM/CloudFormation).

### Detection Rules

**Local**: `src/rules/` → `rules_parser.py` (10 YAML files: rule1.yaml ... rule10.yaml)

**Cloud**: `s3://monitoring-pcap-storage/rules/*.yaml` → `rules_engine.py`

**Example** (`rule1.yaml`):
```yaml
id: HighPortScan
description: Source contacted >10 unique dst ports in 60s
severity: HIGH
conditions:
  - field: unique_dst_ports
    operator: >
    value: 10
window: 60
tags: [scan, reconnaissance]
```

## ☁️ AWS Deployment

1. **S3 Bucket**: `monitoring-pcap-storage`
2. **API Gateway**: `https://gfxxlediud.execute-api.us-east-2.amazonaws.com/prod/ingest`
3. **Deploy Lambdas**:
   ```bash
   # ingest_metadata.py → API Gateway integration
   # rules_engine.py → S3 `ingested/logs/*` trigger
   # alert_gen.py → S3 `alerts/*` trigger + SNS topic
   
   # Upload rules/*.yaml to s3://.../rules/
   aws s3 sync src/rules/ s3://monitoring-pcap-storage/rules/ --sse AES256
   ```
4. **SNS**: Subscribe email to topic ARN from `alert_gen.py`

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| `Permission denied` sniffing | `sudo python app.py` |
| No AWS data | Check `AWS_*` env vars + bucket perms |
| Rules not firing | Validate YAML + check `src/rules/*.yaml` |
| Dashboard blank | Wait 30s for packets + refresh |
| macOS `en0` wrong | `ifconfig \| grep -E \"inet \" \| grep -v 127` |

## 📈 Development

```bash
# Linting
pip install black flake8
black src/
flake8 src/

# Tests (add pytest later)
pytest src/

# View SQLite
sqlite3 src/packets.db \"SELECT * FROM packets ORDER BY id DESC LIMIT 20;\"
```

## 🛡️ Security Notes

- **Local**: SQLite unencrypted (dev only)
- **Cloud**: S3 AES256 encryption, API TLS 1.3
- **Rules**: Whitelist internal IPs (169.254.*, 127.*, RFC1918)
- **Cooldowns**: 30s per src_ip:rule to prevent spam

## 📚 License

MIT License © EECS 592 Capstone Team
