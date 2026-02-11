# 🛡️ AEGIS-V  
### AI-Driven Container Security + Self-Healing Orchestrator (Go + eBPF + Docker + SQLite)

AEGIS-V is a security-first container control plane that combines:

✅ **Kernel-level runtime monitoring (eBPF)**  
✅ **AI-based threat verdicting**  
✅ **Active defense (auto-kill suspicious processes)**  
✅ **Self-healing orchestration (auto restart / quarantine)**  
✅ **Supply-chain policy enforcement (Gatekeeper)**  
✅ **CLI + Web Dashboard for observability**

---

## ⭐ Why AEGIS-V?
Modern container environments face:
- Reverse shells
- Crypto miners
- Unauthorized exec inside containers
- Supply chain poisoning (malicious images)
- Crash loops and infra drift
- Blind spots in runtime behavior

AEGIS-V solves this by acting like a **mini Kubernetes + Falco + AI SOC** — but lightweight and Go-native.

---

# 🔥 Core Components

## 1) 🛡️ AEGIS-ENGINE (Control Plane)
Runs at: `http://localhost:8080`

Responsibilities:
- Secure deployments (`/deploy`)
- Live status (`/status`)
- Alerts (`/alerts`)
- Runtime monitoring (eBPF)
- Self-healing reconciliation loop
- SQLite persistence (`aegis.db`)

---

## 2) 🎛️ AEGIS-CTL (CLI)
A terminal tool to:
- Deploy services via YAML
- Check status + incidents
- View alerts
- Delete services

---

## 3) 📊 AEGIS-VIZ (Dashboard)
Runs at: `http://localhost:8081`

Provides:
- Live security feed
- Threat count
- Chart of threats per service
- Terminal audit vault

---

# 🧠 AEGIS-V Architecture

## High-Level Diagram

```

                     ┌──────────────────────────────────────┐
                     │            AEGIS-CTL (CLI)            │
                     │--------------------------------------│
                     │  • Deploy YAML workloads             │
                     │  • Status (containers + incidents)   │
                     │  • Alerts (detections from DB)       │
                     │  • Delete services                   │
                     └───────────────────┬──────────────────┘
                                         │ HTTP API Calls
                                         ▼

┌───────────────────────────────────────────────────────────────────────────────┐
│                            AEGIS-ENGINE  (API :8080)                          │
│-------------------------------------------------------------------------------│
│                                                                               │
│  ┌──────────────────────┐     ┌──────────────────────┐     ┌────────────────┐ │
│  │  Gatekeeper          │     │  Orchestrator        │     │  AI Advisor    │ │
│  │  (Supply Chain)      │     │  (Docker Runtime)    │     │ (Verdict/AIOps)│ │
│  │----------------------│     │----------------------│     │----------------│ │
│  │ • blocks latest tag  │     │ • pull image         │     │ • threat detect│ │
│  │ • registry whitelist │     │ • create container   │     │ • crashloop    │ │
│  │ • keyword scan       │     │ • set CPU/MEM limits │     │ • quarantine   │ │
│  └───────────┬──────────┘     └───────────┬──────────┘     └───────┬────────┘ │
│              │                            │                        │          │
│              ▼                            ▼                        ▼          │
│       Deployment Allowed            Container Running       AI Insight Stored │
│                                                                               │
│-------------------------------------------------------------------------------│
│                         Runtime Security (Kernel Layer)                       │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐  │
│  │ Guardian + eBPF Monitor                                                 │  │
│  │-------------------------------------------------------------------------│  │
│  │ • tracepoint: sys_enter_execve                                          │  │
│  │ • captures: pid, ppid, uid, mount namespace, comm                       │  │
│  │ • resolves namespace → docker container name                            │  │
│  │ • noise filtering (system + AEGIS safe processes)                       │  │
│  │ • AI verdict tagging                                                    │  │
│  │ • optional defense: kill suspicious process safely                      │  │
│  └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
│                                   │                                           │
│                                   ▼                                           │
│                          SQLite Database (aegis.db)                           │
│-------------------------------------------------------------------------------│
│ • deployments table  → service state + resources + AI insight                 │
│ • detections table   → runtime security incidents                             │
│ • security_alerts    → policy violations                                      │
└───────────────────────────────────────────────────────────────────────────────┘
                                         │
                                         │ DB Read (Incidents)
                                         ▼

                     ┌──────────────────────────────────────┐
                     │            AEGIS-VIZ  (:8081)          │
                     │--------------------------------------│
                     │  • Live Security Feed                 │
                     │  • Threat count + charts              │
                     │  • Source-wise attack visualization   │
                     └──────────────────────────────────────┘


```

---



---

## 🔁 System Flow (Step-by-Step)

### ✅ Deploy Flow
1. User runs: `aegis-ctl <yaml>`
2. CLI sends JSON to: `POST /deploy`
3. Engine runs **Gatekeeper checks**
4. If safe → Orchestrator provisions Docker container
5. Engine stores deployment into DB

---

### 🚨 Runtime Attack Flow
1. Any process executes inside host/container
2. eBPF detects `execve`
3. Guardian filters noise + resolves container
4. AI Advisor generates verdict (HIGH/CRITICAL/etc.)
5. Event saved into SQLite detections
6. Dashboard updates automatically
7. (Optional) Defender kills suspicious PID

---

### ♻️ Self-Healing Flow
1. Reconciliation loop checks DB deployments
2. Cross-checks with live Docker status
3. If service down:
   - AI Advisor correlates recent alerts
   - Either restarts service OR quarantines it



# 📂 Project File Structure

```

aegis-v/
├── api/
│   └── handlers.go               # API handlers (status, provision)
│
├── cmd/
│   ├── aegis-engine/
│   │   └── main.go               # Engine entrypoint (API + loops + eBPF)
│   │
│   ├── aegis-ctl/
│   │   └── main.go               # CLI entrypoint
│   │
│   └── aegis-viz/
│       ├── main.go               # Dashboard server
│       └── static/
│           └── index.html        # UI + ChartJS + Tailwind
│
├── internal/
│   ├── ai/
│   │   └── advisor.go            # AI advisor heuristics + crashloop detection
│   │
│   ├── guardian/
│   │   ├── api.go                # Alerts API handler
│   │   ├── defender.go           # Safe kill logic
│   │   └── ebpf.go               # Log + resolve + save detections
│   │
│   ├── orchestrator/
│   │   └── docker.go             # Docker provisioning + container status
│   │
│   ├── platform/
│   │   └── db.go                 # SQLite init + schema + persistence
│   │
│   └── security/
│       ├── gatekeeper.go         # Image policy enforcement
│       ├── guardian.c            # eBPF program (execve tracepoint)
│       ├── monitor.go            # eBPF loader + ringbuf reader
│       ├── bpf_bpfel.go          # generated Go bindings
│       └── bpf_bpfel.o           # generated object (optional)
│
├── scripts/
│   └── db_check.go               # helper for DB checks
│
├── app.yaml                      # sample workload
├── cluster.yaml                  # cluster config
├── test-app.yaml                 # test deploy
├── test-nginx.yaml               # test deploy
│
├── go.mod
├── go.sum
└── README.md

````

---

# ⚙️ Requirements

### OS
✅ Linux (mandatory for eBPF)

### Tools
- Go 1.20+
- Docker installed + running
- Root permissions (for eBPF monitoring)

---

# 🧠 Docker API Fix (If Docker errors)
If docker API negotiation fails:

```bash
export DOCKER_API_VERSION=1.44
````

---

# 🚀 FULL RUN SEQUENCE (Recommended)

Because AEGIS uses **Kernel-level monitoring**, the Engine must run with `sudo`.

---

## 🧹 Step 1: Clean Start (Safe)

```bash
sudo pkill -9 aegis-engine || true
sudo pkill -9 aegis-viz || true
sudo fuser -k 8080/tcp || true
sudo fuser -k 8081/tcp || true
```

---

## 🛡️ Step 2: Start AEGIS-ENGINE (Terminal 1)

```bash
cd ~/Pictures/aegis-v/cmd/aegis-engine
go build -o aegis-engine .
sudo ./aegis-engine
```

Engine endpoints:

* `http://localhost:8080/health`
* `http://localhost:8080/status`
* `http://localhost:8080/alerts`
* `http://localhost:8080/api/logs`

---

## 📊 Step 3: Start AEGIS-VIZ (Terminal 2)

```bash
cd ~/Pictures/aegis-v/cmd/aegis-viz
go build -o aegis-viz .
./aegis-viz
```

Open dashboard:
👉 `http://localhost:8081`

---

## 🎛️ Step 4: Build AEGIS-CTL (Terminal 3)

```bash
cd ~/Pictures/aegis-v/cmd/aegis-ctl
go build -o aegis-ctl .
```

---

# 🎮 AEGIS-CTL Commands (ALL)

### Help

```bash
./aegis-ctl help
```

### Status (Services + Incidents)

```bash
./aegis-ctl status
```

### Alerts

```bash
./aegis-ctl alerts
```

### Delete Service

```bash
./aegis-ctl delete <service-name>
```

Example:

```bash
./aegis-ctl delete nginx-service
```

---

# 📦 Deploy Workloads (YAML)

### Deploy Nginx

```bash
cd ~/Pictures/aegis-v
./cmd/aegis-ctl/aegis-ctl test-nginx.yaml
```

### Deploy App

```bash
./cmd/aegis-ctl/aegis-ctl test-app.yaml
```

---

# 🧪 Attack Simulation / Testing

## ✅ Normal commands (safe)

```bash
ls
pwd
echo "AEGIS-V running"
```

## 🚨 Suspicious host command (should alert)

```bash
sudo cat /etc/shadow
```

## 🚨 Container exec attempt

```bash
docker ps
docker exec -it <container-id> bash
```

---

# 🛡️ Security Features

## 1) eBPF Runtime Exec Monitoring

* Hooks into:

  * `tracepoint/syscalls/sys_enter_execve`
* Captures:

  * PID, PPID, UID
  * Mount namespace (container identity)
  * command name

## 2) Smart Noise Filtering

AEGIS avoids logging:

* systemd / dockerd / containerd
* VS Code / gopls / apt
* AEGIS internal processes

## 3) AI Advisor Verdict

Threat classification detects patterns like:

* `/etc/shadow` access
* netcat reverse shell
* wget/curl malware ingress
* crypto miners
* recon tools (nmap, tcpdump)

## 4) Active Defense (Guardian Defender)

* Suspicious processes can be terminated
* Built-in safety:

  * does not kill system PID ranges
  * does not kill AEGIS components
  * prevents engine suicide
  * prevents killing engine child processes

## 5) Supply Chain Gatekeeper

Blocks deployment if:

* image uses `latest`
* no version tag
* registry not whitelisted
* keyword contains suspicious terms
* malformed image name

## 6) Self-Healing Reconciliation Loop

Every ~15 seconds:

* checks DB deployments
* checks live docker state
* if down:

  * AI Advisor analyzes alerts
  * either restart or quarantine

---

# 📈 Benefits / Why This Project is Powerful

✅ **Real kernel monitoring (not just logs)**
✅ **Detects runtime attacks inside containers**
✅ **Works like a lightweight SOC for Docker**
✅ **Auto-healing and quarantine logic**
✅ **CLI + Dashboard gives full observability**
✅ **Designed like production DevSecOps tooling**

---

# 💡 Use Cases

* DevSecOps demonstration project
* Mini container security platform
* eBPF learning + runtime security research
* AI-driven AIOps + incident correlation
* Lightweight alternative for lab environments

---

# 🛠️ Troubleshooting

## Port Already in Use

```bash
sudo fuser -k 8080/tcp
sudo fuser -k 8081/tcp
```

## Docker API mismatch

```bash
export DOCKER_API_VERSION=1.44
```

## Dashboard not updating

* Ensure Engine is running on `8080`
* Ensure Viz is running on `8081`
* Refresh browser: `Ctrl + Shift + R`

---

# 🗺️ Roadmap (Future Improvements)

* Add authentication for API endpoints
* Add Prometheus metrics
* Add container network isolation response
* Add real LLM integration (Ollama / OpenAI)
* Add signed image verification (cosign)
* Multi-node cluster support

---

# 👤 Author

**Debasish-87**
Email: `22btics06@suiit.ac.in`

---

# ⭐ Support

If you like this project, give it a ⭐ on GitHub — it motivates future upgrades!

```
