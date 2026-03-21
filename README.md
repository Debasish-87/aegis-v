# 🛡️ AEGIS-V

> **A security-first container control plane** — deploys workloads, enforces supply-chain policy, monitors runtime behavior at the kernel level, and automatically heals or quarantines containers. Built for Docker on a single node.

---

## 🧭 How AEGIS-V Is Different

Most runtime security tools sit *beside* your infrastructure — they observe and alert, but they don't control anything. You still need a separate orchestrator to deploy, manage, and recover containers.

**AEGIS-V collapses security and orchestration into a single control loop:**

```
Deploy → Enforce → Monitor → Respond → Recover
```

It validates workloads *before* they start, watches them at the kernel level *while* they run, and autonomously heals or quarantines them *when* something goes wrong — all in one system, no Kubernetes required.

| Capability | AEGIS-V | Typical Security Monitor |
|---|---|---|
| Deploys containers | ✅ Yes | ❌ No |
| Supply-chain policy at deploy time | ✅ Yes | ❌ No |
| eBPF runtime monitoring | ✅ Yes | ✅ Yes |
| Active process termination | ✅ Yes | Sometimes |
| Self-healing / quarantine | ✅ Yes | ❌ No |
| Requires Kubernetes | ❌ No — Docker only | Usually yes |

> For Kubernetes-native runtime security, see [KubeRTSec](https://github.com/Debasish-87/kubertsec) — a separate project that runs as a DaemonSet and focuses on detection and alerting across a cluster. AEGIS-V takes a different approach: it *owns* the container lifecycle from deploy through recovery, and integrates security decisions into every step.

---

## 🔍 What AEGIS-V Does

### Before a container starts — Gatekeeper

Every workload passes through a supply-chain policy check before it is provisioned:

- Blocks untagged or `:latest` images
- Enforces a registry allowlist
- Scans image names for blacklisted keywords
- Rejects malformed or injection-risk image references

Nothing gets deployed unless it passes. No exceptions.

### While a container runs — eBPF Monitor

AEGIS-V attaches a tracepoint to `sys_enter_execve` at the kernel level:

- Captures PID, PPID, UID, mount namespace, and command name for every process execution
- Resolves mount namespaces to Docker container names
- Filters known-safe processes at both kernel and userspace levels
- Classifies threats using rule-based pattern matching
- Optionally terminates suspicious processes using a safe, whitelist-guarded kill path

### When something goes wrong — Reconciliation Loop

Every ~15 seconds, AEGIS-V compares what *should* be running (DB desired state) against what *is* running (live Docker state):

- Benign crash → restart
- Security incident → quarantine, prevent restart
- All decisions logged and visible in the dashboard

---

## ⚙️ Core Components

### AEGIS-ENGINE — Control Plane (`localhost:8080`)

The single binary that runs everything:

- **Gatekeeper** — supply-chain enforcement before any container starts
- **Orchestrator** — provisions Docker containers with CPU/memory limits
- **eBPF Monitor** — kernel-level process execution tracing
- **Rule-Based Advisor** — threat classification and severity assignment
- **Reconciliation Loop** — desired-state enforcement and security-aware recovery
- **SQLite persistence** (`aegis.db`) — deployments, detections, security alerts

Endpoints: `/deploy` · `/status` · `/alerts` · `/delete` · `/health` · `/api/logs`

### AEGIS-CTL — CLI

```bash
./aegis-ctl <workload.yaml>         # Deploy a workload
./aegis-ctl status                  # Running services + active incidents
./aegis-ctl alerts                  # Detection history
./aegis-ctl delete <service-name>   # Remove a workload
./aegis-ctl help
```

### AEGIS-VIZ — Dashboard (`localhost:8081`)

- Live security event stream (auto-refresh)
- Threat count and bar chart
- Source-wise attack visualization
- Real-time audit feed

---

## 🔁 System Flows

### Deploy Flow

```
aegis-ctl <yaml>
      │
      ▼
POST /deploy
      │
      ▼
Gatekeeper policy check
  (registry · tag · keywords · format)
      │
   Passed?
  ┌───┴───┐
 YES      NO → rejected with reason
  │
  ▼
Orchestrator provisions container
(image pull · CPU/MEM limits · start)
      │
      ▼
State written to SQLite
```

### Runtime Detection Flow

```
Process executes inside container
      │
      ▼
eBPF captures execve
(pid · ppid · uid · mount_ns · comm)
      │
      ▼
Kernel-side noise filter
(drops systemd · dockerd · AEGIS-own)
      │
      ▼
Userspace: NS → container name resolved
      │
      ▼
Rule-based Advisor classifies threat
(LOW / MEDIUM / HIGH / CRITICAL)
      │
      ▼
Detection stored in SQLite → Dashboard updated
      │
(If HIGH/CRITICAL) Defender safely kills PID
  • whitelist check
  • parent-chain check (won't kill engine lineage)
  • system PID range check
```

### Self-Healing Flow

```
Reconciliation loop (every ~15s)
      │
      ▼
DB desired state ↔ live Docker state
      │
  Drift found?
  ┌────┴────┐
 YES        NO → continue
  │
  ▼
Advisor correlates recent detections
      │
  Safe to restart?
  ┌────┴─────────┐
 YES             NO
  │               │
 Restart       Quarantine
(normal crash) (security incident)
```

---

## 🧠 Architecture

```
                  ┌─────────────────────────────────────┐
                  │           AEGIS-CTL (CLI)           │
                  │  Deploy · Status · Alerts · Delete  │
                  └──────────────────┬──────────────────┘
                                     │ HTTP
                                     ▼

┌────────────────────────────────────────────────────────────────────────────┐
│                          AEGIS-ENGINE  (:8080)                             │
│                                                                            │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌────────────────────┐  │
│  │     Gatekeeper      │  │    Orchestrator     │  │  Rule-Based        │  │
│  │  (Supply Chain)     │  │  (Docker Runtime)   │  │  Advisor           │  │
│  │  blocks :latest     │  │  pull image         │  │  threat classify   │  │
│  │  registry allow     │  │  create container   │  │  severity mapping  │  │
│  │  keyword scan       │  │  CPU/MEM limits     │  │  recovery decision │  │
│  └──────────┬──────────┘  └──────────┬──────────┘  └────────┬───────────┘  │
│             └────────────────────────┴──────────────────────┘              │
│                                                                            │
│──────────────────── Runtime Security (Kernel Layer) ───────────────────────│
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Guardian + eBPF Monitor                                             │  │
│  │  tracepoint: sys_enter_execve                                        │  │
│  │  captures: pid · ppid · uid · mount_ns · comm                        │  │
│  │  resolves: namespace → container name                                │  │
│  │  filters:  system procs + AEGIS internals                            │  │
│  │  defense:  safe SIGKILL (whitelist + parent-chain guarded)           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│                       SQLite  (aegis.db)                                   │
│           deployments · detections · security_alerts                       │
└────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼

                  ┌─────────────────────────────────────┐
                  │           AEGIS-VIZ  (:8081)        │
                  │  Live Feed · Threat Charts · Audit  │
                  └─────────────────────────────────────┘
```

---

## 🔒 Security Capabilities

### Supply-Chain Gatekeeper
Policy enforced at deploy time — untagged images, unrecognized registries, suspicious keywords, and malformed references are blocked before a container is ever created.

### eBPF Exec Monitoring
Hooks `tracepoint/syscalls/sys_enter_execve`. Every process execution across all containers is captured at the kernel level with zero application instrumentation.

### Smart Noise Filtering
Known-safe processes suppressed at kernel and userspace — systemd, dockerd, containerd, Go toolchain, VS Code internals, and all AEGIS-own processes — so only real signals surface.

### Rule-Based Threat Classification
Detects patterns including:
- `/etc/shadow` and sensitive file access
- netcat / bash reverse shells
- wget / curl malware ingress
- crypto miner signatures
- recon tools (nmap, tcpdump, lsof)

Severity: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`

### Safe Active Defense
Defender sends SIGKILL with the following safeguards always active:
- Skips system PID ranges
- Skips AEGIS-engine and its child process lineage
- Respects a named process whitelist

### Security-Aware Self-Healing
Reconciliation loop uses recent detection history to decide between restart (benign crash) and quarantine (confirmed security incident). Not just crash recovery — security-informed recovery.

---

## 🧠 Key Design Decisions

| Decision | Rationale |
|---|---|
| Orchestration + security in one system | Eliminates the gap between "what should run" and "what is being watched" |
| Gatekeeper at deploy time | Prevents bad workloads from ever starting — cheaper than killing a running process |
| eBPF over log parsing | Real-time kernel visibility, no app changes, minimal overhead |
| Rule-based classification | Deterministic, explainable — auditable and predictable behavior |
| Security-informed reconciliation | Crash recovery decisions account for whether a security incident was involved |
| Docker-first, no Kubernetes | Self-contained and runnable on a single Linux machine |
| SQLite persistence | Zero external dependencies; WAL mode handles concurrent reads/writes |

---

## 📂 Project Structure

```
aegis-v/
│
├── cmd/
│   ├── aegis-engine/       # Control plane — API, gatekeeper, orchestration, eBPF, reconciliation
│   │   └── main.go
│   ├── aegis-ctl/          # CLI — deploy, status, alerts, delete
│   │   └── main.go
│   └── aegis-viz/          # Dashboard — live feed, threat charts
│       ├── main.go
│       └── static/index.html
│
├── internal/
│   ├── ai/
│   │   └── advisor.go      # Rule-based threat classification + severity + recovery decisions
│   ├── guardian/
│   │   ├── ebpf.go         # Alert pipeline: NS resolve, noise filter, DB write
│   │   ├── api.go          # Alerts API handler
│   │   └── defender.go     # Safe SIGKILL with whitelist + parent-chain protection
│   ├── orchestrator/
│   │   └── docker.go       # Container lifecycle + namespace → name mapping
│   ├── platform/
│   │   └── db.go           # SQLite schema, WAL mode, migration helpers
│   └── security/
│       ├── gatekeeper.go   # Supply-chain policy enforcement
│       ├── guardian.c      # eBPF C program — sys_enter_execve tracepoint
│       ├── monitor.go      # eBPF loader, ringbuf reader, whitelist suppression
│       ├── bpf_bpfel.go    # Generated Go bindings (bpf2go)
│       └── bpf_bpfel.o     # Compiled eBPF object
│
├── api/
│   └── handlers.go         # HTTP handlers — status aggregation, incidents
│
├── scripts/
│   └── db_check.go         # Dev helper — schema validation, incident inspection
│
├── deployments/            # Workload YAML files
├── app.yaml · cluster.yaml · test-nginx.yaml · test-app.yaml
├── go.mod · go.sum
└── README.md
```

---

#  Screenshots

##  AEGIS-VIZ Dashboard
![Dashboard](screenshots/dashboard.png)

##  Engine Running
![Engine Running](screenshots/EngineRunning.png)

##  Sensitive Data Logs Detection
![Sensitive Logs](screenshots/sensitivityDataLogs.png)

##  Isolated Attacker / Quarantine
![Isolated Attacker](screenshots/IsolatedAttacker.png)

##  Self-Healing Recovery
![Self Healing](screenshots/SelfHealling.png)

##  Whole System Status
![Whole System Status](screenshots/WholeSystemStatus.png)

##  CLI / Code View
![CLI](screenshots/Code.png)

---

## ⚙️ Requirements

- **OS:** Linux (mandatory — eBPF requires kernel support)
- **Go:** 1.20+
- **Docker:** installed and running
- **Permissions:** root (required for eBPF tracepoint attachment)

---

## 🚀 Running AEGIS-V

### Step 1 — Clean port state

```bash
sudo pkill -9 aegis-engine || true
sudo pkill -9 aegis-viz || true
sudo fuser -k 8080/tcp || true
sudo fuser -k 8081/tcp || true
```

### Step 2 — Start Engine (Terminal 1)

```bash
cd ~/Pictures/aegis-v/cmd/aegis-engine
go build -o aegis-engine .
sudo ./aegis-engine
```

### Step 3 — Start Dashboard (Terminal 2)

```bash
cd ~/Pictures/aegis-v/cmd/aegis-viz
go build -o aegis-viz .
./aegis-viz
# Open http://localhost:8081
```

### Step 4 — Build CLI (Terminal 3)

```bash
cd ~/Pictures/aegis-v/cmd/aegis-ctl
go build -o aegis-ctl .
```

**Deploy examples:**

```bash
./cmd/aegis-ctl/aegis-ctl test-nginx.yaml
./cmd/aegis-ctl/aegis-ctl test-app.yaml
```

---

## 🧪 Attack Simulation

```bash
# Safe — no alert
ls && pwd && echo "AEGIS-V running"

# Privileged file access — should alert HIGH/CRITICAL
sudo cat /etc/shadow

# Container exec attempt — should alert
docker exec -it <container-id> bash
```

---

## 🔧 Troubleshooting

**Port in use:**
```bash
sudo fuser -k 8080/tcp && sudo fuser -k 8081/tcp
```

**Docker API mismatch:**
```bash
export DOCKER_API_VERSION=1.44
```

**Dashboard not updating:** Confirm engine on `:8080`, viz on `:8081`. Hard refresh: `Ctrl + Shift + R`

---

## ⚠️ Scope & Limitations

- **Single-node only** — no multi-host support
- **Docker-native** — not a Kubernetes controller (see [KubeRTSec](https://github.com/Debasish-87/kubertsec) for that)
- **Rule-based detection** — deterministic heuristics, not ML models
- **Prototype / research system** — not designed for production deployment

---

## 🧭 Roadmap

- [ ] API authentication layer
- [ ] Prometheus metrics endpoint
- [ ] Container network isolation on quarantine
- [ ] Signed image verification (cosign)
- [ ] Multi-node cluster support

---

## 📌 Use Cases

- Understanding how container orchestration and runtime security can be unified in a single control loop
- eBPF learning and supply-chain enforcement prototyping
- DevSecOps demonstration and lab environments

---

## 👤 Author

**Debasish-87**  
`debasishm8765@gmail.com`
