package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings" // Added for name cleaning
	"sync"
	"syscall"
	"time"

	"github.com/Debasish-87/aegis-v/internal/ai"
	"github.com/Debasish-87/aegis-v/internal/guardian"
	"github.com/Debasish-87/aegis-v/internal/orchestrator"
	"github.com/Debasish-87/aegis-v/internal/platform"
	"github.com/Debasish-87/aegis-v/internal/security"
	_ "github.com/glebarez/go-sqlite"
)

var (
	deployLock sync.Mutex
	advisor    = ai.Advisor{ModelPath: "ollama/llama3"}
)

// ANSI Color Codes
const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorReset  = "\033[0m"
)

type DeployRequest struct {
	Name   string  `json:"name"`
	Image  string  `json:"image"`
	CPU    float64 `json:"cpu"`
	Memory int64   `json:"memory"`
}

type ServiceStatus struct {
	Name      string  `json:"name"`
	Image     string  `json:"image"`
	CPU       float64 `json:"cpu"`
	Memory    int64   `json:"memory"`
	Status    string  `json:"status"`
	AIInsight string  `json:"ai_insight"`
}

// ---------------------------------------------------------
// API Endpoint for aegis-ctl to fetch latest logs
// ---------------------------------------------------------
func handleApiLogs(w http.ResponseWriter, r *http.Request) {
	rows, err := platform.DB.Query("SELECT timestamp, command, source, risk FROM detections ORDER BY id DESC LIMIT 5")
	if err != nil {
		http.Error(w, "DB Error", 500)
		return
	}
	defer rows.Close()

	var logs []map[string]string
	for rows.Next() {
		var ts, cmd, src, risk string
		rows.Scan(&ts, &cmd, &src, &risk)
		logs = append(logs, map[string]string{
			"timestamp": ts,
			"command":   cmd,
			"source":    src,
			"risk":      risk,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func startReconciliationLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] Reconciliation Loop Recovered from panic: %v", r)
			time.Sleep(2 * time.Second)
			go startReconciliationLoop()
		}
	}()

	for {
		time.Sleep(15 * time.Second)

		rows, err := platform.DB.Query("SELECT name, image, cpu, memory FROM deployments")
		if err != nil {
			log.Printf("[ERROR] DB Query failed in loop: %v", err)
			continue
		}

		for rows.Next() {
			var name, image string
			var cpu float64
			var mem int64
			rows.Scan(&name, &image, &cpu, &mem)

			go func(n, img string, c float64, m int64) {
				if !orchestrator.IsContainerRunning(n) {
					deployLock.Lock()
					defer deployLock.Unlock()

					if !orchestrator.IsContainerRunning(n) {
						fmt.Printf(ColorYellow+"[SELF-HEALING] 🚨 Service '%s' is DOWN.\n"+ColorReset, n)
						fmt.Printf(ColorPurple+"[AI-ADVISOR] 🧠 Analyzing root cause for %s...\n"+ColorReset, n)

						alerts := getRecentAlerts(n)
						insightChan := make(chan string, 1)

						go func() {
							contextMsg := fmt.Sprintf("Service %s failed. Recent suspicious activity found: %d alerts.", n, len(alerts))
							res := advisor.AnalyzeState(n, contextMsg, alerts)
							insightChan <- res
						}()

						var insight string
						select {
						case res := <-insightChan:
							insight = res
						case <-time.After(10 * time.Second):
							insight = "TIMEOUT_AUTO_RECOVER"
							fmt.Printf(ColorRed + "[SYSTEM] ⚠️ AI Advisor Timeout. Defaulting to Safety Recovery.\n" + ColorReset)
						}

						platform.DB.Exec("UPDATE deployments SET ai_insight = ? WHERE name = ?", insight, n)

						if insight == "BLOCK" {
							fmt.Printf(ColorRed+"[SECURITY] 🛡️ AI Blocked restart of %s due to threat detection.\n"+ColorReset, n)
							platform.DB.Exec("UPDATE deployments SET status = 'QUARANTINED' WHERE name = ?", n)
						} else {
							fmt.Printf(ColorGreen+"[SYSTEM] 🛠️ Auto-recovery in progress for %s...\n"+ColorReset, n)
							err := orchestrator.ProvisionContainer(img, n, c, m)
							if err == nil {
								platform.DB.Exec("UPDATE deployments SET status = 'ACTIVE', ai_insight = 'Self-Healed via AEGIS' WHERE name = ?", n)
								fmt.Printf(ColorGreen+"[SUCCESS] %s is back online.\n"+ColorReset, n)
							}
						}
					}
				}
			}(name, image, cpu, mem)
		}
		rows.Close()
	}
}

func getRecentAlerts(serviceName string) []string {
	var alerts []string
	rows, _ := platform.DB.Query("SELECT command || ' (Risk: ' || risk || ')' FROM detections WHERE identity LIKE ? ORDER BY timestamp DESC LIMIT 10", "%"+serviceName+"%")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cmd string
			rows.Scan(&cmd)
			alerts = append(alerts, cmd)
		}
	}
	return alerts
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req DeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid Payload", 400)
		return
	}

	fmt.Printf(ColorBlue+"[GATEKEEPER] 🛡️ Verifying image integrity for %s...\n"+ColorReset, req.Image)
	gatekeeper := security.NewGatekeeper()
	isSafe, reason := gatekeeper.VerifyImage(req.Image)

	if !isSafe {
		fmt.Printf(ColorRed+"[SECURITY-VIOLATION] 🛡️ BLOCKING DEPLOYMENT: %s\n"+ColorReset, reason)
		platform.DB.Exec("INSERT INTO security_alerts (service, alert_type, message) VALUES (?, ?, ?)",
			req.Name, "POLICY_VIOLATION", reason)
		http.Error(w, "Gatekeeper Blocked: "+reason, http.StatusForbidden)
		return
	}

	deployLock.Lock()
	defer deployLock.Unlock()

	platform.DB.Exec("INSERT OR REPLACE INTO deployments (name, image, cpu, memory, status, ai_insight, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
		req.Name, req.Image, req.CPU, req.Memory, "PROVISIONING", "Initial validation passed", time.Now())

	fmt.Printf(ColorGreen+"[SYSTEM] Provisioning Container: %s...\n"+ColorReset, req.Name)
	err := orchestrator.ProvisionContainer(req.Image, req.Name, req.CPU, req.Memory)
	if err != nil {
		log.Printf("[ERROR] Provisioning failed: %v", err)
		platform.DB.Exec("UPDATE deployments SET status = 'FAILED', ai_insight = ? WHERE name = ?", err.Error(), req.Name)
		http.Error(w, "Provisioning Failed", 500)
		return
	}

	platform.DB.Exec("UPDATE deployments SET status = 'ACTIVE', ai_insight = 'Monitoring Started' WHERE name = ?", req.Name)
	fmt.Printf(ColorPurple+"[AI-ADVISOR] Behavioral monitoring active for '%s'.\n"+ColorReset, req.Name)
	fmt.Printf(ColorGreen+"[SUCCESS] AEGIS-V: Workload '%s' is now shielded and live.\n\n"+ColorReset, req.Name)

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("AEGIS-V: Secure deployment successful"))
}

// handleStatus: (UPDATED) Combines DB and Real-time Docker Status
func handleStatus(w http.ResponseWriter, r *http.Request) {
	// 1. Get Live Docker List
	dockerContainers, err := orchestrator.GetAllContainers()
	if err != nil {
		log.Printf("[ERROR] Failed to fetch live docker status: %v", err)
	}

	// 2. Get DB Deployments
	rows, err := platform.DB.Query("SELECT name, image, cpu, memory, status, COALESCE(ai_insight, 'No Insights Available') FROM deployments")
	if err != nil {
		http.Error(w, "DB Error", 500)
		return
	}
	defer rows.Close()

	dbMap := make(map[string]ServiceStatus)
	for rows.Next() {
		var s ServiceStatus
		var dbStatus, insight string
		rows.Scan(&s.Name, &s.Image, &s.CPU, &s.Memory, &dbStatus, &insight)
		s.Status = dbStatus
		s.AIInsight = insight
		dbMap[s.Name] = s
	}

	var finalStatuses []ServiceStatus

	// 3. Merge Live Docker data into Response
	for _, c := range dockerContainers {
		name := "unknown"
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		if dbInfo, exists := dbMap[name]; exists {
			dbInfo.Status = "✅ " + c.Status // Real Docker status
			finalStatuses = append(finalStatuses, dbInfo)
			delete(dbMap, name) // Avoid duplicate
		} else {
			// Manual containers not in our DB
			finalStatuses = append(finalStatuses, ServiceStatus{
				Name:      name,
				Image:     c.Image,
				Status:    "⚪ " + c.Status,
				AIInsight: "External Service",
			})
		}
	}

	// 4. Handle Offline/Crashed services (In DB but not in Docker)
	for _, s := range dbMap {
		s.Status = "🚨 DOWN"
		finalStatuses = append(finalStatuses, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalStatuses)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Missing name", 400)
		return
	}
	deployLock.Lock()
	defer deployLock.Unlock()

	fmt.Printf(ColorRed+"[SYSTEM] Decommissioning service: %s\n"+ColorReset, name)
	platform.DB.Exec("DELETE FROM deployments WHERE name = ?", name)
	orchestrator.StopContainer(name)
	w.Write([]byte("Service removed successfully"))
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	rows, err := platform.DB.Query("SELECT id, command, risk, source, identity, pid, timestamp FROM detections ORDER BY timestamp DESC LIMIT 50")
	if err != nil {
		http.Error(w, "DB Error", 500)
		return
	}
	defer rows.Close()

	var alerts []map[string]interface{}
	for rows.Next() {
		var id, pid int
		var cmd, risk, src, identity, ts string
		rows.Scan(&id, &cmd, &risk, &src, &identity, &pid, &ts)
		alerts = append(alerts, map[string]interface{}{
			"id": id, "command": cmd, "risk": risk, "source": src, "identity": identity, "pid": pid, "timestamp": ts,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("AEGIS-ENGINE: UP"))
}

func main() {
	dbConn, err := platform.InitDB()
	if err != nil {
		log.Fatalf("[CRITICAL] Storage Failure: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	guardian.InitGuardian(dbConn)
	fmt.Println(ColorBlue + "[SYSTEM] AEGIS-V Engine v2.3 (Autonomous & AI-Driven) Initializing..." + ColorReset)

	go security.StartSecurityMonitor()
	go startReconciliationLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/deploy", handleDeploy)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/delete", handleDelete)
	mux.HandleFunc("/alerts", handleAlerts)
	mux.HandleFunc("/api/logs", handleApiLogs)
	mux.HandleFunc("/health", handleHealth)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		fmt.Println(ColorGreen + "[SYSTEM] API Gateway listening on :8080" + ColorReset)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-ctx.Done()
	fmt.Println(ColorYellow + "\n[SYSTEM] Graceful shutdown initiated..." + ColorReset)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.Shutdown(shutdownCtx)
	dbConn.Close()
	fmt.Println(ColorGreen + "[SYSTEM] Engine offline. All security probes detached." + ColorReset)
}