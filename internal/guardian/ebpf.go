package guardian

import (
	"database/sql"
	"fmt"
	"log"
	"os" // Added for Getpid()
	"strconv"
	"strings"
	"time"

	"github.com/Debasish-87/aegis-v/internal/ai"
	"github.com/Debasish-87/aegis-v/internal/orchestrator"
)

var globalDB *sql.DB

// AI Advisor instance initialize
var advisor = ai.NewAdvisor("aegis-brain-v1")

// InitGuardian database ko initialize karta hai
func InitGuardian(db *sql.DB) {
	globalDB = db
}

// ProcessAndLog terminal pe dikhayega aur DB mein save karega
func ProcessAndLog(cmd string, pid int, risk string, source string, identity string) {

	// 🔥 ADDED RECOVERY & SELF-PROTECTION LOGIC 🔥
	if identity == "AEGIS_INTERNAL_RECOVERY" || pid == os.Getpid() {
		return // Agar engine khud recovery kar raha hai, toh allow karo
	}

	// 1. IMPROVED NOISE FILTER (Self-Protection Logic)
	cmdLow := strings.ToLower(cmd)

	if strings.Contains(cmdLow, "aegis") ||
		strings.Contains(cmdLow, "go") ||
		pid == os.Getpid() ||
		identity == "AEGIS_INTERNAL_RECOVERY" {
		return // Inhe turant ignore karo
	}

	if cmdLow == "runc" ||
		cmdLow == "containerd-shim" ||
		cmdLow == "runc:[2:init]" ||
		cmdLow == "docker-proxy" ||
		cmdLow == "healthcheck" ||
		strings.Contains(cmdLow, "aegis-viz") ||
		strings.Contains(cmdLow, "aegis-ctl") ||
		strings.Contains(cmdLow, "aegis-engine") ||
		cmdLow == "go" {
		return
	}

	// 2. Resolve "NS:ID" to "Container Name"
	resolvedSource := source
	if strings.HasPrefix(source, "NS:") {
		nsStr := strings.TrimPrefix(source, "NS:")
		nsID, err := strconv.ParseUint(nsStr, 10, 32)
		if err == nil {
			name := orchestrator.GetContainerNameByNamespace(uint32(nsID))
			if name != "" {
				resolvedSource = name
			} else if nsID == 4026531832 || nsID == 4026531840 {
				resolvedSource = "HOST / SYSTEM"
			}
		}
	}

	// 3. GET AI VERDICT
	aiVerdict := advisor.GetVerdict(cmd, identity, resolvedSource)

	// 4. Terminal Output
	fmt.Printf("\n[EBPF ALERT] 🚨 Unauthorized Exec Detected!\n")
	fmt.Printf("   ├─ Command:    %s\n", cmd)
	fmt.Printf("   ├─ AI Verdict: %s\n", aiVerdict)
	fmt.Printf("   ├─ Source:     %s\n", resolvedSource)
	fmt.Printf("   ├─ Identity:   %s\n", identity)
	fmt.Printf("   └─ PID:        %d\n", pid)
	fmt.Println("--------------------------------------------")

	// 5. Database Save Logic
	if globalDB != nil {
		query := `INSERT INTO detections (command, risk, source, identity, pid, timestamp) 
                  VALUES (?, ?, ?, ?, ?, ?)`
		_, err := globalDB.Exec(query, cmd, aiVerdict, resolvedSource, identity, pid, time.Now().Format(time.RFC3339Nano))
		if err != nil {
			log.Printf("[DB ERROR] Failed to save detection: %v", err)
		}
	}
}
