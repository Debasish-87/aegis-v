package ai

import (
	"fmt"
	"strings"
	"time"
)

// Advisor represents the advanced AIOps engine
type Advisor struct {
	ModelPath        string
	EntropyThreshold float64
	// In-memory cache to track recurring failures (CrashLoop detection)
	FailureHistory map[string]int
}

// AnalysisResult defines the structured output for the engine
type AnalysisResult struct {
	Action      string
	RootCause   string
	Severity    string
	Remediation string
}

// NewAdvisor initializes the advisor with history tracking
func NewAdvisor(modelPath string) *Advisor {
	return &Advisor{
		ModelPath:      modelPath,
		FailureHistory: make(map[string]int),
	}
}

// AnalyzeState performs heuristic and pattern-based analysis
func (a *Advisor) AnalyzeState(serviceName string, lastError string, alerts []string) string {
	result := a.processIntelligence(serviceName, lastError, alerts)

	// Update Failure History
	if result.Severity == "CRITICAL" || result.Action == "BLOCK" {
		a.FailureHistory[serviceName]++
	}

	// CrashLoopBackOff Detection
	if a.FailureHistory[serviceName] > 3 && result.Action != "BLOCK" {
		return fmt.Sprintf("BLOCK: Service '%s' entered CrashLoop (Failures: %d). Manual intervention required.", serviceName, a.FailureHistory[serviceName])
	}

	// Output formatted for AEGIS Control Plane
	if result.Action == "BLOCK" {
		// Yahan hum BLOCK ke saath reason bhi bhej rahe hain taaki Dashboard pe dikhe
		return fmt.Sprintf("[CRITICAL] BLOCK -> %s", result.RootCause)
	}

	return fmt.Sprintf("[%s] %s -> %s", result.Severity, result.RootCause, result.Remediation)
}

// GetVerdict: Ye naya function hai jo eBPF alerts ko instant analyze karega
func (a *Advisor) GetVerdict(cmd string, identity string, source string) string {
	alerts := []string{cmd}
	res := a.processIntelligence(source, "", alerts)
	return fmt.Sprintf("%s: %s", res.Severity, res.RootCause)
}

func (a *Advisor) processIntelligence(serviceName string, lastError string, alerts []string) AnalysisResult {

	// 1. PHASE: CYBER-THREAT CORRELATION (Security Vector)
	// Added: High-fidelity patterns for modern container attacks
	threatPatterns := map[string]string{
		"shadow":   "Credential Access (Etc/Shadow) Attempt",
		"chmod":    "Privilege Escalation via Permission Change",
		"nc":       "Netcat Reverse Shell / Data Leak Detected",
		"iptables": "Firewall Bypass / Network Tampering",
		"base64":   "Encoded Malware Payload Execution",
		"curl":     "External Script/Malware Ingress",
		"wget":     "Unauthorized Binary Download",
		"stratum":  "Crypto-mining (Stratum Protocol) Detected",
		"nmap":     "Internal Network Reconnaissance",
		"tcpdump":  "Packet Sniffing / Traffic Capture",
		"bash":     "Unauthorized Interactive Shell Spawned",
		"sh":       "Unauthorized Shell Access",
		"python":   "Suspicious Python Script Execution",
	}

	for _, alert := range alerts {
		alertLow := strings.ToLower(alert)
		for pattern, description := range threatPatterns {
			if strings.Contains(alertLow, pattern) {
				return AnalysisResult{
					Action:      "BLOCK",
					RootCause:   description,
					Severity:    "CRITICAL",
					Remediation: "Quarantining container and freezing reconciliation.",
				}
			}
		}
	}

	// 2. PHASE: INFRASTRUCTURE ANOMALY (SRE Vector)
	lastError = strings.ToLower(lastError)

	if strings.Contains(lastError, "137") || strings.Contains(lastError, "oom") || strings.Contains(lastError, "killed") {
		return AnalysisResult{
			Action:      "RESTART_WITH_UPGRADE",
			RootCause:   "Resource Exhaustion (OOMKilled)",
			Severity:    "WARNING",
			Remediation: "Increasing memory limits for next deployment.",
		}
	}

	if strings.Contains(lastError, "139") || strings.Contains(lastError, "segmentation fault") || strings.Contains(lastError, "sigsegv") {
		return AnalysisResult{
			Action:      "RESTART_STABLE",
			RootCause:   "Memory Corruption / Segfault",
			Severity:    "HIGH",
			Remediation: "Rolling back to stable image tag.",
		}
	}

	// 3. PHASE: NETWORK & CONFIGURATION DRIFT
	if strings.Contains(lastError, "exit code 1") || strings.Contains(lastError, "connrefused") || strings.Contains(lastError, "timeout") {
		return AnalysisResult{
			Action:      "RESTART_DELAYED",
			RootCause:   "Dependency Outage (DB/DNS Timeout)",
			Severity:    "MEDIUM",
			Remediation: "Backing off for 15s to allow recovery.",
		}
	}

	// 4. PHASE: KERNEL-LEVEL ANOMALIES (Detected via eBPF)
	if len(alerts) > 10 {
		return AnalysisResult{
			Action:      "THROTTLE",
			RootCause:   "Excessive Security Alerts (Flooding)",
			Severity:    "MEDIUM",
			Remediation: "Rate-limiting container and enabling aggressive filtering.",
		}
	}

	// 5. DEFAULT: SELF-HEALING REFLEX
	return AnalysisResult{
		Action:      "RESTART",
		RootCause:   fmt.Sprintf("Intermittent System Flake (%s)", time.Now().Format("15:04:05")),
		Severity:    "LOW",
		Remediation: "Standard recovery: Cleaning orphan layers and restarting.",
	}
}