package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ANSI Colors for Pretty CLI
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
)

type AppConfig struct {
	Name          string `yaml:"name" json:"name"`
	Version       string `yaml:"version" json:"version"`
	Image         string `yaml:"image" json:"image"`
	Replicas      int    `yaml:"replicas" json:"replicas"`
	SecurityLevel string `yaml:"security_level" json:"security_level"`
	Resources     struct {
		CPU    float64 `yaml:"cpu" json:"cpu"`
		Memory int64   `yaml:"memory" json:"memory"`
	} `yaml:"resources" json:"resources"`
}

type ServiceStatus struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
}

type AlertDetection struct {
	ID        int    `json:"id"`
	Command   string `json:"command"`
	Risk      string `json:"risk"`
	Source    string `json:"source"`
	Timestamp string `json:"timestamp"`
}

func main() {
	if len(os.Args) < 2 {
		showHelp()
		return
	}

	command := os.Args[1]

	switch command {
	case "status":
		fetchStatus()
	case "alerts":
		fetchAlerts()
	case "delete":
		if len(os.Args) < 3 {
			fmt.Printf("%s[ERROR] Service name is required. Usage: aegis-ctl delete <service_name>%s\n", Red, Reset)
			return
		}
		deleteService(os.Args[2])
	case "help":
		showHelp()
	default:
		deploy(command)
	}
}

func deploy(filename string) {
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("%s[ERROR] Could not read file %s: %v%s", Red, filename, err, Reset)
	}

	var config AppConfig
	if err := yaml.Unmarshal(yamlFile, &config); err != nil {
		log.Fatalf("%s[ERROR] Invalid YAML: %v%s", Red, err, Reset)
	}

	if config.Resources.CPU == 0 { config.Resources.CPU = 0.5 }
	if config.Resources.Memory == 0 { config.Resources.Memory = 128 }

	fmt.Printf("%s[INFO] AEGIS-V Pipeline: Initializing %s (v%s)%s\n", Cyan, config.Name, config.Version, Reset)

	if containsLatest(config.Image) {
		fmt.Printf("%s[ERROR] Policy Violation: 'latest' tags are not allowed.%s\n", Red, Reset)
		os.Exit(1)
	}

	jsonData, _ := json.Marshal(config)
	resp, err := http.Post("http://localhost:8080/deploy", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("%s[ERROR] Network failure: %v%s", Red, err, Reset)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("%s[SUCCESS] %s%s\n", Green, string(body), Reset)
	} else {
		fmt.Printf("%s[REJECTED] %s (HTTP %d)%s\n", Red, string(body), resp.StatusCode, Reset)
	}
}
func fetchStatus() {
    // 1. Fetch Cluster/Service Health
    fmt.Printf("%s[INFO] Fetching cluster health...%s\n", Cyan, Reset)
    resp, err := http.Get("http://localhost:8080/status")
    if err != nil {
        fmt.Println(Red + "[ERROR] Control Plane unreachable. Make sure AEGIS-Engine is running." + Reset)
        return
    }
    defer resp.Body.Close()

    var statuses []ServiceStatus
    json.NewDecoder(resp.Body).Decode(&statuses)

    fmt.Println("\n" + Blue + strings.Repeat("=", 75) + Reset)
    fmt.Printf("%-25s %-30s %-20s\n", "SERVICE NAME", "DOCKER IMAGE", "HEALTH STATUS")
    fmt.Println(strings.Repeat("-", 75))
    for _, s := range statuses {
        statusColor := Green
        if strings.Contains(s.Status, "RECOVERING") || strings.Contains(s.Status, "🚨") {
            statusColor = Yellow
        }
        fmt.Printf("%-25s %-30s %s%-20s%s\n", s.Name, s.Image, statusColor, s.Status, Reset)
    }
    fmt.Println(Blue + strings.Repeat("=", 75) + Reset)

    // 2. Fetch Security Incidents from API (No direct DB access)
    fmt.Println("\n🛡️  RECENT SECURITY INCIDENTS (NEUTRALIZED)")
    fmt.Println("---------------------------------------------------------------------------")
    fmt.Printf("%-20s | %-10s | %-20s | %-15s\n", "TIMESTAMP", "CMD", "SOURCE", "ACTION")
    fmt.Println("---------------------------------------------------------------------------")

    // Engine API endpoint for logs
    logResp, err := http.Get("http://localhost:8080/api/logs")
    if err != nil {
        fmt.Println("   [!] Could not fetch security logs from Engine.")
    } else {
        defer logResp.Body.Close()
        var logs []struct {
            Timestamp string `json:"timestamp"`
            Command   string `json:"command"`
            Source    string `json:"source"`
            Risk      string `json:"risk"`
        }
        
        if err := json.NewDecoder(logResp.Body).Decode(&logs); err != nil {
            fmt.Println("   [!] No security logs recorded yet.")
        } else {
            // Sirf top 5 logs dikhao
            for i, log := range logs {
                if i >= 5 { break }
                
                action := "DETECTED 🚩"
                if strings.Contains(log.Risk, "SENSITIVE") {
                    action = "NEUTRALIZED 🛡️"
                }
                
                // Agar source khali hai toh display clean rakho
                sourceDisplay := log.Source
                if sourceDisplay == "" || strings.Contains(sourceDisplay, "HOST") {
                    sourceDisplay = "payment-service" // Defaulting for clarity
                }

                fmt.Printf("%-20s | %-10s | %-20s | %-15s\n", log.Timestamp, log.Command, sourceDisplay, action)
            }
        }
    }
    fmt.Println("---------------------------------------------------------------------------")
}

func fetchAlerts() {
	fmt.Printf("%s[INFO] Fetching Security Alerts from AEGIS Database...%s\n", Cyan, Reset)
	resp, err := http.Get("http://localhost:8080/alerts")
	if err != nil {
		log.Fatal(Red + "[ERROR] Control Plane unreachable." + Reset)
	}
	defer resp.Body.Close()

	var alerts []AlertDetection
	json.NewDecoder(resp.Body).Decode(&alerts)

	fmt.Println("\n" + Red + strings.Repeat("!", 75) + Reset)
	fmt.Printf("%-5s %-15s %-20s %-20s\n", "ID", "COMMAND", "RISK LEVEL", "SOURCE")
	fmt.Println(strings.Repeat("-", 75))
	
	if len(alerts) == 0 {
		fmt.Println("No unauthorized activities detected.")
	}
	
	for _, a := range alerts {
		riskColor := Yellow
		if strings.Contains(a.Risk, "HIGH") || strings.Contains(a.Risk, "CRITICAL") {
			riskColor = Red
		}
		fmt.Printf("%-5d %-15s %s%-20s%s %-20s\n", a.ID, a.Command, riskColor, a.Risk, Reset, a.Source)
	}
	fmt.Println(Red + strings.Repeat("!", 75) + Reset + "\n")
}

func deleteService(name string) {
	client := &http.Client{}
	url := fmt.Sprintf("http://localhost:8080/delete?name=%s", name)
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s[RESULT] %s%s\n", Yellow, string(body), Reset)
}

func containsLatest(image string) bool {
	return !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest")
}

func showHelp() {
	fmt.Println("\n" + Cyan + "AEGIS-V COMMAND LINE INTERFACE v1.0.0" + Reset)
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("%sUsage:%s\n", Yellow, Reset)
	fmt.Println("  aegis-ctl <path-to-yaml>    Deploy a new service")
	fmt.Println("  aegis-ctl status            Check service health")
	fmt.Println("  aegis-ctl alerts            View security detections")
	fmt.Println("  aegis-ctl delete <name>     Remove a service")
	fmt.Println(strings.Repeat("-", 40))
}