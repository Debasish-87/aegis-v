package api

import (
	"encoding/json"
	"net/http"

	"github.com/Debasish-87/aegis-v/internal/guardian"
	"github.com/Debasish-87/aegis-v/internal/orchestrator"
)

// StatusResponse defines the JSON structure sent to aegis-ctl
type StatusResponse struct {
	Services  []ServiceInfo       `json:"services"`
	Incidents []guardian.Incident `json:"incidents"`
}

type ServiceInfo struct {
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
}

// HandleStatus fetches both container health and security logs
func HandleStatus(w http.ResponseWriter, r *http.Request) {
	// 1. Fetch Containers from Orchestrator
	dockerContainers, err := orchestrator.GetAllContainers()
	if err != nil {
		http.Error(w, "Failed to fetch cluster health", http.StatusInternalServerError)
		return
	}

	var services []ServiceInfo
	for _, c := range dockerContainers {
		name := "Unknown"
		if len(c.Names) > 0 {
			name = c.Names[0][1:] // Remove leading slash
		}
		services = append(services, ServiceInfo{
			Name:   name,
			Image:  c.Image,
			Status: c.Status,
		})
	}

	// 2. Fetch Incidents from Guardian (Database)
	incidents, err := guardian.GetRecentIncidents(10) // Last 10 incidents
	if err != nil {
		incidents = []guardian.Incident{} // Fallback to empty
	}

	// 3. Send combined response
	response := StatusResponse{
		Services:  services,
		Incidents: incidents,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleProvision (Optional: if you want to deploy via API)
func HandleProvision(w http.ResponseWriter, r *http.Request) {
	// Provision logic can be added here later
	w.Write([]byte("Provisioning endpoint active"))
}