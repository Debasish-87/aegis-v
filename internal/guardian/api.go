package guardian

import (
	"encoding/json"
	"net/http"
	"github.com/Debasish-87/aegis-v/internal/platform"
)

type Detection struct {
	ID        int    `json:"id"`
	Command   string `json:"command"`
	Risk      string `json:"risk"`
	Identity  string `json:"identity"`
	Source    string `json:"source"`
	PID       int    `json:"pid"`
	Timestamp string `json:"timestamp"`
}

// GetAlertsHandler fetches all security detections from DB
func GetAlertsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := platform.DB.Query("SELECT id, command, risk, identity, source, pid, timestamp FROM detections ORDER BY id DESC LIMIT 50")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []Detection
	for rows.Next() {
		var a Detection
		if err := rows.Scan(&a.ID, &a.Command, &a.Risk, &a.Identity, &a.Source, &a.PID, &a.Timestamp); err != nil {
			continue
		}
		alerts = append(alerts, a)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}