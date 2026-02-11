package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

type Incident struct {
	ID        int    `json:"id"`
	Command   string `json:"command"`
	Risk      string `json:"risk"`
	Source    string `json:"source"`
	Timestamp string `json:"timestamp"`
}

var db *sql.DB

func main() {
	var err error
	// Database connection (aapka actual db file)
	db, err = sql.Open("sqlite", "../aegis-engine/aegis.db")
	if err != nil {
		log.Fatal("[ERROR] Database connection failed:", err)
	}

	// 1. Background Task: Terminal mein Live Audit dikhane ke liye
	go func() {
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Println("🛡️  AEGIS-V LIVE TERMINAL AUDIT VAULT")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Printf("%-25s | %-15s | %-40s\n", "TIMESTAMP", "SOURCE", "AI VERDICT")
		fmt.Println(strings.Repeat("-", 80))

		lastID := 0
		for {
			// Sirf naye incidents fetch karo jo last check ke baad aaye hain
			query := fmt.Sprintf("SELECT id, source, risk, timestamp FROM detections WHERE id > %d ORDER BY id ASC", lastID)
			rows, err := db.Query(query)
			if err == nil {
				for rows.Next() {
					var id int
					var source, risk, ts string
					rows.Scan(&id, &source, &risk, &ts)
					
					// Terminal par print karo
					fmt.Printf("%-25s | %-15s | %-40s\n", ts[:19], source, risk)
					lastID = id
				}
				rows.Close()
			}
			time.Sleep(2 * time.Second) // Har 2 sec mein check karega
		}
	}()

	// 2. Web Routes
	http.HandleFunc("/api/incidents", getIncidents)
	http.Handle("/", http.FileServer(http.Dir("./static")))

	fmt.Printf("\n[VIZ] 🌐 Web Dashboard live at http://localhost:8081\n\n")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func getIncidents(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, command, risk, source, timestamp FROM detections ORDER BY id DESC LIMIT 20")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var incidents []Incident
	for rows.Next() {
		var i Incident
		rows.Scan(&i.ID, &i.Command, &i.Risk, &i.Source, &i.Timestamp)
		incidents = append(incidents, i)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(incidents)
}