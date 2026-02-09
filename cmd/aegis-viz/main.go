package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings" // Fixed: Added this import

	_ "github.com/glebarez/go-sqlite"
)

func main() {
	// Connect to the DB file (Path from aegis-viz to engine)
	db, err := sql.Open("sqlite", "../aegis-engine/aegis_audit.db")
	if err != nil {
		log.Fatal("[ERROR] Could not open database:", err)
	}
	defer db.Close()

	// Query data from deployments table
	rows, err := db.Query("SELECT id, service_name, image, replicas, timestamp FROM deployments")
	if err != nil {
		log.Fatal("[ERROR] Query failed:", err)
	}
	defer rows.Close()

	fmt.Println("\n--- AEGIS-V AUDIT VAULT RECORDS ---")
	// Table Header
	fmt.Printf("%-3s | %-20s | %-40s | %-3s | %-20s\n", "ID", "Service", "Image", "Rep", "Timestamp")
	fmt.Println(strings.Repeat("-", 100))

	// Iterate through rows
	for rows.Next() {
		var id, replicas int
		var name, image, ts string
		err := rows.Scan(&id, &name, &image, &replicas, &ts)
		if err != nil {
			log.Printf("[WARN] Row scan failed: %v", err)
			continue
		}
		// Professional table row format
		fmt.Printf("%-3d | %-20s | %-40s | %-3d | %-20s\n", id, name, image, replicas, ts)
	}
}
