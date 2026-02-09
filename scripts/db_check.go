package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func main() {
	// 1. Possible paths jahan DB ho sakta hai
	home, _ := os.UserHomeDir()
	baseDir := filepath.Join(home, "Pictures", "aegis-v")
	
	paths := []string{
		filepath.Join(baseDir, "aegis.db"), // Root wala
		filepath.Join(baseDir, "cmd", "aegis-engine", "aegis.db"), // Engine folder wala
	}

	var dbPath string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			// Check if table exists in this DB
			if tableExists(p) {
				dbPath = p
				break
			}
		}
	}

	if dbPath == "" {
		log.Fatal("[ERROR] Sahi database file nahi mili jisme data ho. Pehle engine chalao aur deploy karo.")
	}

	fmt.Printf("[INFO] Using Database: %s\n", dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, name, image, status FROM deployments")
	if err != nil {
		log.Fatal("Query Error: ", err)
	}
	defer rows.Close()

	fmt.Println("\n--- AEGIS-V DATABASE EXPOSURE ---")
	fmt.Printf("%-5s %-25s %-25s %-15s\n", "ID", "SERVICE NAME", "DOCKER IMAGE", "STATUS")
	fmt.Println(strings.Repeat("-", 75))

	for rows.Next() {
		var id int
		var name, image, status string
		rows.Scan(&id, &name, &image, &status)
		fmt.Printf("%-5d %-25s %-25s %-15s\n", id, name, image, status)
	}
	fmt.Println(strings.Repeat("-", 75))
}

func tableExists(path string) bool {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return false
	}
	defer db.Close()
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='deployments'").Scan(&name)
	return err == nil
}