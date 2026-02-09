package platform

import (
	"database/sql"
	"fmt"

	// Humne driver change kar diya hai CGO-free version par
	_ "github.com/glebarez/go-sqlite" 
)

func InitDB() (*sql.DB, error) {
	// Driver name "sqlite3" se badal kar "sqlite" ho gaya hai
	db, err := sql.Open("sqlite", "./aegis_audit.db")
	if err != nil {
		return nil, fmt.Errorf("storage initialization failed: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database connectivity check failed: %v", err)
	}

	const schema = `
	CREATE TABLE IF NOT EXISTS deployments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service_name TEXT NOT NULL,
		image TEXT NOT NULL,
		replicas INTEGER NOT NULL,
		security_level TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema enforcement failed: %v", err)
	}

	return db, nil
}