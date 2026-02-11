package platform

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/glebarez/go-sqlite"
)

var DB *sql.DB

func InitDB() (*sql.DB, error) {
	// FIXED: Hamesha Project Root ki DB use karein, bhale hi engine kisi bhi folder se chale
	cwd, _ := os.Getwd()
	// Agar hum cmd/aegis-engine mein hain, toh root par jane ke liye path fix karein
	dbPath := filepath.Join(cwd, "aegis.db")
	
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// Stability Settings
	db.SetMaxOpenConns(1)

	// --- FULL SYNCED SCHEMA ---
	const schema = `
    CREATE TABLE IF NOT EXISTS deployments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE, 
        image TEXT NOT NULL,
        cpu REAL DEFAULT 0.5,
        memory INTEGER DEFAULT 128,
        status TEXT,
        ai_insight TEXT DEFAULT 'Initial validation passed',
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        command TEXT,
        risk TEXT,
        source TEXT,
        identity TEXT,
        pid INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT,
        alert_type TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );`

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema error: %v", err)
	}

	// Column Migration (Double Check)
	_, _ = db.Exec("ALTER TABLE deployments ADD COLUMN ai_insight TEXT DEFAULT 'Monitoring active'")

	DB = db
	log.Printf("[DATABASE] ✅ Connected to: %s (WAL Mode)", dbPath)
	return db, nil
}

// LogDetection persists eBPF security events with Aggressive Filtering
func LogDetection(command, risk, source, identity string, pid int) error {
	if DB == nil {
		return fmt.Errorf("DB not ready")
	}
	
	// NOISE FILTER: In commands ko database mein mat daalo, ye engine/system ke hain
	noiseCommands := map[string]bool{
		"dockerd":         true,
		"containerd":      true,
		"containerd-shim": true,
		"go":              true,
		"sudo":            true,
		"runc":            true,
		"sh":              true, // Engine pulls ke waqt sh use karta hai
	}

	if noiseCommands[command] {
		return nil 
	}

	query := `INSERT INTO detections (command, risk, source, identity, pid) VALUES (?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, command, risk, source, identity, pid)
	if err != nil {
		log.Printf("[DB-ERROR] LogDetection: %v", err)
	}
	return err
}

// UpdateDeploymentStatus updates both status and AI insights
func UpdateDeploymentStatus(name, status, insight string) error {
	if DB == nil {
		return fmt.Errorf("DB not ready")
	}
	query := `UPDATE deployments SET status = ?, ai_insight = ?, last_seen = CURRENT_TIMESTAMP WHERE name = ?`
	_, err := DB.Exec(query, status, insight, name)
	return err
}