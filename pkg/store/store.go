package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store provides sqlite persistence for darkscan
type Store struct {
	db *sql.DB
}

// ScanRecord represents a past scan log entry
type ScanRecord struct {
	ID        int
	FilePath  string
	Infected  bool
	Threats   string
	ScanTime  time.Time
	FileHash  string
}

// New initializes a new sqlite database at the given path
func New(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &Store{db: db}
	if err := s.Init(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

// Init creates necessary tables if they don't exist
func (s *Store) Init() error {
	query := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_path TEXT NOT NULL,
		infected BOOLEAN NOT NULL,
		threats TEXT,
		scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
		file_hash TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_file_path ON scans(file_path);
	CREATE INDEX IF NOT EXISTS idx_file_hash ON scans(file_hash);
	`
	_, err := s.db.Exec(query)
	return err
}

// RecordScan writes a scan record to the database
func (s *Store) RecordScan(record ScanRecord) error {
	query := `INSERT INTO scans (file_path, infected, threats, file_hash, scan_time) VALUES (?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, record.FilePath, record.Infected, record.Threats, record.FileHash, record.ScanTime)
	return err
}

// Cleanup removes records older than retentionMonths
func (s *Store) Cleanup(retentionMonths int) error {
	query := `DELETE FROM scans WHERE scan_time < datetime('now', '-' || ? || ' months')`
	_, err := s.db.Exec(query, retentionMonths)
	return err
}

// SearchScans queries the history for matching file paths, hashes, or threat heuristics
func (s *Store) SearchScans(searchQuery string, limit int) ([]ScanRecord, error) {
	query := `
	SELECT id, file_path, infected, threats, scan_time, file_hash 
	FROM scans 
	WHERE file_path LIKE ? OR threats LIKE ? OR file_hash = ?
	ORDER BY scan_time DESC LIMIT ?`

	likeMatch := "%" + searchQuery + "%"
	rows, err := s.db.Query(query, likeMatch, likeMatch, searchQuery, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.FilePath, &r.Infected, &r.Threats, &r.ScanTime, &r.FileHash); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

// GetRecentScans fetches the most recent scan logs
func (s *Store) GetRecentScans(limit int) ([]ScanRecord, error) {
	query := `SELECT id, file_path, infected, threats, scan_time, file_hash FROM scans ORDER BY scan_time DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		if err := rows.Scan(&r.ID, &r.FilePath, &r.Infected, &r.Threats, &r.ScanTime, &r.FileHash); err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}
