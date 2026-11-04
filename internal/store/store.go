// Package store persists captured flows to a per-project SQLite database using
// the pure-Go modernc.org/sqlite driver (no cgo required).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"interlace/internal/model"
	"interlace/internal/scanner"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS flows (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ts           INTEGER NOT NULL,
	method       TEXT    NOT NULL,
	scheme       TEXT    NOT NULL,
	host         TEXT    NOT NULL,
	path         TEXT    NOT NULL,
	url          TEXT    NOT NULL,
	req_headers  TEXT    NOT NULL,
	req_body     BLOB,
	status_code  INTEGER NOT NULL,
	resp_headers TEXT    NOT NULL,
	resp_body    BLOB,
	content_type TEXT,
	duration_ms  INTEGER NOT NULL,
	error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_ts   ON flows(ts);

CREATE TABLE IF NOT EXISTS findings (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	flow_id    INTEGER,
	ts         INTEGER NOT NULL,
	severity   TEXT    NOT NULL,
	check_slug TEXT    NOT NULL,
	title      TEXT    NOT NULL,
	detail     TEXT,
	host       TEXT,
	url        TEXT,
	evidence   TEXT,
	source     TEXT DEFAULT 'passive',
	dedup_key  TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS ws_messages (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        INTEGER NOT NULL,
	host      TEXT,
	url       TEXT,
	direction TEXT,
	opcode    TEXT,
	payload   TEXT
);

CREATE TABLE IF NOT EXISTS saved_requests (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,
	name   TEXT    NOT NULL,
	scheme TEXT    NOT NULL,
	host   TEXT    NOT NULL,
	raw    TEXT    NOT NULL
);
`

// Store wraps the SQLite database connection.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the project database at path and ensures the schema.
func Open(path string) (*Store, error) {
	// _pragma busy_timeout avoids "database is locked" under concurrent writes
	// from many proxy goroutines.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite writes are serialized; a single connection keeps WAL simple here.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	// Lightweight migration for databases created before the note column existed.
	// SQLite has no "ADD COLUMN IF NOT EXISTS"; a duplicate-column error is benign.
	if _, err := db.Exec(`ALTER TABLE findings ADD COLUMN note TEXT`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column") {
		db.Close()
		return nil, fmt.Errorf("migrate findings.note: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Insert stores a flow and returns its assigned ID.
func (s *Store) Insert(f *model.Flow) (int64, error) {
	reqH, _ := json.Marshal(f.ReqHeaders)
	respH, _ := json.Marshal(f.RespHeaders)
	res, err := s.db.Exec(
		`INSERT INTO flows (ts, method, scheme, host, path, url, req_headers, req_body,
			status_code, resp_headers, resp_body, content_type, duration_ms, error)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.Timestamp.UnixMilli(), f.Method, f.Scheme, f.Host, f.Path, f.URL,
		string(reqH), f.ReqBody, f.StatusCode, string(respH), f.RespBody,
		f.ContentType, f.DurationMs, f.Error,
	)
	if err != nil {
		return 0, fmt.Errorf("insert flow: %w", err)
	}
	return res.LastInsertId()
}

// ListOpts controls List filtering/pagination.
type ListOpts struct {
	Host   string // substring match on host, optional
	Query  string // full-text search across url/host/path and bodies, optional
	Limit  int
	Offset int
}

// List returns flow summaries (no bodies) newest-first.
func (s *Store) List(opts ListOpts) ([]model.Flow, error) {
	if opts.Limit <= 0 || opts.Limit > 1000 {
		opts.Limit = 200
	}
	query := `SELECT id, ts, method, scheme, host, path, url, status_code, content_type, duration_ms, error, COALESCE(LENGTH(resp_body),0)
	          FROM flows`
	args := []any{}
	var where []string
	if opts.Host != "" {
		where = append(where, `host LIKE ?`)
		args = append(args, "%"+opts.Host+"%")
	}
	if opts.Query != "" {
		where = append(where, `(url LIKE ? OR host LIKE ? OR path LIKE ? OR CAST(req_body AS TEXT) LIKE ? OR CAST(resp_body AS TEXT) LIKE ?)`)
		q := "%" + opts.Query + "%"
		args = append(args, q, q, q, q, q)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, opts.Limit, opts.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list flows: %w", err)
	}
	defer rows.Close()

	var out []model.Flow
	for rows.Next() {
		var f model.Flow
		var tsMilli int64
		if err := rows.Scan(&f.ID, &tsMilli, &f.Method, &f.Scheme, &f.Host, &f.Path,
			&f.URL, &f.StatusCode, &f.ContentType, &f.DurationMs, &f.Error, &f.RespLen); err != nil {
			return nil, fmt.Errorf("scan flow: %w", err)
		}
		f.Timestamp = time.UnixMilli(tsMilli)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Get returns a single flow including bodies and headers.
func (s *Store) Get(id int64) (*model.Flow, error) {
	var f model.Flow
	var tsMilli int64
	var reqH, respH string
	err := s.db.QueryRow(
		`SELECT id, ts, method, scheme, host, path, url, req_headers, req_body,
			status_code, resp_headers, resp_body, content_type, duration_ms, error
		 FROM flows WHERE id = ?`, id,
	).Scan(&f.ID, &tsMilli, &f.Method, &f.Scheme, &f.Host, &f.Path, &f.URL,
		&reqH, &f.ReqBody, &f.StatusCode, &respH, &f.RespBody, &f.ContentType,
		&f.DurationMs, &f.Error)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get flow: %w", err)
	}
	f.Timestamp = time.UnixMilli(tsMilli)
	f.ReqHeaders = decodeHeader(reqH)
	f.RespHeaders = decodeHeader(respH)
	return &f, nil
}

// ExportFlows returns every flow with bodies and headers (for project export).
func (s *Store) ExportFlows() ([]model.Flow, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, method, scheme, host, path, url, req_headers, req_body,
			status_code, resp_headers, resp_body, content_type, duration_ms, error
		 FROM flows ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("export flows: %w", err)
	}
	defer rows.Close()
	var out []model.Flow
	for rows.Next() {
		var f model.Flow
		var tsMilli int64
		var reqH, respH string
		if err := rows.Scan(&f.ID, &tsMilli, &f.Method, &f.Scheme, &f.Host, &f.Path, &f.URL,
			&reqH, &f.ReqBody, &f.StatusCode, &respH, &f.RespBody, &f.ContentType,
			&f.DurationMs, &f.Error); err != nil {
			return nil, err
		}
		f.Timestamp = time.UnixMilli(tsMilli)
		f.ReqHeaders = decodeHeader(reqH)
		f.RespHeaders = decodeHeader(respH)
		out = append(out, f)
	}
	return out, rows.Err()
}

// Clear removes all stored flows and findings.
func (s *Store) Clear() error {
	if _, err := s.db.Exec(`DELETE FROM flows`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM findings`); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM ws_messages`)
	return err
}

// InsertFinding stores a finding, ignoring duplicates by dedup key. It reports
// whether a new row was actually inserted and, if so, its ID.
func (s *Store) InsertFinding(f *scanner.Finding) (id int64, inserted bool, err error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO findings (flow_id, ts, severity, check_slug, title, detail, host, url, evidence, source, dedup_key)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		f.FlowID, f.Time.UnixMilli(), f.Severity, f.Check, f.Title, f.Detail, f.Host, f.URL, f.Evidence, f.Source, f.Key,
	)
	if err != nil {
		return 0, false, fmt.Errorf("insert finding: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return 0, false, nil // duplicate
	}
	id, _ = res.LastInsertId()
	return id, true, nil
}

// ListFindings returns findings most-severe first, then newest.
func (s *Store) ListFindings() ([]scanner.Finding, error) {
	rows, err := s.db.Query(
		`SELECT id, flow_id, ts, severity, check_slug, title, detail, host, url, evidence, COALESCE(source,'passive'), COALESCE(note,'')
		 FROM findings
		 ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, id DESC
		 LIMIT 2000`)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	var out []scanner.Finding
	for rows.Next() {
		var f scanner.Finding
		var tsMilli int64
		if err := rows.Scan(&f.ID, &f.FlowID, &tsMilli, &f.Severity, &f.Check,
			&f.Title, &f.Detail, &f.Host, &f.URL, &f.Evidence, &f.Source, &f.Note); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		f.Time = time.UnixMilli(tsMilli)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetFindingNote stores (or clears) an analyst note on a finding.
func (s *Store) SetFindingNote(id int64, note string) error {
	_, err := s.db.Exec(`UPDATE findings SET note = ? WHERE id = ?`, note, id)
	return err
}

// SavedRequest is a named, reusable Repeater request.
type SavedRequest struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Raw    string `json:"raw"`
}

// SaveRequest persists a named Repeater request and returns its ID.
func (s *Store) SaveRequest(r SavedRequest) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO saved_requests (ts, name, scheme, host, raw) VALUES (?,?,?,?,?)`,
		time.Now().UnixMilli(), r.Name, r.Scheme, r.Host, r.Raw)
	if err != nil {
		return 0, fmt.Errorf("save request: %w", err)
	}
	return res.LastInsertId()
}

// ListSavedRequests returns saved Repeater requests, newest first.
func (s *Store) ListSavedRequests() ([]SavedRequest, error) {
	rows, err := s.db.Query(`SELECT id, name, scheme, host, raw FROM saved_requests ORDER BY id DESC LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("list saved requests: %w", err)
	}
	defer rows.Close()
	var out []SavedRequest
	for rows.Next() {
		var r SavedRequest
		if err := rows.Scan(&r.ID, &r.Name, &r.Scheme, &r.Host, &r.Raw); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteSavedRequest removes a saved Repeater request by ID.
func (s *Store) DeleteSavedRequest(id int64) error {
	_, err := s.db.Exec(`DELETE FROM saved_requests WHERE id = ?`, id)
	return err
}

// CountFindings returns the total number of findings.
func (s *Store) CountFindings() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&n)
	return n, err
}

// InsertWS stores a WebSocket message and returns its ID.
func (s *Store) InsertWS(m *model.WSMessage) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO ws_messages (ts, host, url, direction, opcode, payload) VALUES (?,?,?,?,?,?)`,
		m.Time.UnixMilli(), m.Host, m.URL, m.Direction, m.Opcode, m.Payload)
	if err != nil {
		return 0, fmt.Errorf("insert ws: %w", err)
	}
	return res.LastInsertId()
}

// ListWS returns recent WebSocket messages, newest first.
func (s *Store) ListWS(limit int) ([]model.WSMessage, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.db.Query(
		`SELECT id, ts, host, url, direction, opcode, payload FROM ws_messages ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list ws: %w", err)
	}
	defer rows.Close()
	var out []model.WSMessage
	for rows.Next() {
		var m model.WSMessage
		var tsMilli int64
		if err := rows.Scan(&m.ID, &tsMilli, &m.Host, &m.URL, &m.Direction, &m.Opcode, &m.Payload); err != nil {
			return nil, err
		}
		m.Time = time.UnixMilli(tsMilli)
		out = append(out, m)
	}
	return out, rows.Err()
}

// Count returns the total number of stored flows.
func (s *Store) Count() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n)
	return n, err
}

func decodeHeader(s string) http.Header {
	h := http.Header{}
	_ = json.Unmarshal([]byte(s), &h)
	return h
}
