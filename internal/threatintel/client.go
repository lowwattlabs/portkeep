// Package threatintel coordinates fetching and caching of 9 threat-intel sources.
package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DB is the aggregated, port-queryable threat intelligence database.
type DB struct {
	LastSync string     `json:"last_sync"`
	C2Ports  []C2Port   `json:"c2_ports"`
	KEVMap   []KEVEntry `json:"kev_entries"`
	sources  []string   // for AgeString
}

// C2Port is a port known to be used as a command-and-control endpoint.
type C2Port struct {
	Port    int    `json:"port"`
	Source  string `json:"source"`
	Malware string `json:"malware,omitempty"`
	Added   string `json:"added,omitempty"`
}

// KEVEntry maps a CISA-KEV product to ports it is commonly associated with.
type KEVEntry struct {
	Product string `json:"product"`
	Ports   []int  `json:"ports"`
}

// SyncResult reports the outcome of syncing one source.
type SyncResult struct {
	Source string
	Detail string
	Err    error
}

// C2Entries returns all C2Port entries matching the given port number.
func (db *DB) C2Entries(port int) []C2Port {
	var out []C2Port
	for _, c := range db.C2Ports {
		if c.Port == port {
			out = append(out, c)
		}
	}
	return out
}

// KEVMatchesForPort returns product names with CISA-KEV entries known to use
// the given port as a common attack surface.
func (db *DB) KEVMatchesForPort(port int) []string {
	var out []string
	for _, k := range db.KEVMap {
		for _, p := range k.Ports {
			if p == port {
				out = append(out, k.Product)
				break
			}
		}
	}
	return out
}

// AgeString returns a human-readable description of how old the threat intel is.
func (db *DB) AgeString() string {
	if db.LastSync == "" {
		return "not synced (run portkeep sync)"
	}
	t, err := time.Parse(time.RFC3339, db.LastSync)
	if err != nil {
		return db.LastSync
	}
	age := time.Since(t).Round(time.Minute)
	return fmt.Sprintf("%s old (synced %s)", age, t.Format("2006-01-02 15:04 UTC"))
}

// EmptyDB returns a zero-value DB for use when no cache exists.
func EmptyDB() *DB {
	return &DB{}
}

// Load reads the aggregated DB from cacheDir/db.json.
func Load(cacheDir string) (*DB, error) {
	path := filepath.Join(cacheDir, "db.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var db DB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, err
	}
	return &db, nil
}

// save persists the DB to cacheDir/db.json.
func save(cacheDir string, db *DB) error {
	db.LastSync = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(cacheDir, "db.json.tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(cacheDir, "db.json"))
}

// SyncAll fetches all 9 sources concurrently and returns per-source results.
// Partial failures are tolerated; the DB is saved with whatever succeeded.
func SyncAll(cacheDir string, timeout time.Duration) []SyncResult {
	type fetchFn struct {
		name string
		fn   func(ctx context.Context, cacheDir string) (string, error)
	}

	fetchers := []fetchFn{
		{"cisa-kev", fetchCISAKEV},
		{"epss", fetchEPSS},
		{"osv", fetchOSV},
		{"threatfox", fetchThreatFox},
		{"urlhaus", fetchURLhaus},
		{"malwarebazaar", fetchMalwareBazaar},
		{"feodo", fetchFeodo},
		{"semgrep", fetchSemgrep},
		{"yara", fetchYARA},
	}

	results := make([]SyncResult, len(fetchers))
	var wg sync.WaitGroup

	for i, f := range fetchers {
		wg.Add(1)
		go func(idx int, ff fetchFn) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			detail, err := ff.fn(ctx, cacheDir)
			results[idx] = SyncResult{
				Source: ff.name,
				Detail: detail,
				Err:    err,
			}
		}(i, f)
	}

	wg.Wait()

	// Re-aggregate DB from individual cache files.
	db := aggregate(cacheDir)
	_ = save(cacheDir, db)

	return results
}

// aggregate reads individual source caches and builds a unified DB.
func aggregate(cacheDir string) *DB {
	db := &DB{}

	// Pull C2 ports from Feodo
	db.C2Ports = append(db.C2Ports, loadFeodoPorts(cacheDir)...)

	// Pull C2 ports from ThreatFox
	db.C2Ports = append(db.C2Ports, loadThreatFoxPorts(cacheDir)...)

	// Pull KEV product-port mappings
	db.KEVMap = loadKEVMap(cacheDir)

	return db
}
