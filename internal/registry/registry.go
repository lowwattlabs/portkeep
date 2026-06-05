// Package registry manages the local port registry (expected/known ports).
package registry

import (
	"encoding/json"
	"os"
)

const registryVersion = "1"

// PortEntry represents a single registered port.
type PortEntry struct {
	Port         int      `json:"port"`
	Protocol     string   `json:"protocol"`     // "tcp" or "udp"
	Service      string   `json:"service"`      // e.g. "sshd", "nginx"
	Description  string   `json:"description"`  // human-readable note
	Tags         []string `json:"tags"`         // optional labels
	RegisteredAt string   `json:"registered_at"` // RFC3339 timestamp
}

// Registry holds all registered ports.
type Registry struct {
	Version string      `json:"version"`
	Entries []PortEntry `json:"entries"`
}

// Load reads the registry from disk. Returns an empty registry if the file
// doesn't exist yet (first run).
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Registry{Version: registryVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	if reg.Version == "" {
		reg.Version = registryVersion
	}
	return &reg, nil
}

// Save writes the registry to disk atomically.
func Save(path string, reg *Registry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	// Write to a temp file then rename (atomic on most filesystems).
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Add inserts a new entry. Replaces existing entry for the same port/proto.
func (r *Registry) Add(entry PortEntry) {
	for i, e := range r.Entries {
		if e.Port == entry.Port && e.Protocol == entry.Protocol {
			r.Entries[i] = entry
			return
		}
	}
	r.Entries = append(r.Entries, entry)
}

// Remove deletes an entry by port+proto. Returns true if found and removed.
func (r *Registry) Remove(port int, proto string) bool {
	for i, e := range r.Entries {
		if e.Port == port && e.Protocol == proto {
			r.Entries = append(r.Entries[:i], r.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// IsRegistered returns true if the port+proto is in the registry.
func (r *Registry) IsRegistered(port int, proto string) bool {
	return r.Find(port, proto) != nil
}

// Find returns the entry for the given port+proto, or nil if not found.
func (r *Registry) Find(port int, proto string) *PortEntry {
	for i, e := range r.Entries {
		if e.Port == port && e.Protocol == proto {
			return &r.Entries[i]
		}
	}
	return nil
}
