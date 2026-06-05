// Package config provides paths for PortKeep's local data store.
package config

import (
	"os"
	"path/filepath"
)

// DataDir returns ~/.portkeep, creating it if needed.
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".portkeep")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

// RegistryPath returns the path to the port registry JSON file.
func RegistryPath() string {
	return filepath.Join(DataDir(), "registry.json")
}

// CacheDir returns the path to the threat-intel cache directory.
func CacheDir() string {
	dir := filepath.Join(DataDir(), "cache")
	_ = os.MkdirAll(dir, 0700)
	return dir
}

// CachePath returns the path to a named source's cache file.
func CachePath(source string) string {
	return filepath.Join(CacheDir(), source+".json")
}
