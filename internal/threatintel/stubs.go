package threatintel

import (
	"context"
	"fmt"
)

// Stub implementations — will be fleshed out in v0.2+

func fetchCISAKEV(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("CISA KEV sync not yet implemented (v0.2)")
}
func fetchEPSS(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("EPSS sync not yet implemented (v0.2)")
}
func fetchOSV(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("OSV sync not yet implemented (v0.2)")
}
func fetchThreatFox(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("ThreatFox sync not yet implemented (v0.2)")
}
func fetchURLhaus(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("URLhaus sync not yet implemented (v0.2)")
}
func fetchMalwareBazaar(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("MalwareBazaar sync not yet implemented (v0.2)")
}
func fetchFeodo(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("Feodo sync not yet implemented (v0.2)")
}
func fetchSemgrep(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("Semgrep sync not yet implemented (v0.2)")
}
func fetchYARA(ctx context.Context, cacheDir string) (string, error) {
	return "", fmt.Errorf("YARA sync not yet implemented (v0.2)")
}
func loadFeodoPorts(cacheDir string) []C2Port { return nil }
func loadThreatFoxPorts(cacheDir string) []C2Port { return nil }
func loadKEVMap(cacheDir string) []KEVEntry { return nil }
