package probes

import (
	"context"
	"fmt"
	"sync"
)

type ProbeRunner func(ctx context.Context, pCtx ProbeContext) []Finding

var (
	probeMapMu sync.RWMutex
	probeMap   = make(map[string]ProbeRunner)
)

// Register registriert eine Probe-Funktion im Speicher. Neue Probe-Dateien
// melden sich üblicherweise in init() mit Register("modul_name", runner) an.
func Register(name string, runner ProbeRunner) {
	probeMapMu.Lock()
	defer probeMapMu.Unlock()
	if runner == nil {
		panic("Probe runner darf nicht nil sein")
	}
	probeMap[name] = runner
}

// RunModule führt eine registrierte Probe aus
func RunModule(ctx context.Context, name string, pCtx ProbeContext) ([]Finding, error) {
	probeMapMu.RLock()
	runner, exists := probeMap[name]
	probeMapMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("probe module nicht registriert: %s", name)
	}
	return runner(ctx, pCtx), nil
}
