package executor

import (
	"sync"
	"testing"
)

// Reproduces the crash the live re-audit hit: the scheduler loop mutates
// AuthEnv (applyWafStealth) while stage goroutines range it in redactSecrets /
// rfufEnv. Before the RWMutex this failed under -race (and fatal-crashed in
// production). Run with: go test -race ./internal/executor/
func TestAuthEnvConcurrentReadWrite(t *testing.T) {
	SetAuthEnv("RFUF_AUTH_COOKIE", "session=secretvalue12345")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = redactSecrets("line with session=secretvalue12345 in it")
				_ = rfufEnv()
			}
		}()
	}
	// Concurrent writer, mimicking applyWafStealth in the scheduler loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			SetAuthEnv("RFUF_USER_AGENT", "ua")
			SetAuthEnv("RFUF_STEALTH_HEADERS", "-H x")
		}
	}()
	wg.Wait()
}
