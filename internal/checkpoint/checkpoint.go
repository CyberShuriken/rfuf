package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Checkpoint struct {
	Domain         string    `json:"domain"`
	StartedAt      time.Time `json:"started_at"`
	LastUpdated    time.Time `json:"last_updated"`
	CompletedSteps []string  `json:"completed_steps"`
	path           string
}

func Load(workDir string, domain string) (*Checkpoint, error) {
	cpPath := filepath.Join(workDir, ".rfuf", "checkpoint.json")
	if _, err := os.Stat(cpPath); os.IsNotExist(err) {
		return &Checkpoint{
			Domain:         domain,
			StartedAt:      time.Now(),
			LastUpdated:    time.Now(),
			CompletedSteps: []string{},
			path:           cpPath,
		}, nil
	}

	data, err := os.ReadFile(cpPath)
	if err != nil {
		return nil, err
	}

	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	cp.path = cpPath
	return &cp, nil
}

func (cp *Checkpoint) Save() error {
	cp.LastUpdated = time.Now()
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(cp.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(cp.path, data, 0644)
}

func (cp *Checkpoint) IsCompleted(stepID string) bool {
	for _, s := range cp.CompletedSteps {
		if s == stepID {
			return true
		}
	}
	return false
}

func (cp *Checkpoint) CompleteStep(stepID string) error {
	cp.CompletedSteps = append(cp.CompletedSteps, stepID)
	return cp.Save()
}
