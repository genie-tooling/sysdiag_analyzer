package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Store is the persisted, learned baseline: unit -> metric -> state, plus a
// last-seen timestamp per unit for age-based pruning. It is small (hundreds of
// units x a few metrics x a few floats) and lives as one JSON file.
type Store struct {
	Units    map[string]map[string]*MetricState `json:"units"`
	LastSeen map[string]float64                 `json:"last_seen"`
}

func New() *Store {
	return &Store{
		Units:    map[string]map[string]*MetricState{},
		LastSeen: map[string]float64{},
	}
}

func (s *Store) metric(unit string) map[string]*MetricState {
	m := s.Units[unit]
	if m == nil {
		m = map[string]*MetricState{}
		s.Units[unit] = m
	}
	return m
}

// Load reads the baseline state, returning a fresh store if absent/corrupt.
func Load(path string) *Store {
	b, err := os.ReadFile(path)
	if err != nil {
		return New()
	}
	var s Store
	if json.Unmarshal(b, &s) != nil || s.Units == nil {
		return New()
	}
	if s.LastSeen == nil {
		s.LastSeen = map[string]float64{}
	}
	return &s
}

// Save persists the store atomically (temp file + rename).
func (s *Store) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Prune drops units not seen within maxAgeSecs of now (bounds growth from
// transient scopes) while tolerating brief absences.
func (s *Store) Prune(now, maxAgeSecs float64) {
	for unit, last := range s.LastSeen {
		if now-last > maxAgeSecs {
			delete(s.Units, unit)
			delete(s.LastSeen, unit)
		}
	}
}
