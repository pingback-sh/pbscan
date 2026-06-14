package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

type Store struct {
	mu       sync.Mutex
	path     string
	session  model.Session
	pending  int
	lastSave time.Time
}

func New(path string, s model.Session) *Store {
	if s.Results == nil {
		s.Results = map[string]model.DispatchResult{}
	}
	if s.Findings == nil {
		s.Findings = map[string]model.Finding{}
	}
	return &Store{path: path, session: s, lastSave: time.Now()}
}

func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s model.Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse session: %w", err)
	}
	return New(path, s), nil
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) AddResult(result model.DispatchResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session.Results[result.AttemptID] = result
	s.session.UpdatedAt = time.Now().UTC()
	s.pending++
	if s.pending >= 25 || time.Since(s.lastSave) >= 2*time.Second {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) AddFinding(finding model.Finding) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(finding.Events) == 0 {
		return false, nil
	}
	existing, exists := s.session.Findings[finding.Attempt.ID]
	seen := map[string]struct{}{}
	for _, observation := range existing.Events {
		seen[observationKey(observation.Event)] = struct{}{}
	}
	added := false
	for _, observation := range finding.Events {
		key := observationKey(observation.Event)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		existing.Events = append(existing.Events, observation)
		if !exists || existing.FirstSeen.IsZero() || observation.SeenAt.Before(existing.FirstSeen) {
			existing.FirstSeen = observation.SeenAt
		}
		if existing.LastSeen.IsZero() || observation.SeenAt.After(existing.LastSeen) {
			existing.LastSeen = observation.SeenAt
		}
		added = true
	}
	if !added {
		return false, nil
	}
	existing.Attempt = finding.Attempt
	s.session.Findings[finding.Attempt.ID] = existing
	s.session.UpdatedAt = time.Now().UTC()
	return true, s.saveLocked()
}

func (s *Store) SetLastHitID(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id <= s.session.LastHitID {
		return nil
	}
	s.session.LastHitID = id
	s.session.UpdatedAt = time.Now().UTC()
	s.pending++
	if s.pending >= 25 || time.Since(s.lastSave) >= 2*time.Second {
		return s.saveLocked()
	}
	return nil
}

func (s *Store) Snapshot() model.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, _ := json.Marshal(s.session)
	var out model.Session
	_ = json.Unmarshal(data, &out)
	return out
}

func (s *Store) Path() string { return s.path }

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.session, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.pending = 0
	s.lastSave = time.Now()
	return nil
}

func observationKey(event map[string]any) string {
	data, _ := json.Marshal(event)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
