package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

type Reporter struct {
	mu       sync.Mutex
	dir      string
	activity *os.File
	results  *os.File
	findings *os.File
	attempts *os.File
}

func New(dir string) (*Reporter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	open := func(name string) (*os.File, error) {
		return os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	}
	activity, err := open("activity.log")
	if err != nil {
		return nil, err
	}
	results, err := open("results.jsonl")
	if err != nil {
		activity.Close()
		return nil, err
	}
	findings, err := open("findings.jsonl")
	if err != nil {
		activity.Close()
		results.Close()
		return nil, err
	}
	attempts, err := open("attempts.jsonl")
	if err != nil {
		activity.Close()
		results.Close()
		findings.Close()
		return nil, err
	}
	return &Reporter{dir: dir, activity: activity, results: results, findings: findings, attempts: attempts}, nil
}

func (r *Reporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for _, f := range []*os.File{r.activity, r.results, r.findings, r.attempts} {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (r *Reporter) WriteAttempts(attempts []model.Attempt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	w := bufio.NewWriter(r.attempts)
	for _, attempt := range attempts {
		data, err := json.Marshal(attempt)
		if err != nil {
			return err
		}
		if _, err := w.Write(append(data, '\n')); err != nil {
			return err
		}
	}
	return w.Flush()
}

func (r *Reporter) WriteResult(result model.DispatchResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if _, err := r.results.Write(append(data, '\n')); err != nil {
		return err
	}
	line := fmt.Sprintf("%s SENT %s status=%d bytes=%d duration=%s", result.SentAt.Format(time.RFC3339), result.AttemptID, result.StatusCode, result.ResponseBytes, result.Duration)
	if result.Error != "" {
		line += " error=" + result.Error
	}
	_, err = fmt.Fprintln(r.activity, line)
	return err
}

func (r *Reporter) WriteFinding(finding model.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	if _, err := r.findings.Write(append(data, '\n')); err != nil {
		return err
	}
	seenAt := finding.LastSeen
	if len(finding.Events) > 0 {
		seenAt = finding.Events[len(finding.Events)-1].SeenAt
	}
	_, err = fmt.Fprintf(r.activity, "%s CALLBACK %s vector=%s point=%s target=%s\n", seenAt.Format(time.RFC3339), finding.Attempt.ID, finding.Attempt.Vector, finding.Attempt.InjectionPoint, finding.Attempt.TargetURL)
	return err
}

func (r *Reporter) WriteSummary(s model.Session) error {
	type summary struct {
		ScanID         string         `json:"scan_id"`
		CreatedAt      time.Time      `json:"created_at"`
		UpdatedAt      time.Time      `json:"updated_at"`
		Attempts       int            `json:"attempts"`
		Dispatched     int            `json:"dispatched"`
		Errors         int            `json:"errors"`
		Callbacks      int            `json:"callbacks"`
		CallbackEvents int            `json:"callback_events"`
		ByVector       map[string]int `json:"by_vector"`
		FindingIDs     []string       `json:"finding_ids"`
	}
	out := summary{ScanID: s.ScanID, CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt, Attempts: len(s.Attempts), Dispatched: len(s.Results), Callbacks: len(s.Findings), ByVector: map[string]int{}}
	for _, finding := range s.Findings {
		out.CallbackEvents += len(finding.Events)
	}
	for _, attempt := range s.Attempts {
		out.ByVector[attempt.Vector]++
	}
	for _, result := range s.Results {
		if result.Error != "" {
			out.Errors++
		}
	}
	for id := range s.Findings {
		out.FindingIDs = append(out.FindingIDs, id)
	}
	sort.Strings(out.FindingIDs)
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.dir, "summary.json"), append(data, '\n'), 0o600)
}
