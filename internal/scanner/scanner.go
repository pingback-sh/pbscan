package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pingback-sh/pbscan/internal/model"
)

type Options struct {
	Threads          int
	Rate             int
	Timeout          time.Duration
	Retries          int
	FollowRedirects  bool
	InsecureTLS      bool
	UserAgent        string
	MaxResponseBytes int64
}

type Scanner struct {
	client *http.Client
	opts   Options
}

func New(opts Options) *Scanner {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = opts.Threads * 2
	transport.MaxIdleConnsPerHost = opts.Threads
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.InsecureTLS} // #nosec G402 -- explicit CLI option.
	client := &http.Client{Transport: transport, Timeout: opts.Timeout}
	if !opts.FollowRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &Scanner{client: client, opts: opts}
}

func (s *Scanner) Dispatch(ctx context.Context, attempts []model.Attempt, onResult func(model.DispatchResult)) error {
	if len(attempts) == 0 {
		return nil
	}
	jobs := make(chan model.Attempt)
	errs := make(chan error, s.opts.Threads)

	interval := time.Second / time.Duration(s.opts.Rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for i := 0; i < s.opts.Threads; i++ {
		go func() {
			for attempt := range jobs {
				select {
				case <-ctx.Done():
					errs <- ctx.Err()
					return
				case <-ticker.C:
				}
				result := s.send(ctx, attempt)
				if onResult != nil {
					onResult(result)
				}
			}
			errs <- nil
		}()
	}

sendLoop:
	for _, attempt := range attempts {
		select {
		case <-ctx.Done():
			break sendLoop
		case jobs <- attempt:
		}
	}
	close(jobs)

	var firstErr error
	for i := 0; i < s.opts.Threads; i++ {
		if err := <-errs; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil && firstErr != context.Canceled {
		return firstErr
	}
	return nil
}

func (s *Scanner) send(ctx context.Context, attempt model.Attempt) model.DispatchResult {
	result := model.DispatchResult{AttemptID: attempt.ID, SentAt: time.Now().UTC()}
	started := time.Now()
	var lastErr error
	for try := 0; try <= s.opts.Retries; try++ {
		req, err := attempt.Request()
		if err != nil {
			lastErr = err
			break
		}
		req = req.WithContext(ctx)
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", s.opts.UserAgent)
		}
		req.Header.Set("X-PBScan-Attempt", attempt.ID)

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			if try < s.opts.Retries {
				if !sleepContext(ctx, time.Duration(try+1)*250*time.Millisecond) {
					lastErr = ctx.Err()
					break
				}
				continue
			}
			break
		}
		result.StatusCode = resp.StatusCode
		limit := s.opts.MaxResponseBytes
		if limit <= 0 {
			limit = 1 << 20
		}
		n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		result.ResponseBytes = n
		if readErr != nil {
			lastErr = fmt.Errorf("read response: %w", readErr)
		} else {
			lastErr = nil
		}
		break
	}
	result.Duration = time.Since(started)
	if lastErr != nil {
		result.Error = lastErr.Error()
	}
	return result
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
