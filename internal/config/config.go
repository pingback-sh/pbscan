package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	APIBaseURL            string            `json:"api_base_url"`
	APIToken              string            `json:"api_token,omitempty"`
	AuthorizedUse         bool              `json:"authorized_use_accepted"`
	IncludeRequestSecrets bool              `json:"include_request_secrets"`
	CallbackTemplate      string            `json:"callback_template"`
	FeedURL               string            `json:"feed_url,omitempty"`
	FeedHeaders           map[string]string `json:"feed_headers,omitempty"`
	OutputDir             string            `json:"output_dir"`
	Threads               int               `json:"threads"`
	Rate                  int               `json:"rate"`
	Timeout               time.Duration     `json:"-"`
	TimeoutString         string            `json:"timeout"`
	Wait                  time.Duration     `json:"-"`
	WaitString            string            `json:"wait"`
	Retries               int               `json:"retries"`
	FollowRedirects       bool              `json:"follow_redirects"`
	InsecureTLS           bool              `json:"insecure_tls"`
	AllowPrivateTarget    bool              `json:"allow_private_targets"`
	UserAgent             string            `json:"user_agent"`
	HeaderNames           []string          `json:"header_names"`
	MaxResponseBytes      int64             `json:"max_response_bytes"`
}

func Default() Config {
	return Config{
		APIBaseURL:       "https://pingback.sh/api/v1",
		OutputDir:        "output",
		Threads:          10,
		Rate:             10,
		Timeout:          12 * time.Second,
		TimeoutString:    "12s",
		Wait:             20 * time.Second,
		WaitString:       "20s",
		Retries:          1,
		UserAgent:        "pbscan/1.1 (+https://github.com/pingback-sh/pbscan; authorized-security-testing)",
		MaxResponseBytes: 1 << 20,
		HeaderNames: []string{
			"Referer",
			"Origin",
			"X-Forwarded-Host",
			"X-Original-URL",
			"X-Rewrite-URL",
			"Forwarded",
			"Base-URL",
		},
	}
}

func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "pbscan.json"
	}
	return filepath.Join(home, ".config", "pbscan", "config.json")
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Normalize(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) Normalize() error {
	if c.Threads < 1 || c.Threads > 100 {
		return fmt.Errorf("threads must be between 1 and 100")
	}
	if c.Rate < 1 || c.Rate > 1000 {
		return fmt.Errorf("rate must be between 1 and 1000 requests/second")
	}
	if c.TimeoutString == "" {
		c.TimeoutString = "12s"
	}
	if c.WaitString == "" {
		c.WaitString = "20s"
	}
	var err error
	c.Timeout, err = time.ParseDuration(c.TimeoutString)
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}
	c.Wait, err = time.ParseDuration(c.WaitString)
	if err != nil {
		return fmt.Errorf("invalid wait duration: %w", err)
	}
	if strings.TrimSpace(c.APIBaseURL) == "" {
		c.APIBaseURL = "https://pingback.sh/api/v1"
	}
	c.APIBaseURL = strings.TrimRight(strings.TrimSpace(c.APIBaseURL), "/")
	c.APIToken = strings.TrimSpace(c.APIToken)
	if c.OutputDir == "" {
		c.OutputDir = "output"
	}
	if c.UserAgent == "" {
		c.UserAgent = Default().UserAgent
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = 1 << 20
	}
	if c.FeedHeaders == nil {
		c.FeedHeaders = map[string]string{}
	}
	for i := range c.HeaderNames {
		c.HeaderNames[i] = strings.TrimSpace(c.HeaderNames[i])
	}
	return nil
}

func Save(path string, cfg Config) error {
	if path == "" {
		path = DefaultPath()
	}
	cfg.TimeoutString = cfg.Timeout.String()
	cfg.WaitString = cfg.Wait.String()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
