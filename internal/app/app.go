package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pingback-sh/pbscan/internal/callback"
	"github.com/pingback-sh/pbscan/internal/config"
	inputpkg "github.com/pingback-sh/pbscan/internal/input"
	"github.com/pingback-sh/pbscan/internal/model"
	"github.com/pingback-sh/pbscan/internal/mutate"
	"github.com/pingback-sh/pbscan/internal/pingback"
	"github.com/pingback-sh/pbscan/internal/report"
	"github.com/pingback-sh/pbscan/internal/scanner"
	"github.com/pingback-sh/pbscan/internal/session"
	"github.com/pingback-sh/pbscan/internal/target"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

func Run(args []string, streams IO) int {
	if streams.In == nil {
		streams.In = os.Stdin
	}
	if streams.Out == nil {
		streams.Out = os.Stdout
	}
	if streams.Err == nil {
		streams.Err = os.Stderr
	}
	if len(args) == 0 {
		if stdinHasData() {
			args = []string{"scan", "--stdin"}
		} else {
			printRootHelp(streams.Out)
			return 0
		}
	}

	known := map[string]bool{"scan": true, "watch": true, "auth": true, "logout": true, "init": true, "doctor": true, "version": true, "help": true, "--version": true, "-version": true, "--help": true, "-h": true}
	command := args[0]
	commandArgs := args[1:]
	if strings.HasPrefix(command, "-") || !known[command] {
		command = "scan"
		commandArgs = args
	}

	var err error
	switch command {
	case "scan":
		err = runScan(commandArgs, streams)
	case "watch":
		err = runWatch(commandArgs, streams)
	case "auth":
		err = runAuth(commandArgs, streams)
	case "logout":
		err = runLogout(commandArgs, streams)
	case "init":
		err = runInit(commandArgs, streams)
	case "doctor":
		err = runDoctor(commandArgs, streams)
	case "version", "--version", "-version":
		fmt.Fprintf(streams.Out, "pbscan %s commit=%s built=%s go=%s\n", Version, Commit, Date, runtime.Version())
		return 0
	case "help", "--help", "-h":
		printRootHelp(streams.Out)
		return 0
	}
	if err != nil {
		fmt.Fprintf(streams.Err, "error: %v\n", err)
		return 1
	}
	return 0
}

type stringList []string

func (s *stringList) String() string         { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error { *s = append(*s, value); return nil }

type feedHeaderList map[string]string

func (h *feedHeaderList) String() string { return "" }
func (h *feedHeaderList) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return fmt.Errorf("feed header must be 'Name: value'")
	}
	if *h == nil {
		*h = map[string]string{}
	}
	(*h)[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	return nil
}

type console struct {
	out    io.Writer
	silent bool
	json   bool
	mu     sync.Mutex
}

func (c *console) event(kind string, fields map[string]any) {
	if c.silent {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.json {
		fields["type"] = kind
		data, _ := json.Marshal(fields)
		fmt.Fprintln(c.out, string(data))
		return
	}
	switch kind {
	case "listener":
		fmt.Fprintf(c.out, "[+] listener=%v id=%v label=%v\n", fields["host"], fields["listener_id"], fields["label"])
	case "register":
		fmt.Fprintf(c.out, "[+] correlated injections %v/%v\n", fields["done"], fields["total"])
	case "start":
		fmt.Fprintf(c.out, "[+] scan=%v targets=%v attempts=%v output=%v\n", fields["scan_id"], fields["targets"], fields["attempts"], fields["output"])
	case "sent":
		if fields["error"] != "" {
			fmt.Fprintf(c.out, "[-] %v error=%v\n", fields["attempt_id"], fields["error"])
		} else {
			fmt.Fprintf(c.out, "[>] %v status=%v vector=%v point=%v\n", fields["attempt_id"], fields["status"], fields["vector"], fields["point"])
		}
	case "finding":
		fmt.Fprintf(c.out, "[CONFIRMED] %v cid=%v vector=%v point=%v target=%v\n", fields["attempt_id"], fields["correlation_id"], fields["vector"], fields["point"], fields["target"])
	case "done":
		fmt.Fprintf(c.out, "[+] complete sent=%v errors=%v callbacks=%v session=%v\n", fields["sent"], fields["errors"], fields["callbacks"], fields["session"])
	default:
		fmt.Fprintf(c.out, "[%s] %v\n", strings.ToUpper(kind), fields)
	}
}

func runAuth(args []string, streams IO) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	var token, apiBase string
	var tokenStdin, accept bool
	fs.StringVar(&token, "token", "", "revocable PingBack Pro API token")
	fs.StringVar(&apiBase, "api-base", cfg.APIBaseURL, "PingBack API base URL")
	fs.BoolVar(&tokenStdin, "token-stdin", false, "read the API token from stdin")
	fs.BoolVar(&accept, "accept-authorized-use", false, "accept that pbscan may only be used on authorized targets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if token == "" && len(fs.Args()) > 0 {
		token = fs.Args()[0]
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("PINGBACK_API_TOKEN"))
	}
	if token == "" && tokenStdin {
		line, readErr := bufio.NewReader(streams.In).ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		token = strings.TrimSpace(line)
	}
	if token == "" {
		token = cfg.APIToken
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("API token required; create a revocable token in PingBack 'My listeners' and pass --token")
	}
	if !accept && !cfg.AuthorizedUse {
		return errors.New("pass --accept-authorized-use once to confirm that scans will only target systems you are authorized to test")
	}
	client := pingback.Client{BaseURL: apiBase, Token: token, UserAgent: cfg.UserAgent, HTTP: &http.Client{Timeout: 20 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := client.Validate(ctx); err != nil {
		return fmt.Errorf("validate PingBack API token: %w", err)
	}
	cfg.APIBaseURL = strings.TrimRight(apiBase, "/")
	cfg.APIToken = strings.TrimSpace(token)
	cfg.AuthorizedUse = true
	if err := config.Save(configPath(), cfg); err != nil {
		return err
	}
	fmt.Fprintf(streams.Out, "PingBack API connected. Configuration saved securely to %s.\n", configPath())
	fmt.Fprintln(streams.Out, "Next scan: pbscan urls.txt")
	return nil
}

func runLogout(args []string, streams IO) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.APIToken = ""
	if err := config.Save(configPath(), cfg); err != nil {
		return err
	}
	fmt.Fprintln(streams.Out, "PingBack API token removed from local configuration.")
	return nil
}

func runScan(args []string, streams IO) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	var urls stringList
	var listPath, requestPath, baseURL string
	var apiBase, apiToken, listenerLabel string
	var listener, callbackTemplate, feedURL, outputRoot string
	var feedHeaders feedHeaderList = cloneStringMap(cfg.FeedHeaders)
	var headerNames stringList
	var useStdin, fuzzHeaders, noQuery, noBody, authorized, silent, jsonOutput, failOnFindings, dryRun, legacy bool
	var includeRequestSecrets bool
	var threads, rate, retries, maxAttempts int
	var timeout, wait time.Duration
	var followRedirects, insecureTLS, allowPrivate bool

	fs.Var(&urls, "u", "target URL (repeatable)")
	fs.Var(&urls, "url", "target URL (repeatable)")
	fs.StringVar(&listPath, "l", "", "file containing target URLs")
	fs.StringVar(&listPath, "list", "", "file containing target URLs")
	fs.BoolVar(&useStdin, "stdin", false, "read target URLs from stdin")
	fs.StringVar(&requestPath, "request", "", "raw HTTP request file")
	fs.StringVar(&baseURL, "base-url", "", "scheme/host for a raw request without an absolute URL")
	fs.StringVar(&apiBase, "api-base", cfg.APIBaseURL, "PingBack API base URL")
	fs.StringVar(&apiToken, "api-token", "", "override the saved PingBack API token")
	fs.StringVar(&listenerLabel, "label", "", "label for the automatically created PingBack listener")
	fs.BoolVar(&includeRequestSecrets, "include-request-secrets", cfg.IncludeRequestSecrets, "include Authorization/Cookie values in correlated request evidence")
	fs.BoolVar(&legacy, "legacy", false, "use a manually supplied listener/feed instead of PingBack API v1")
	fs.StringVar(&listener, "listener", "", "legacy listener host or URL")
	fs.StringVar(&callbackTemplate, "callback-template", cfg.CallbackTemplate, "legacy callback URL template containing {token}")
	fs.StringVar(&feedURL, "feed-url", cfg.FeedURL, "legacy JSON feed URL")
	fs.Var(&feedHeaders, "feed-header", "legacy feed header, e.g. 'Authorization: Bearer ...' (repeatable)")
	fs.BoolVar(&fuzzHeaders, "headers", false, "test the conservative routing/header list")
	fs.Var(&headerNames, "header", "additional header name to test (repeatable)")
	fs.BoolVar(&noQuery, "no-query", false, "do not mutate query parameters")
	fs.BoolVar(&noBody, "no-body", false, "do not mutate JSON/form string fields")
	fs.IntVar(&threads, "threads", cfg.Threads, "concurrent target workers (1-100)")
	fs.IntVar(&rate, "rate", cfg.Rate, "global maximum target requests per second")
	fs.IntVar(&retries, "retries", cfg.Retries, "network retries per target request")
	fs.DurationVar(&timeout, "timeout", cfg.Timeout, "per-request timeout")
	fs.DurationVar(&wait, "wait", cfg.Wait, "time to continue polling after dispatch")
	fs.StringVar(&outputRoot, "output", cfg.OutputDir, "output root directory")
	fs.BoolVar(&followRedirects, "follow-redirects", cfg.FollowRedirects, "follow target redirects")
	fs.BoolVar(&insecureTLS, "insecure", cfg.InsecureTLS, "skip target TLS certificate verification")
	fs.BoolVar(&allowPrivate, "allow-private-targets", cfg.AllowPrivateTarget, "allow loopback/private target addresses")
	fs.BoolVar(&authorized, "authorized", cfg.AuthorizedUse || envTrue("PBSCAN_AUTHORIZED"), "confirm authorization for all targets")
	fs.BoolVar(&silent, "silent", false, "suppress progress output")
	fs.BoolVar(&jsonOutput, "json", false, "emit progress as JSON lines")
	fs.BoolVar(&failOnFindings, "fail-on-findings", false, "exit non-zero when callbacks are confirmed")
	fs.BoolVar(&dryRun, "dry-run", false, "generate local attempts without API calls or target requests")
	fs.IntVar(&maxAttempts, "max-attempts", 500, "refuse scans above this attempt count; 0 disables the limit")
	args = reorderInterspersedArgs(fs, args)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !authorized {
		return errors.New("authorization confirmation required; run 'pbscan auth --token ... --accept-authorized-use' once or pass --authorized")
	}
	if threads < 1 || threads > 100 {
		return fmt.Errorf("threads must be between 1 and 100")
	}
	if rate < 1 || rate > 1000 {
		return fmt.Errorf("rate must be between 1 and 1000")
	}
	if retries < 0 || retries > 5 {
		return fmt.Errorf("retries must be between 0 and 5")
	}
	if maxAttempts < 0 {
		return fmt.Errorf("max-attempts cannot be negative")
	}
	if timeout <= 0 || wait < 0 {
		return fmt.Errorf("timeout must be positive and wait cannot be negative")
	}

	sources, err := collectSources(fs.Args(), urls, listPath, requestPath, baseURL, useStdin, streams.In)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		return errors.New("no targets supplied; use 'pbscan urls.txt', -u, -l, --request, or stdin")
	}
	for _, src := range sources {
		if err := target.Validate(src.URL, allowPrivate); err != nil {
			return fmt.Errorf("%s: %w", src.Name, err)
		}
	}

	scanID, err := callback.NewScanID()
	if err != nil {
		return err
	}
	placeholder, _ := callback.NewTemplate("https://pbscan.invalid/callback/{token}")
	allHeaders := append([]string(nil), cfg.HeaderNames...)
	allHeaders = append(allHeaders, headerNames...)
	builder := mutate.NewBuilder(scanID, placeholder)
	attempts, err := builder.Build(sources, mutate.Options{Query: !noQuery, Body: !noBody, Headers: fuzzHeaders, HeaderNames: dedupeStrings(allHeaders)})
	if err != nil {
		return err
	}
	if len(attempts) == 0 {
		return errors.New("no injectable query parameters, JSON/form string fields, or enabled headers were found")
	}
	if maxAttempts > 0 && len(attempts) > maxAttempts {
		return fmt.Errorf("scan would create %d correlated API records, above --max-attempts=%d; split the input or raise the limit deliberately", len(attempts), maxAttempts)
	}

	con := &console{out: streams.Out, silent: silent, json: jsonOutput}
	mode := "api"
	var apiClient *pingback.Client
	var createdListener pingback.Listener
	var legacyTemplateString string
	legacyExplicit := legacy || listener != "" || flagWasSet(fs, "callback-template") || flagWasSet(fs, "feed-url")
	if apiToken == "" {
		apiToken = strings.TrimSpace(os.Getenv("PINGBACK_API_TOKEN"))
	}
	if apiToken == "" {
		apiToken = cfg.APIToken
	}
	if legacyExplicit {
		mode = "legacy"
		var template callback.Template
		if listener != "" && !flagWasSet(fs, "callback-template") {
			template, err = callback.FromListener(listener)
		} else if callbackTemplate != "" {
			template, err = callback.NewTemplate(callbackTemplate)
		} else {
			return errors.New("legacy mode requires --listener or --callback-template")
		}
		if err != nil {
			return err
		}
		legacyTemplateString = template.String()
		legacyBuilder := mutate.NewBuilder(scanID, template)
		attempts, err = legacyBuilder.Build(sources, mutate.Options{Query: !noQuery, Body: !noBody, Headers: fuzzHeaders, HeaderNames: dedupeStrings(allHeaders)})
		if err != nil {
			return err
		}
	} else if strings.TrimSpace(apiToken) == "" {
		return errors.New("PingBack API is not configured; run 'pbscan auth --token pba_... --accept-authorized-use' once")
	}

	scanDir := filepath.Join(outputRoot, scanID)
	if dryRun {
		reporter, err := report.New(scanDir)
		if err != nil {
			return err
		}
		defer reporter.Close()
		if err := reporter.WriteAttempts(attempts); err != nil {
			return err
		}
		now := time.Now().UTC()
		sess := model.Session{Version: 2, Mode: mode, ScanID: scanID, CreatedAt: now, UpdatedAt: now, Attempts: attempts, Results: map[string]model.DispatchResult{}, Findings: map[string]model.Finding{}}
		store := session.New(filepath.Join(scanDir, "session.json"), sess)
		if err := store.Save(); err != nil {
			return err
		}
		_ = reporter.WriteSummary(sess)
		con.event("start", map[string]any{"scan_id": scanID, "targets": len(sources), "attempts": len(attempts), "output": scanDir})
		con.event("done", map[string]any{"sent": 0, "errors": 0, "callbacks": 0, "session": store.Path()})
		return nil
	}

	ctx, cancel := signalContext()
	defer cancel()
	if mode == "api" {
		apiClient = &pingback.Client{BaseURL: apiBase, Token: apiToken, UserAgent: cfg.UserAgent, HTTP: &http.Client{Timeout: timeout + 8*time.Second}}
		if listenerLabel == "" {
			listenerLabel = automaticListenerLabel(scanID, sources)
		}
		createdListener, err = apiClient.CreateListener(ctx, listenerLabel)
		if err != nil {
			return fmt.Errorf("create PingBack listener: %w", err)
		}
		con.event("listener", map[string]any{"listener_id": createdListener.ID, "host": emptyFallback(createdListener.Host, "created"), "label": listenerLabel})
		attempts, err = registerCorrelatedAttempts(ctx, apiClient, createdListener.ID, attempts, includeRequestSecrets, con)
		if err != nil {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = apiClient.DeleteListener(cleanupCtx, createdListener.ID)
			cleanupCancel()
			return err
		}
	}

	reporter, err := report.New(scanDir)
	if err != nil {
		return err
	}
	defer reporter.Close()
	if err := reporter.WriteAttempts(attempts); err != nil {
		return err
	}
	now := time.Now().UTC()
	sess := model.Session{Version: 2, Mode: mode, ScanID: scanID, CreatedAt: now, UpdatedAt: now, FeedURL: feedURL, Attempts: attempts, Results: map[string]model.DispatchResult{}, Findings: map[string]model.Finding{}}
	if mode == "api" {
		sess.APIBaseURL = strings.TrimRight(apiBase, "/")
		sess.ListenerID = createdListener.ID
		sess.ListenerHost = createdListener.Host
	} else if len(attempts) > 0 {
		sess.CallbackTemplate = legacyTemplateString
	}
	store := session.New(filepath.Join(scanDir, "session.json"), sess)
	if err := store.Save(); err != nil {
		return err
	}
	con.event("start", map[string]any{"scan_id": scanID, "targets": len(sources), "attempts": len(attempts), "output": scanDir})

	attemptByID := make(map[string]model.Attempt, len(attempts))
	for _, attempt := range attempts {
		attemptByID[attempt.ID] = attempt
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	watchDone := make(chan error, 1)
	watching := false
	if mode == "api" {
		watching = true
		watcher := pingback.HitsWatcher{Client: apiClient, ListenerID: createdListener.ID, Interval: 2 * time.Second, Limit: 250}
		go func() {
			watchDone <- watcher.Watch(watchCtx, attempts, nil, findingHandler(store, reporter, con, streams.Err), func(id int64) { _ = store.SetLastHitID(id) })
		}()
	} else if feedURL != "" {
		watching = true
		watcher := callback.FeedWatcher{URL: feedURL, Headers: feedHeaders, Interval: 2 * time.Second, Timeout: timeout}
		go func() {
			watchDone <- watcher.Watch(watchCtx, attempts, nil, findingHandler(store, reporter, con, streams.Err))
		}()
	}

	s := scanner.New(scanner.Options{Threads: threads, Rate: rate, Timeout: timeout, Retries: retries, FollowRedirects: followRedirects, InsecureTLS: insecureTLS, UserAgent: cfg.UserAgent, MaxResponseBytes: cfg.MaxResponseBytes})
	dispatchErr := s.Dispatch(ctx, attempts, func(result model.DispatchResult) {
		_ = store.AddResult(result)
		_ = reporter.WriteResult(result)
		attempt := attemptByID[result.AttemptID]
		con.event("sent", map[string]any{"attempt_id": result.AttemptID, "status": result.StatusCode, "error": result.Error, "vector": attempt.Vector, "point": attempt.InjectionPoint})
	})
	if watching && dispatchErr == nil && wait > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	stopWatch()
	if watching {
		if watchErr := <-watchDone; watchErr != nil && dispatchErr == nil {
			dispatchErr = watchErr
		}
	}
	if saveErr := store.Save(); saveErr != nil && dispatchErr == nil {
		dispatchErr = saveErr
	}
	final := store.Snapshot()
	if err := reporter.WriteSummary(final); err != nil && dispatchErr == nil {
		dispatchErr = err
	}
	con.event("done", map[string]any{"sent": len(final.Results), "errors": countErrors(final), "callbacks": len(final.Findings), "session": store.Path()})
	if dispatchErr != nil {
		return dispatchErr
	}
	if failOnFindings && len(final.Findings) > 0 {
		return fmt.Errorf("%d confirmed callback(s)", len(final.Findings))
	}
	return nil
}

func registerCorrelatedAttempts(ctx context.Context, client *pingback.Client, listenerID int64, attempts []model.Attempt, includeSecrets bool, con *console) ([]model.Attempt, error) {
	out := make([]model.Attempt, len(attempts))
	for index, attempt := range attempts {
		request := pingback.InjectionRequest{
			ListenerID:         listenerID,
			Label:              fmt.Sprintf("pbscan · %s · %s", attempt.Vector, attempt.InjectionPoint),
			VulnerabilityType:  "SSRF",
			TargetURL:          emptyFallback(attempt.OriginalTargetURL, attempt.TargetURL),
			InjectionPoint:     attempt.Vector + ": " + attempt.InjectionPoint,
			RequestMethod:      attempt.Method,
			ResponsibleRequest: attempt.ResponsibleRequest("{{PINGBACK_HTTP_PAYLOAD}}", includeSecrets),
			Notes:              fmt.Sprintf("Automated by pbscan scan %s; local attempt %s; source %s", attempt.ScanID, attempt.ID, attempt.SourceName),
		}
		injection, err := client.CreateInjection(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("register correlated injection %d/%d (%s %s): %w", index+1, len(attempts), attempt.Vector, attempt.InjectionPoint, err)
		}
		updated := model.ReplaceCallback(attempt, injection.Payloads["http"])
		updated.CorrelationID = injection.CorrelationID
		updated.Payloads = injection.Payloads
		out[index] = updated
		if index == 0 || (index+1)%25 == 0 || index+1 == len(attempts) {
			con.event("register", map[string]any{"done": index + 1, "total": len(attempts)})
		}
	}
	return out, nil
}

func runWatch(args []string, streams IO) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	var sessionPath, feedURL, apiToken string
	var duration, interval time.Duration
	var headers feedHeaderList = cloneStringMap(cfg.FeedHeaders)
	var silent, jsonOutput bool
	fs.StringVar(&sessionPath, "session", "", "path to session.json")
	fs.StringVar(&apiToken, "api-token", "", "override saved PingBack API token")
	fs.StringVar(&feedURL, "feed-url", "", "override legacy JSON feed URL")
	fs.Var(&headers, "feed-header", "legacy feed header (repeatable)")
	fs.DurationVar(&duration, "duration", 10*time.Minute, "how long to watch")
	fs.DurationVar(&interval, "interval", 2*time.Second, "polling interval")
	fs.BoolVar(&silent, "silent", false, "suppress output")
	fs.BoolVar(&jsonOutput, "json", false, "emit JSON lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if sessionPath == "" && len(fs.Args()) > 0 {
		sessionPath = fs.Args()[0]
	}
	if sessionPath == "" {
		return errors.New("session path is required")
	}
	store, err := session.Load(sessionPath)
	if err != nil {
		return err
	}
	snapshot := store.Snapshot()
	reporter, err := report.New(filepath.Dir(sessionPath))
	if err != nil {
		return err
	}
	defer reporter.Close()
	con := &console{out: streams.Out, silent: silent, json: jsonOutput}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	handler := findingHandler(store, reporter, con, streams.Err)
	if snapshot.Mode == "api" || snapshot.ListenerID > 0 {
		if apiToken == "" {
			apiToken = strings.TrimSpace(os.Getenv("PINGBACK_API_TOKEN"))
		}
		if apiToken == "" {
			apiToken = cfg.APIToken
		}
		if apiToken == "" {
			return errors.New("saved PingBack API token is missing; run pbscan auth again")
		}
		base := snapshot.APIBaseURL
		if base == "" {
			base = cfg.APIBaseURL
		}
		client := &pingback.Client{BaseURL: base, Token: apiToken, UserAgent: cfg.UserAgent, HTTP: &http.Client{Timeout: cfg.Timeout + 8*time.Second}}
		watcher := pingback.HitsWatcher{Client: client, ListenerID: snapshot.ListenerID, Interval: interval, Limit: 250, SinceID: snapshot.LastHitID}
		err = watcher.Watch(ctx, snapshot.Attempts, snapshot.Findings, handler, func(id int64) { _ = store.SetLastHitID(id) })
	} else {
		if feedURL == "" {
			feedURL = snapshot.FeedURL
		}
		if feedURL == "" {
			return errors.New("legacy session has no feed URL")
		}
		watcher := callback.FeedWatcher{URL: feedURL, Headers: headers, Interval: interval, Timeout: cfg.Timeout}
		err = watcher.Watch(ctx, snapshot.Attempts, snapshot.Findings, handler)
	}
	final := store.Snapshot()
	_ = store.Save()
	_ = reporter.WriteSummary(final)
	con.event("done", map[string]any{"sent": len(final.Results), "errors": countErrors(final), "callbacks": len(final.Findings), "session": sessionPath})
	return err
}

func findingHandler(store *session.Store, reporter *report.Reporter, con *console, errOut io.Writer) func(model.Finding) {
	return func(finding model.Finding) {
		added, addErr := store.AddFinding(finding)
		if addErr != nil {
			fmt.Fprintf(errOut, "warning: save finding: %v\n", addErr)
			return
		}
		if !added {
			return
		}
		_ = reporter.WriteFinding(finding)
		con.event("finding", map[string]any{"attempt_id": finding.Attempt.ID, "correlation_id": finding.Attempt.CorrelationID, "vector": finding.Attempt.Vector, "point": finding.Attempt.InjectionPoint, "target": finding.Attempt.OriginalTargetURL})
	}
}

func runInit(args []string, streams IO) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	path := config.DefaultPath()
	var force bool
	fs.StringVar(&path, "path", path, "configuration path")
	fs.BoolVar(&force, "force", false, "overwrite an existing file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists; use --force to overwrite", path)
		}
	}
	if err := config.Save(path, config.Default()); err != nil {
		return err
	}
	fmt.Fprintf(streams.Out, "created %s\n", path)
	return nil
}

func runDoctor(args []string, streams IO) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	var listener, templateValue, feedURL, apiToken string
	fs.StringVar(&apiToken, "api-token", "", "override saved PingBack API token")
	fs.StringVar(&listener, "listener", "", "legacy listener host or URL")
	fs.StringVar(&templateValue, "callback-template", "", "legacy callback URL template")
	fs.StringVar(&feedURL, "feed-url", "", "legacy JSON feed URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if apiToken == "" {
		apiToken = strings.TrimSpace(os.Getenv("PINGBACK_API_TOKEN"))
	}
	if apiToken == "" {
		apiToken = cfg.APIToken
	}
	if apiToken != "" {
		client := pingback.Client{BaseURL: cfg.APIBaseURL, Token: apiToken, UserAgent: cfg.UserAgent, HTTP: &http.Client{Timeout: 20 * time.Second}}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := client.Validate(ctx); err != nil {
			return err
		}
		fmt.Fprintf(streams.Out, "PingBack API: connected (%s)\n", cfg.APIBaseURL)
		fmt.Fprintf(streams.Out, "authorized-use acceptance: %v\n", cfg.AuthorizedUse)
		fmt.Fprintf(streams.Out, "config: %s\n", configPath())
		return nil
	}
	if listener == "" && templateValue == "" && feedURL == "" {
		return errors.New("PingBack API token is not configured; run pbscan auth --token pba_... --accept-authorized-use")
	}
	var tpl callback.Template
	if listener != "" {
		tpl, err = callback.FromListener(listener)
	} else {
		tpl, err = callback.NewTemplate(templateValue)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(streams.Out, "legacy callback template: OK (%s)\n", tpl.String())
	if feedURL != "" {
		req, err := http.NewRequest(http.MethodGet, feedURL, nil)
		if err != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
			return errors.New("legacy feed URL must use HTTP(S)")
		}
		fmt.Fprintln(streams.Out, "legacy feed URL: OK")
	}
	return nil
}

type boolFlag interface {
	IsBoolFlag() bool
}

func reorderInterspersedArgs(fs *flag.FlagSet, args []string) []string {
	var options, positionals []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		options = append(options, arg)
		nameValue := strings.TrimLeft(arg, "-")
		name := nameValue
		if equals := strings.IndexByte(nameValue, '='); equals >= 0 {
			name = nameValue[:equals]
			continue
		}
		definition := fs.Lookup(name)
		if definition == nil {
			continue
		}
		if value, ok := definition.Value.(boolFlag); ok && value.IsBoolFlag() {
			continue
		}
		if index+1 < len(args) {
			index++
			options = append(options, args[index])
		}
	}
	return append(options, positionals...)
}

func collectSources(positionals []string, urls stringList, listPath, requestPath, baseURL string, useStdin bool, in io.Reader) ([]model.Source, error) {
	var sources []model.Source
	for _, raw := range urls {
		src, err := inputpkg.URLSource(raw)
		if err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	if listPath != "" {
		items, err := inputpkg.URLsFromFile(listPath)
		if err != nil {
			return nil, err
		}
		sources = append(sources, items...)
	}
	if requestPath != "" {
		src, err := inputpkg.RawRequestFile(requestPath, baseURL)
		if err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	for _, value := range positionals {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			src, err := inputpkg.URLSource(value)
			if err != nil {
				return nil, err
			}
			sources = append(sources, src)
			continue
		}
		info, err := os.Stat(value)
		if err != nil || info.IsDir() {
			return nil, fmt.Errorf("positional input %q is neither an absolute URL nor a readable URL-list file", value)
		}
		items, err := inputpkg.URLsFromFile(value)
		if err != nil {
			return nil, err
		}
		sources = append(sources, items...)
	}
	if useStdin || (len(sources) == 0 && stdinHasData()) {
		items, err := inputpkg.URLsFromReader(in, "stdin")
		if err != nil {
			return nil, err
		}
		sources = append(sources, items...)
	}
	return sources, nil
}

func automaticListenerLabel(scanID string, sources []model.Source) string {
	host := "targets"
	if len(sources) > 0 {
		if parsed, err := url.Parse(sources[0].URL); err == nil && parsed.Hostname() != "" {
			host = parsed.Hostname()
		}
	}
	return fmt.Sprintf("pbscan · %s · %s · %s", host, scanID, time.Now().UTC().Format("2006-01-02 15:04 UTC"))
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func loadConfig() (config.Config, error) { return config.Load(configPath()) }
func configPath() string {
	if value := strings.TrimSpace(os.Getenv("PBSCAN_CONFIG")); value != "" {
		return value
	}
	return config.DefaultPath()
}
func envTrue(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true" || value == "yes"
}
func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}
func countErrors(s model.Session) int {
	n := 0
	for _, result := range s.Results {
		if result.Error != "" {
			n++
		}
	}
	return n
}
func stdinHasData() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func printRootHelp(w io.Writer) {
	fmt.Fprintln(w, `pbscan - automatic correlated SSRF/OAST scanner for authorized testing

One-time setup:
  pbscan auth --token pba_your_revocable_token --accept-authorized-use

Scan:
  pbscan urls.txt
  pbscan -l urls.txt
  cat urls.txt | pbscan
  pbscan 'https://target.example/fetch?url=test'

pbscan automatically creates a PingBack listener, registers every injection,
uses the official per-injection payload, polls evidence, and correlates hits.

Other commands:
  pbscan watch output/<scan>/session.json
  pbscan doctor
  pbscan logout
  pbscan version

Run 'pbscan scan -h' for advanced options.`)
}
