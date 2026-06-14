package mutate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pingback-sh/pbscan/internal/callback"
	"github.com/pingback-sh/pbscan/internal/model"
)

type Options struct {
	Query       bool
	Body        bool
	Headers     bool
	HeaderNames []string
}

type Builder struct {
	ScanID   string
	Template callback.Template
	next     int
}

func NewBuilder(scanID string, template callback.Template) *Builder {
	return &Builder{ScanID: scanID, Template: template}
}

func (b *Builder) Build(sources []model.Source, opts Options) ([]model.Attempt, error) {
	var attempts []model.Attempt
	for _, src := range sources {
		if opts.Query {
			items, err := b.queryAttempts(src)
			if err != nil {
				return nil, err
			}
			attempts = append(attempts, items...)
		}
		if opts.Body && len(src.Body) > 0 {
			items, err := b.bodyAttempts(src)
			if err != nil {
				return nil, err
			}
			attempts = append(attempts, items...)
		}
		if opts.Headers {
			items, err := b.headerAttempts(src, opts.HeaderNames)
			if err != nil {
				return nil, err
			}
			attempts = append(attempts, items...)
		}
	}
	return attempts, nil
}

func (b *Builder) newAttempt(src model.Source, vector, point, original, targetURL string, headers map[string]string, body []byte) (model.Attempt, error) {
	b.next++
	id, err := callback.NewAttemptID(b.ScanID, b.next)
	if err != nil {
		return model.Attempt{}, err
	}
	return model.Attempt{
		ID:                id,
		ScanID:            b.ScanID,
		SourceName:        src.Name,
		Method:            src.Method,
		OriginalTargetURL: src.URL,
		TargetURL:         targetURL,
		Vector:            vector,
		InjectionPoint:    point,
		OriginalValue:     original,
		CallbackURL:       b.Template.URL(id),
		Headers:           cloneMap(headers),
		Body:              append([]byte(nil), body...),
		CreatedAt:         time.Now().UTC(),
	}, nil
}

func (b *Builder) queryAttempts(src model.Source) ([]model.Attempt, error) {
	u, err := url.Parse(src.URL)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	var out []model.Attempt
	for key, values := range query {
		for index, original := range values {
			placeholder := "__PBSCAN_CALLBACK__"
			copyURL := *u
			copyQuery := cloneValues(query)
			copyQuery[key][index] = placeholder
			copyURL.RawQuery = copyQuery.Encode()
			attempt, err := b.newAttempt(src, "query", queryPoint(key, index, len(values)), original, copyURL.String(), src.Headers, src.Body)
			if err != nil {
				return nil, err
			}
			attempt.TargetURL = strings.Replace(attempt.TargetURL, url.QueryEscape(placeholder), url.QueryEscape(attempt.CallbackURL), 1)
			out = append(out, attempt)
		}
	}
	return out, nil
}

func (b *Builder) bodyAttempts(src model.Source) ([]model.Attempt, error) {
	contentType := strings.ToLower(src.ContentType)
	if strings.Contains(contentType, "application/json") || looksLikeJSON(src.Body) {
		return b.jsonAttempts(src)
	}
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return b.formAttempts(src)
	}
	return nil, nil
}

func (b *Builder) formAttempts(src model.Source) ([]model.Attempt, error) {
	values, err := url.ParseQuery(string(src.Body))
	if err != nil {
		return nil, fmt.Errorf("parse form body in %s: %w", src.Name, err)
	}
	var out []model.Attempt
	for key, list := range values {
		for index, original := range list {
			placeholder := "__PBSCAN_CALLBACK__"
			copyValues := cloneValues(values)
			copyValues[key][index] = placeholder
			attempt, err := b.newAttempt(src, "form", formPoint(key, index, len(list)), original, src.URL, src.Headers, []byte(copyValues.Encode()))
			if err != nil {
				return nil, err
			}
			attempt.Body = []byte(strings.Replace(string(attempt.Body), url.QueryEscape(placeholder), url.QueryEscape(attempt.CallbackURL), 1))
			out = append(out, attempt)
		}
	}
	return out, nil
}

type jsonPath []any

type jsonLeaf struct {
	Path     jsonPath
	Original string
}

func (b *Builder) jsonAttempts(src model.Source) ([]model.Attempt, error) {
	var root any
	if err := json.Unmarshal(src.Body, &root); err != nil {
		return nil, fmt.Errorf("parse JSON body in %s: %w", src.Name, err)
	}
	var leaves []jsonLeaf
	collectJSONStrings(root, nil, &leaves)
	var out []model.Attempt
	for _, leaf := range leaves {
		copyRoot, err := deepCopyJSON(root)
		if err != nil {
			return nil, err
		}
		placeholder := "__PBSCAN_CALLBACK__"
		if err := setJSONPath(copyRoot, leaf.Path, placeholder); err != nil {
			return nil, err
		}
		body, err := json.Marshal(copyRoot)
		if err != nil {
			return nil, err
		}
		attempt, err := b.newAttempt(src, "json", jsonPointer(leaf.Path), leaf.Original, src.URL, src.Headers, body)
		if err != nil {
			return nil, err
		}
		quotedPlaceholder, _ := json.Marshal(placeholder)
		quotedCallback, _ := json.Marshal(attempt.CallbackURL)
		attempt.Body = []byte(strings.Replace(string(attempt.Body), string(quotedPlaceholder), string(quotedCallback), 1))
		out = append(out, attempt)
	}
	return out, nil
}

func (b *Builder) headerAttempts(src model.Source, names []string) ([]model.Attempt, error) {
	var out []model.Attempt
	for _, name := range names {
		name = http.CanonicalHeaderKey(strings.TrimSpace(name))
		if name == "" || strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Length") {
			continue
		}
		original := src.Headers[name]
		attempt, err := b.newAttempt(src, "header", name, original, src.URL, src.Headers, src.Body)
		if err != nil {
			return nil, err
		}
		attempt.Headers[name] = attempt.CallbackURL
		out = append(out, attempt)
	}
	return out, nil
}

func collectJSONStrings(value any, path jsonPath, out *[]jsonLeaf) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			collectJSONStrings(child, appendPath(path, key), out)
		}
	case []any:
		for i, child := range v {
			collectJSONStrings(child, appendPath(path, i), out)
		}
	case string:
		*out = append(*out, jsonLeaf{Path: append(jsonPath(nil), path...), Original: v})
	}
}

func setJSONPath(root any, path jsonPath, value string) error {
	if len(path) == 0 {
		return fmt.Errorf("cannot replace root JSON value")
	}
	current := root
	for i, part := range path {
		last := i == len(path)-1
		switch key := part.(type) {
		case string:
			obj, ok := current.(map[string]any)
			if !ok {
				return fmt.Errorf("invalid JSON object path")
			}
			if last {
				obj[key] = value
				return nil
			}
			current = obj[key]
		case int:
			arr, ok := current.([]any)
			if !ok || key < 0 || key >= len(arr) {
				return fmt.Errorf("invalid JSON array path")
			}
			if last {
				arr[key] = value
				return nil
			}
			current = arr[key]
		default:
			return fmt.Errorf("invalid JSON path component")
		}
	}
	return nil
}

func deepCopyJSON(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func jsonPointer(path jsonPath) string {
	parts := make([]string, 0, len(path))
	for _, item := range path {
		switch value := item.(type) {
		case string:
			value = strings.ReplaceAll(value, "~", "~0")
			value = strings.ReplaceAll(value, "/", "~1")
			parts = append(parts, value)
		case int:
			parts = append(parts, strconv.Itoa(value))
		}
	}
	return "/" + strings.Join(parts, "/")
}

func appendPath(path jsonPath, item any) jsonPath {
	out := append(jsonPath(nil), path...)
	return append(out, item)
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func looksLikeJSON(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func queryPoint(key string, index, count int) string {
	if count == 1 {
		return key
	}
	return fmt.Sprintf("%s[%d]", key, index)
}

func formPoint(key string, index, count int) string {
	if count == 1 {
		return key
	}
	return fmt.Sprintf("%s[%d]", key, index)
}
