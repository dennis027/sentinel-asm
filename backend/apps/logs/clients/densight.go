// Package densight sends a Go application's logs to Densight: a log/slog
// handler, plus HTTP middleware that logs each request and recovers panics.
// Standard library only (Go 1.21+). Copy this file into your module, e.g. as
// internal/densight/densight.go.
//
//	dh := densight.New(densight.Options{URL: os.Getenv("DENSIGHT_URL"), Key: os.Getenv("DENSIGHT_KEY"), Service: "orders"})
//	defer dh.Close()
//	logger := slog.New(densight.Tee(slog.NewJSONHandler(os.Stdout, nil), dh))
//	slog.SetDefault(logger)
//	http.ListenAndServe(":8080", densight.Middleware(logger, mux))
//
// An error passed as an attribute (slog.Any("error", err)) is sent with its
// type; at error level the call stack is sent too, so repeats of the same
// error are grouped. Records are batched and sent from a goroutine; a
// Densight outage never blocks or crashes the application.
package densight

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Options configures the handler. URL and Key are required.
type Options struct {
	URL, Key                      string
	Service, Environment, Release string // Release defaults to $DENSIGHT_RELEASE
	Level                         slog.Leveler
	BatchSize                     int
	FlushInterval                 time.Duration
}

// Handler is a slog.Handler that ships records to Densight.
type Handler struct {
	shared *shipper
	attrs  []slog.Attr
	groups []string
}

type shipper struct {
	opts    Options
	host    string
	queue   chan map[string]any
	client  *http.Client
	done    chan struct{}
	stopped sync.WaitGroup
	once    sync.Once
}

// New starts the background sender; call Close before the program exits.
func New(opts Options) *Handler {
	if opts.Level == nil {
		opts.Level = slog.LevelInfo
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 2 * time.Second
	}
	if opts.Release == "" {
		opts.Release = os.Getenv("DENSIGHT_RELEASE")
	}
	host, _ := os.Hostname()
	s := &shipper{opts: opts, host: host, queue: make(chan map[string]any, 20000),
		client: &http.Client{Timeout: 5 * time.Second}, done: make(chan struct{})}
	s.stopped.Add(1)
	go s.run()
	return &Handler{shared: s}
}

// Close sends what is queued and stops the sender.
func (h *Handler) Close() {
	h.shared.once.Do(func() { close(h.shared.done); h.shared.stopped.Wait() })
}

func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.shared.opts.Level.Level()
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &Handler{shared: h.shared, attrs: append(append([]slog.Attr{}, h.attrs...), attrs...), groups: h.groups}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{shared: h.shared, attrs: h.attrs, groups: append(append([]string{}, h.groups...), name)}
}

func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	o := h.shared.opts
	entry := map[string]any{
		"timestamp": r.Time.UTC().Format(time.RFC3339Nano), "level": r.Level.String(), "message": r.Message,
		"service": o.Service, "environment": o.Environment, "release": o.Release, "host": h.shared.host,
	}
	add := func(a slog.Attr) {
		key := strings.Join(append(append([]string{}, h.groups...), a.Key), ".")
		value := a.Value.Resolve().Any()
		if err, ok := value.(error); ok {
			entry["error"] = map[string]any{"type": fmt.Sprintf("%T", err), "message": err.Error()}
			return
		}
		if _, taken := entry[key]; !taken {
			entry[key] = value
		}
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool { add(a); return true })
	if r.Level >= slog.LevelError {
		stack := callers(r.PC)
		if e, ok := entry["error"].(map[string]any); ok {
			e["stack"] = stack
		} else {
			entry["stacktrace"] = stack
		}
	}
	select {
	case h.shared.queue <- entry:
	default: // full: drop rather than block the application
	}
	return nil
}

// selfFile is this file: its frames are left out of stacks even when the
// compiler inlines them into the caller (and renames them).
var selfFile = func() string { _, file, _, _ := runtime.Caller(0); return file }()

// callers formats the stack from the logging call outwards, as Go prints it:
// "pkg.Func\n\t/path/file.go:42".
func callers(pc uintptr) string {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(4, pcs)
	if pc != 0 {
		pcs = append([]uintptr{pc}, pcs[:n]...)
	} else {
		pcs = pcs[:n]
	}
	var b strings.Builder
	frames := runtime.CallersFrames(pcs)
	seen := map[string]bool{}
	for {
		f, more := frames.Next()
		where := fmt.Sprintf("%s:%d", f.File, f.Line)
		// Not slog's or this package's own frames: the stack starts at the application's code.
		own := f.File == selfFile || strings.HasPrefix(f.Function, "densight.") || strings.Contains(f.Function, "/densight.")
		if !seen[where] && !own && !strings.HasPrefix(f.Function, "log/slog.") {
			seen[where] = true
			fmt.Fprintf(&b, "%s\n\t%s\n", f.Function, where)
		}
		if !more {
			break
		}
	}
	return b.String()
}

func (s *shipper) run() {
	defer s.stopped.Done()
	ticker := time.NewTicker(s.opts.FlushInterval)
	defer ticker.Stop()
	batch := make([]map[string]any, 0, s.opts.BatchSize)
	send := func() {
		if len(batch) > 0 {
			s.post(batch)
			batch = batch[:0]
		}
	}
	for {
		select {
		case entry := <-s.queue:
			batch = append(batch, entry)
			if len(batch) >= s.opts.BatchSize {
				send()
			}
		case <-ticker.C:
			send()
		case <-s.done:
			for {
				select {
				case entry := <-s.queue:
					batch = append(batch, entry)
				default:
					send()
					return
				}
			}
		}
	}
}

func (s *shipper) post(batch []map[string]any) {
	body, err := json.Marshal(batch)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, s.opts.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.opts.Key)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := s.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

// Tee sends each record to several handlers (e.g. stdout and Densight).
func Tee(handlers ...slog.Handler) slog.Handler { return tee(handlers) }

type tee []slog.Handler

func (t tee) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range t {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (t tee) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range t {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r.Clone())
		}
	}
	return nil
}

func (t tee) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(tee, len(t))
	for i, h := range t {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (t tee) WithGroup(name string) slog.Handler {
	out := make(tee, len(t))
	for i, h := range t {
		out[i] = h.WithGroup(name)
	}
	return out
}

// PanicError is a recovered panic, logged as an error of its own type.
type PanicError struct{ Value any }

func (p PanicError) Error() string { return fmt.Sprintf("%v", p.Value) }

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

// Middleware logs every request (method, path, status, client address, user
// agent) and turns a panic into a logged error with its stack and a 500.
func Middleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			ip = req.RemoteAddr
		}
		attrs := func() []any {
			return []any{"method", req.Method, "path", req.URL.RequestURI(), "status", rec.status, "ip", ip,
				"user_agent", req.UserAgent(), "duration_ms", time.Since(start).Milliseconds()}
		}
		defer func() {
			if p := recover(); p != nil {
				rec.status = http.StatusInternalServerError
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				logger.Error(fmt.Sprintf("panic: %v", p), append(attrs(), "error", PanicError{p})...)
				return
			}
			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelWarn
			}
			logger.Log(req.Context(), level, fmt.Sprintf("%s %s %d", req.Method, req.URL.Path, rec.status), attrs()...)
		}()
		next.ServeHTTP(rec, req)
	})
}
