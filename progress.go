package main

// Progress beacon: while uploading, the collector rewrites a small
// <drop>/progress.json every few seconds — state, per-host bytes, the last
// lines of its own output, and (at the end) the command that re-collects
// any failed hosts. The Offline Traces dialog reads it, so WEKA can watch a
// customer run live (tower-sev1, 2026-11-25: support sat on a call with no
// way to tell whether anything was arriving).

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

const progressFormat = "offline-traces-drop/2"

type hostProgress struct {
	Name          string `json:"name"`
	State         string `json:"state"` // queued | listing | streaming | done | failed | stalled
	Files         int    `json:"files"`
	EstBytes      int64  `json:"est_bytes"`
	ReadBytes     int64  `json:"read_bytes"`     // pulled off the host so far
	UploadedBytes int64  `json:"uploaded_bytes"` // confirmed by object storage
	Error         string `json:"error,omitempty"`
	Started       string `json:"started,omitempty"`
	Finished      string `json:"finished,omitempty"`
}

type progressDoc struct {
	Format   string          `json:"format"`
	Version  string          `json:"version"`
	Customer string          `json:"customer"`
	Cluster  string          `json:"cluster"`
	Drop     string          `json:"drop"`
	RunsOn   string          `json:"runs_on"`
	Command  string          `json:"command"`
	State    string          `json:"state"` // starting | discovering | listing | collecting | done | partial | failed | interrupted
	Message  string          `json:"message,omitempty"`
	Started  string          `json:"started"`
	Updated  string          `json:"updated"`
	Finished string          `json:"finished,omitempty"`
	From     string          `json:"window_from,omitempty"`
	To       string          `json:"window_to,omitempty"`
	EstTotal int64           `json:"est_total"`
	Hosts    []*hostProgress `json:"hosts"`
	Log      []string        `json:"log"`
	Rerun    string          `json:"rerun,omitempty"`
}

type beacon struct {
	mu       sync.Mutex
	doc      progressDoc
	object   string
	c        *parClient
	stop     chan struct{}
	stopOnce sync.Once
	running  bool
	done     chan struct{}
	// redact hides the upload URL in anything we write back to the bucket.
	redact func(string) string
}

var (
	logRingMu sync.Mutex
	logRing   []string
	prog      *beacon // nil when not uploading
)

const logRingMax = 80

func remember(line string) {
	logRingMu.Lock()
	logRing = append(logRing, line)
	if len(logRing) > logRingMax {
		logRing = logRing[len(logRing)-logRingMax:]
	}
	logRingMu.Unlock()
}

func newBeacon(c *parClient, dropPrefix string, doc progressDoc, redact func(string) string) *beacon {
	doc.Format = progressFormat
	doc.Started = time.Now().UTC().Format(time.RFC3339)
	return &beacon{doc: doc, object: dropPrefix + "progress.json", c: c,
		stop: make(chan struct{}), done: make(chan struct{}), redact: redact}
}

func (b *beacon) update(fn func(d *progressDoc)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	fn(&b.doc)
	b.mu.Unlock()
}

func (b *beacon) host(name string) *hostProgress {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, h := range b.doc.Hosts {
		if h.Name == name {
			return h
		}
	}
	h := &hostProgress{Name: name, State: "queued"}
	b.doc.Hosts = append(b.doc.Hosts, h)
	return h
}

func (b *beacon) hostDo(name string, fn func(h *hostProgress)) {
	if b == nil {
		return
	}
	h := b.host(name)
	b.mu.Lock()
	fn(h)
	b.mu.Unlock()
}

func (b *beacon) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	logRingMu.Lock()
	b.doc.Log = make([]string, 0, len(logRing))
	for _, l := range logRing {
		b.doc.Log = append(b.doc.Log, b.redact(l))
	}
	logRingMu.Unlock()
	b.doc.Updated = time.Now().UTC().Format(time.RFC3339)
	b.doc.Command = b.redact(b.doc.Command)
	b.doc.Rerun = b.redact(b.doc.Rerun)
	out, _ := json.MarshalIndent(b.doc, "", " ")
	return out
}

// flush writes progress.json once. Failures are only logged to stderr: the
// beacon must never take the collection down with it.
func (b *beacon) flush(timeout time.Duration) error {
	if b == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return b.c.putBytes(ctx, b.object, b.snapshot(), "application/json")
}

func (b *beacon) run(every time.Duration) {
	b.running = true
	go func() {
		defer close(b.done)
		t := time.NewTicker(every)
		defer t.Stop()
		fails := 0
		for {
			select {
			case <-b.stop:
				return
			case <-t.C:
				if err := b.flush(45 * time.Second); err != nil {
					fails++
					if fails == 1 || fails%20 == 0 {
						// stderr only — logf would feed the ring and loop.
						os.Stderr.WriteString("[" + time.Now().Format("15:04:05") + "] (status update to WEKA failed: " + oneLine(err.Error()) + ")\n")
					}
				} else {
					fails = 0
				}
			}
		}
	}()
}

// finish stops the ticker and writes the final state.
func (b *beacon) finish(state, message string) {
	if b == nil {
		return
	}
	// Ctrl-C and a fatal error can race here; only the first one finishes.
	first := false
	b.stopOnce.Do(func() {
		first = true
		close(b.stop)
		if b.running {
			<-b.done
		}
	})
	if !first {
		return
	}
	b.update(func(d *progressDoc) {
		d.State = state
		if message != "" {
			d.Message = message
		}
		d.Finished = time.Now().UTC().Format(time.RFC3339)
	})
	if err := b.flush(60 * time.Second); err != nil {
		os.Stderr.WriteString("(final status update to WEKA failed: " + oneLine(err.Error()) + ")\n")
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}
