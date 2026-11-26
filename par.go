package main

// Upload side: everything goes through the WEKA-provided upload code, an OCI
// pre-authenticated request (PAR) that can only write objects.
//
// Why multipart: OCI refuses a single PUT over 50 GiB, and a whole-cluster
// pull is routinely bigger (tower-sev1, 2026-11-25: 20 hosts x ~15 GiB). A
// multipart upload has no practical size cap (10,000 parts, 10 TiB), every
// part retries on its own, and nothing has to be staged on the customer's
// disk: parts are cut straight off the stream coming back from each host.
//
// PAR multipart protocol (Object Storage "Uploading with a PAR"):
//   PUT  <par>/o/<object>  + "opc-multipart: true"  -> {"accessUri": ".../u/<object>/id/<uploadId>/", ...}
//   PUT  <origin><accessUri><partNum>                -> one part (ETag in the response)
//   POST <origin><accessUri>                         -> commit
//   DELETE <origin><accessUri>                       -> abort

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type parClient struct {
	base   string // ".../o/" (trailing slash)
	origin string // "https://objectstorage.<region>.oraclecloud.com"
	hc     *http.Client
	// test hooks
	retryBase time.Duration
}

func newPARClient(uploadURL string) (*parClient, error) {
	u, err := url.Parse(strings.TrimSpace(uploadURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("cannot parse the upload URL")
	}
	base := strings.TrimRight(uploadURL, "/") + "/"
	if !strings.HasSuffix(base, "/o/") {
		return nil, fmt.Errorf("the upload URL must end in /o/ (copy it exactly as WEKA sent it)")
	}
	return &parClient{
		base:   base,
		origin: u.Scheme + "://" + u.Host,
		// No client-wide timeout: a big part on a slow uplink can take a
		// while. Every request carries its own context deadline instead.
		hc: &http.Client{Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 10 * time.Minute,
			ExpectContinueTimeout: 5 * time.Second,
		}},
		retryBase: 2 * time.Second,
	}, nil
}

// ociError carries the HTTP status and OCI's own message, which names the
// real problem (expired code, wrong bucket, size limit) — v0.1.x threw it away.
type ociError struct {
	op     string
	status int
	body   string
}

func (e *ociError) Error() string {
	msg := strings.TrimSpace(e.body)
	var j struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(msg), &j) == nil && (j.Code != "" || j.Message != "") {
		msg = strings.TrimSpace(j.Code + ": " + j.Message)
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	hint := ""
	switch e.status {
	case 401, 403, 404:
		hint = " (the upload code has probably expired or was mistyped — ask WEKA for a fresh one)"
	}
	return fmt.Sprintf("%s: HTTP %d %s%s", e.op, e.status, msg, hint)
}

// retryable: network errors, 5xx, 408 and 429. Other 4xx answers won't
// change on a retry.
func retryable(err error) bool {
	var oe *ociError
	if errors.As(err, &oe) {
		return oe.status >= 500 || oe.status == 408 || oe.status == 429
	}
	return !errors.Is(err, context.Canceled)
}

func escapeObject(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// do runs one HTTP request (body re-created per attempt) with retries.
func (c *parClient) do(ctx context.Context, op, method, u string, hdr map[string]string,
	body func() io.Reader, size int64, attempts int, perTry time.Duration) (*http.Response, []byte, error) {
	var lastErr error
	for a := 1; a <= attempts; a++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		tctx, cancel := context.WithTimeout(ctx, perTry)
		var rd io.Reader
		if body != nil {
			rd = body()
		}
		req, err := http.NewRequestWithContext(tctx, method, u, rd)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		req.ContentLength = size
		if size == 0 {
			req.Body = http.NoBody
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.hc.Do(req)
		if err == nil {
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			cancel()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if rerr != nil {
					lastErr = rerr
				} else {
					return resp, b, nil
				}
			} else {
				lastErr = &ociError{op: op, status: resp.StatusCode, body: string(b)}
			}
		} else {
			cancel()
			lastErr = fmt.Errorf("%s: %v", op, err)
		}
		if !retryable(lastErr) || a == attempts {
			break
		}
		wait := c.retryBase * time.Duration(1<<uint(a-1))
		if wait > time.Minute {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, nil, lastErr
}

// putBytes writes a small object in one PUT (progress beacon, manifests).
func (c *parClient) putBytes(ctx context.Context, name string, b []byte, contentType string) error {
	_, _, err := c.do(ctx, "PUT "+name, http.MethodPut, c.base+escapeObject(name),
		map[string]string{"Content-Type": contentType},
		func() io.Reader { return bytes.NewReader(b) }, int64(len(b)), 4, 2*time.Minute)
	return err
}

type multipartUpload struct {
	c         *parClient
	name      string
	accessURL string // ends with "/"
	mu        sync.Mutex
	etags     map[int]string
}

func (c *parClient) startMultipart(ctx context.Context, name string) (*multipartUpload, error) {
	_, b, err := c.do(ctx, "start upload of "+name, http.MethodPut, c.base+escapeObject(name),
		map[string]string{"opc-multipart": "true"}, nil, 0, 6, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	var j struct {
		AccessURI string `json:"accessUri"`
	}
	if err := json.Unmarshal(b, &j); err != nil || j.AccessURI == "" {
		return nil, fmt.Errorf("start upload of %s: unexpected reply from object storage: %.200s", name, string(b))
	}
	au := j.AccessURI
	if !strings.HasPrefix(au, "http") {
		au = c.origin + "/" + strings.TrimLeft(au, "/")
	}
	if !strings.HasSuffix(au, "/") {
		au += "/"
	}
	return &multipartUpload{c: c, name: name, accessURL: au, etags: map[int]string{}}, nil
}

func (m *multipartUpload) uploadPart(ctx context.Context, num int, data []byte) error {
	// Generous per-try deadline: 32 MiB on a 1 MB/s uplink is ~35 s.
	perTry := 5*time.Minute + time.Duration(len(data)/(64<<10))*time.Second
	resp, _, err := m.c.do(ctx, fmt.Sprintf("upload part %d of %s", num, m.name), http.MethodPut,
		m.accessURL+strconv.Itoa(num), nil,
		func() io.Reader { return bytes.NewReader(data) }, int64(len(data)), 8, perTry)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.etags[num] = strings.Trim(resp.Header.Get("ETag"), `"`)
	m.mu.Unlock()
	return nil
}

func (m *multipartUpload) commit(ctx context.Context) error {
	_, _, err := m.c.do(ctx, "commit "+m.name, http.MethodPost, m.accessURL, nil, nil, 0, 6, 10*time.Minute)
	if err == nil {
		return nil
	}
	// Some endpoints want the part list spelled out — retry once that way.
	var oe *ociError
	if !errors.As(err, &oe) || oe.status < 400 || oe.status >= 500 {
		return err
	}
	type part struct {
		PartNum int    `json:"partNum"`
		Etag    string `json:"etag"`
	}
	m.mu.Lock()
	var parts []part
	for n := 1; n <= len(m.etags); n++ {
		parts = append(parts, part{PartNum: n, Etag: m.etags[n]})
	}
	m.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"partsToCommit": parts})
	_, _, err2 := m.c.do(ctx, "commit "+m.name, http.MethodPost, m.accessURL,
		map[string]string{"Content-Type": "application/json"},
		func() io.Reader { return bytes.NewReader(b) }, int64(len(b)), 4, 10*time.Minute)
	if err2 != nil {
		return err // the first answer is the meaningful one
	}
	return nil
}

func (m *multipartUpload) abort() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m.c.do(ctx, "abort "+m.name, http.MethodDelete, m.accessURL, nil, nil, 0, 2, 20*time.Second)
}

// uploadStream cuts r into partSize pieces and uploads them with up to
// inflight parts in the air, then commits. onPart is told every confirmed
// byte count. RAM use is bounded at (inflight+1)*partSize. On any error the
// multipart upload is aborted so no half-object is left behind.
func (c *parClient) uploadStream(ctx context.Context, name string, r io.Reader, partSize int64, inflight int,
	onPart func(n int64)) (total int64, err error) {
	mp, err := c.startMultipart(ctx, name)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	free := make(chan []byte, inflight+1)
	for i := 0; i < inflight+1; i++ {
		free <- make([]byte, partSize)
	}
	type job struct {
		num  int
		data []byte
		buf  []byte
	}
	jobs := make(chan job)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
		sent     int64
	)
	fail := func(e error) {
		errOnce.Do(func() { firstErr = e; cancel() })
	}
	for w := 0; w < inflight; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if err := mp.uploadPart(ctx, j.num, j.data); err != nil {
					fail(err)
				} else {
					atomic.AddInt64(&sent, int64(len(j.data)))
					if onPart != nil {
						onPart(int64(len(j.data)))
					}
				}
				free <- j.buf
			}
		}()
	}

	num := 0
	var readErr error
	for {
		var buf []byte
		select {
		case buf = <-free:
		case <-ctx.Done():
		}
		if buf == nil {
			break
		}
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			num++
			select {
			case jobs <- job{num: num, data: buf[:n], buf: buf}:
			case <-ctx.Done():
			}
		} else {
			free <- buf
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			readErr = rerr
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(jobs)
	wg.Wait()

	switch {
	case readErr != nil:
		mp.abort()
		return sent, readErr
	case firstErr != nil:
		mp.abort()
		return sent, firstErr
	case ctx.Err() != nil:
		mp.abort()
		return sent, ctx.Err()
	case num == 0:
		// Empty stream: multipart can't commit zero parts — write it plain.
		mp.abort()
		return 0, c.putBytes(context.Background(), name, nil, "application/x-tar")
	}
	if err := mp.commit(context.Background()); err != nil {
		mp.abort()
		return sent, err
	}
	return sent, nil
}
