package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOCI implements just enough of the PAR + multipart protocol.
type fakeOCI struct {
	mu        sync.Mutex
	objects   map[string][]byte
	uploads   map[string]map[int][]byte // uploadId -> parts
	uploadObj map[string]string
	failOnce  map[string]bool // path -> fail first attempt with 503
	partDelay time.Duration
	expired   bool
	partsSeen int
	aborted   int
}

func newFakeOCI() *fakeOCI {
	return &fakeOCI{objects: map[string][]byte{}, uploads: map[string]map[int][]byte{},
		uploadObj: map[string]string{}, failOnce: map[string]bool{}}
}

func (f *fakeOCI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if f.expired {
		f.mu.Unlock()
		w.WriteHeader(404)
		io.WriteString(w, `{"code":"NotAuthorizedOrNotFound","message":"PAR not found"}`)
		return
	}
	if f.failOnce[r.URL.Path] {
		delete(f.failOnce, r.URL.Path)
		f.mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(503)
		return
	}
	f.mu.Unlock()
	p := r.URL.Path
	const obj = "/p/tok/n/ns/b/bkt/o/"
	switch {
	case strings.HasPrefix(p, obj) && r.Method == http.MethodPut && r.Header.Get("opc-multipart") == "true":
		name := strings.TrimPrefix(p, obj)
		f.mu.Lock()
		id := fmt.Sprintf("up%d", len(f.uploads)+1)
		f.uploads[id] = map[int][]byte{}
		f.uploadObj[id] = name
		f.mu.Unlock()
		fmt.Fprintf(w, `{"accessUri":"/p/tok2/n/ns/b/bkt/u/%s/id/%s/","uploadId":"%s"}`, name, id, id)
	case strings.HasPrefix(p, obj) && r.Method == http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.objects[strings.TrimPrefix(p, obj)] = b
		f.mu.Unlock()
	case strings.Contains(p, "/u/"):
		i := strings.Index(p, "/id/")
		rest := strings.Split(strings.Trim(p[i+4:], "/"), "/")
		id := rest[0]
		f.mu.Lock()
		parts, ok := f.uploads[id]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case http.MethodPut:
			n, _ := strconv.Atoi(rest[1])
			if f.partDelay > 0 {
				time.Sleep(f.partDelay)
			}
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			parts[n] = b
			f.partsSeen++
			f.mu.Unlock()
			w.Header().Set("ETag", fmt.Sprintf(`"etag-%d"`, n))
		case http.MethodPost:
			f.mu.Lock()
			var nums []int
			for n := range parts {
				nums = append(nums, n)
			}
			sort.Ints(nums)
			var all []byte
			for _, n := range nums {
				all = append(all, parts[n]...)
			}
			f.objects[f.uploadObj[id]] = all
			delete(f.uploads, id)
			f.mu.Unlock()
		case http.MethodDelete:
			f.mu.Lock()
			delete(f.uploads, id)
			f.aborted++
			f.mu.Unlock()
		}
	default:
		w.WriteHeader(400)
	}
}

func testClient(t *testing.T, f *fakeOCI) *parClient {
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := newPARClient(srv.URL + "/p/tok/n/ns/b/bkt/o/")
	if err != nil {
		t.Fatal(err)
	}
	c.retryBase = 10 * time.Millisecond
	return c
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestUploadStreamMultipartWithRetry(t *testing.T) {
	f := newFakeOCI()
	c := testClient(t, f)
	f.failOnce["/p/tok2/n/ns/b/bkt/u/cust/drop/hosts/h1.tar/id/up1/2"] = true
	data := randBytes(10<<20 + 12345)
	var confirmed int64
	var mu sync.Mutex
	n, err := c.uploadStream(context.Background(), "cust/drop/hosts/h1.tar", bytes.NewReader(data), 1<<20, 3,
		func(k int64) { mu.Lock(); confirmed += k; mu.Unlock() })
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if n != int64(len(data)) || confirmed != int64(len(data)) {
		t.Fatalf("byte counts: returned %d confirmed %d want %d", n, confirmed, len(data))
	}
	if !bytes.Equal(f.objects["cust/drop/hosts/h1.tar"], data) {
		t.Fatal("committed object differs from the input")
	}
	if f.partsSeen != 11 {
		t.Fatalf("parts uploaded = %d, want 11", f.partsSeen)
	}
}

func TestUploadStreamExpiredCodeSaysSo(t *testing.T) {
	f := newFakeOCI()
	f.expired = true
	c := testClient(t, f)
	_, err := c.uploadStream(context.Background(), "x/y.tar", bytes.NewReader(randBytes(100)), 1<<20, 2, nil)
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "NotAuthorizedOrNotFound") {
		t.Fatalf("want an 'expired' error carrying OCI's message, got %v", err)
	}
}

func TestUploadStreamReaderErrorAborts(t *testing.T) {
	f := newFakeOCI()
	c := testClient(t, f)
	pr, pw := io.Pipe()
	go func() {
		pw.Write(randBytes(3 << 20))
		pw.CloseWithError(errors.New("host went away"))
	}()
	_, err := c.uploadStream(context.Background(), "x/h.tar", pr, 1<<20, 2, nil)
	if err == nil || !strings.Contains(err.Error(), "host went away") {
		t.Fatalf("want the reader's error, got %v", err)
	}
	if _, ok := f.objects["x/h.tar"]; ok || f.aborted != 1 {
		t.Fatalf("a failed stream must abort, not commit (aborted=%d)", f.aborted)
	}
}

// localShell swaps ssh for a local bash so the remote side can be scripted.
func localShell(t *testing.T, tarCmd string) {
	oldSSH, oldTar := sshCommand, remoteTarCmd
	sshCommand = func(ctx context.Context, host, remote string) *exec.Cmd {
		return exec.CommandContext(ctx, "bash", "-c", remote)
	}
	remoteTarCmd = tarCmd
	t.Cleanup(func() { sshCommand, remoteTarCmd = oldSSH, oldTar })
}

func tempFiles(t *testing.T, n, size int) []string {
	dir := t.TempDir()
	var files []string
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprintf("wekanode_slot%d_main_compute0_1_2_x.shard", i))
		os.WriteFile(p, randBytes(size), 0644)
		files = append(files, p)
	}
	return files
}

func TestStreamHostStallIsDetected(t *testing.T) {
	files := tempFiles(t, 3, 200<<10)
	// Send part of the archive, then go silent with the pipe still open.
	localShell(t, "tar -cf - --absolute-names -T - | head -c 300000; sleep 30")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	start := time.Now()
	_, _, err := streamHostIntoTar(context.Background(), tw, "p/", "h1", files, 2*time.Second, nil)
	if !errors.Is(err, errStalled) {
		t.Fatalf("want errStalled, got %v", err)
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("stall took %s to detect", el)
	}
}

func TestStreamHostEmptyStreamIsAnError(t *testing.T) {
	localShell(t, "echo 'sudo: a password is required' >&2; exit 1")
	var buf bytes.Buffer
	_, _, err := streamHostIntoTar(context.Background(), tar.NewWriter(&buf), "p/", "h1", []string{"/x"}, 5*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("an empty stream must fail with the remote's stderr, got %v", err)
	}
}

func TestUploadHostSlowUplinkIsNotAStall(t *testing.T) {
	files := tempFiles(t, 4, 1<<20) // ~4 MiB
	localShell(t, "tar -cf - --absolute-names -T -")
	f := newFakeOCI()
	f.partDelay = 700 * time.Millisecond // slow uplink: ~6 s for the host
	c := testClient(t, f)
	o := opts{stall: 1 * time.Second, inflight: 1, partMiB: 8}
	p := hostPlan{name: "h1", files: files, est: 4 << 20}
	var all int64
	// part size floor is 8 MiB in the flag; force small parts for the test
	n, err := uploadHostWithPart(o, c, "cust/d/", "weka-traces-c-s/", p, &all, 512<<10)
	if err != nil {
		t.Fatalf("a slow uplink must not count as a stalled host: %v", err)
	}
	obj := f.objects["cust/d/hosts/h1.tar"]
	if int64(len(obj)) != n || n == 0 {
		t.Fatalf("object size %d vs reported %d", len(obj), n)
	}
	tr := tar.NewReader(bytes.NewReader(obj))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("uploaded host tar is not readable: %v", err)
		}
		names = append(names, h.Name)
	}
	if len(names) != 5 || names[0] != "weka-traces-c-s/hosts/h1/filelist.txt" {
		t.Fatalf("unexpected entries: %v", names)
	}
}

func TestPickPartSize(t *testing.T) {
	if got := pickPartSize(15<<30, 32); got != 32<<20 {
		t.Fatalf("15 GiB host: %d", got)
	}
	big := int64(2) << 40 // 2 TiB host
	ps := pickPartSize(big, 32)
	if big*13/10/ps > 9000 || ps%(1<<20) != 0 {
		t.Fatalf("2 TiB host would need %d parts of %d", big/ps, ps)
	}
}
