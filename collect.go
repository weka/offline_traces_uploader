package main

// Collection side: host discovery, per-host file selection, and the remote
// tar stream. Every external call has a deadline and every host stream has a
// stall watchdog — a Sev1 cluster is exactly when hosts and the WEKA CLI
// misbehave, and one silent host must never freeze the whole run again
// (tower-sev1, 2026-11-25: host 9 of 20 went quiet and the run sat forever).

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Selection: shards whose mtime falls in the window, every ELF cache, dumper
// configs. Only when NOTHING on the host matches the window (window predates
// the cluster, clock skew, retention already rotated it away) does it fall
// back to the newest shard of every <util>_slot<N>_<area>_<container>
// stream, so the box still has something readable. v0.1.x always added
// those newest shards — on a past window that is ~2 GB/host of live shards
// from hours after the incident, still being written.
const selectScript = `
FROM_EPOCH="$1"; TO_EPOCH="$2"
DIRS=""
for d in /opt/weka/traces /opt/weka/wtracer/traces; do [ -d "$d" ] && DIRS="$DIRS $d"; done
[ -n "$DIRS" ] || exit 0
W=$(for d in $DIRS; do
  find "$d" -maxdepth 1 -type f -name '*.shard' -newermt "@$FROM_EPOCH" ! -newermt "@$TO_EPOCH" 2>/dev/null
done)
{
  if [ -n "$W" ]; then
    echo "$W"
  else
    for d in $DIRS; do
      ls -1t "$d"/*.shard 2>/dev/null | awk '{
        p=$0; sub(/_[0-9]+_[0-9]+_[^_\/]*\.shard$/,"",p);
        if (!(p in seen)) { seen[p]=1; print }
      }'
    done
  fi
  for d in $DIRS; do
    find "$d" -maxdepth 1 -type f -name '*cache*' 2>/dev/null
    find "$d" -maxdepth 2 -type f -name 'config.json' 2>/dev/null
  done
} | sort -u
`

// sshArgs mirrors what `weka debug pdsh --dry-run` shows the CLI itself
// using, plus: BatchMode (a password prompt must fail, not wait for a human
// that isn't watching that host) and keepalives (a dead peer is noticed in
// ~60 s instead of never).
var sshArgs = []string{
	"-o", "LogLevel=ERROR",
	"-o", "UserKnownHostsFile=/dev/null",
	"-o", "StrictHostKeyChecking=no",
	"-o", "ConnectTimeout=15",
	"-o", "BatchMode=yes",
	"-o", "ServerAliveInterval=15",
	"-o", "ServerAliveCountMax=4",
}

// Test seams: the tests swap ssh for a local shell and drop the sudo.
var (
	sshCommand = func(ctx context.Context, host, remote string) *exec.Cmd {
		args := append(append([]string{}, sshArgs...), host, remote)
		return exec.CommandContext(ctx, "ssh", args...)
	}
	remoteTarCmd = "sudo tar -cf - --absolute-names --warning=no-file-changed --ignore-failed-read -T -"
	remoteSelect = func(from, to int64) string { return fmt.Sprintf("sudo bash -s '%d' '%d'", from, to) }
	remoteDuCmd  = "sudo xargs -r -d '\\n' du -cb 2>/dev/null | tail -1 | cut -f1"
)

const (
	cliTimeout  = 90 * time.Second // any single weka CLI call
	listTimeout = 3 * time.Minute  // per-host file listing / sizing over ssh
)

// runT runs a local command with a deadline; stderr comes back separately so
// failures can say what actually went wrong.
func runT(timeout time.Duration, name string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return strings.TrimSpace(so.String()), strings.TrimSpace(se.String()), err
}

func run(name string, args ...string) (string, error) {
	out, _, err := runT(cliTimeout, name, args...)
	return out, err
}

// weka runs the weka CLI, returning stdout.
func weka(args ...string) (string, error) { return run("weka", args...) }

func parseTime(s string) (time.Time, error) {
	// Accept what `date -d` would: lean on date(1) so operators can use the
	// same strings they are used to ("2026-09-29 14:00", "45 minutes ago", ISO).
	out, err := run("date", "-d", s, "+%s")
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot parse time %q", s)
	}
	var epoch int64
	fmt.Sscanf(out, "%d", &epoch)
	return time.Unix(epoch, 0), nil
}

func freezeWindow() (start, end time.Time, err error) {
	out, se, err := runT(cliTimeout, "weka", "debug", "traces", "freeze", "show", "-J")
	if err != nil {
		return start, end, fmt.Errorf("cannot read the freeze period (%v %s) — are you logged in? (weka user login)", err, firstLine(se))
	}
	var j struct {
		Start string `json:"start_time"`
		End   string `json:"end_time"`
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.Start == "" || j.End == "" {
		return start, end, fmt.Errorf("no freeze period is set on this cluster (weka debug traces freeze show)")
	}
	if start, err = time.Parse(time.RFC3339Nano, j.Start); err != nil {
		return start, end, err
	}
	end, err = time.Parse(time.RFC3339Nano, j.End)
	return start, end, err
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// runningContainers lists local WEKA containers in state Running.
func runningContainers() []string {
	out, err := weka("local", "ps", "--no-header")
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "Running" {
			names = append(names, f[0])
		}
	}
	return names
}

func parseHostList(s string) []string {
	seen := map[string]bool{}
	var hs []string
	for _, h := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\t' }) {
		if h = strings.TrimSpace(h); h != "" && !seen[h] {
			seen[h] = true
			hs = append(hs, h)
		}
	}
	return hs
}

// discoverHosts resolves the backends via `weka debug pdsh --print-hosts`,
// which reads the LOCAL container's copy of the cluster config
// (`weka local run /weka/cfgdump`), so it does not need a cluster leader —
// but it does need a running local container. It tries the default
// container, then every other running one, and prints the CLI's own error on
// every miss (v0.1.x only printed it after the third attempt, so a Ctrl-C
// left nothing to go on).
func discoverHosts(o opts) []string {
	if o.hosts != "" {
		return parseHostList(o.hosts)
	}
	try := func(extra ...string) ([]string, error) {
		var all []string
		var lastErr error
		for _, role := range []string{"--drives", "--computes"} {
			args := append(append([]string{"debug", "pdsh"}, extra...), role, "--print-hosts")
			out, se, err := runT(cliTimeout, "weka", args...)
			if err != nil {
				lastErr = fmt.Errorf("weka %s: %v %s", strings.Join(args, " "), err, firstLine(se))
				continue
			}
			all = append(all, parseHostList(out)...)
		}
		hs := parseHostList(strings.Join(all, ","))
		if len(hs) == 0 && lastErr == nil {
			lastErr = fmt.Errorf("the cluster config listed no backends")
		}
		if len(hs) > 0 {
			return hs, nil
		}
		return nil, lastErr
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if hs, err := try(); err == nil {
			sort.Strings(hs)
			return hs
		} else {
			lastErr = err
			logf("host discovery attempt %d failed: %v", attempt, err)
		}
		for _, c := range runningContainers() {
			if hs, err := try("-C", c); err == nil {
				logf("host discovery worked via container %s", c)
				sort.Strings(hs)
				return hs
			} else {
				logf("  via container %s: %v", c, err)
			}
		}
		if attempt < 3 {
			logf("retrying host discovery in 10s (Ctrl-C and pass -hosts to skip it)...")
			time.Sleep(10 * time.Second)
		}
	}
	host, _ := os.Hostname()
	die("host discovery failed: %v\n"+
		"  - is WEKA up on this host? (weka local ps)\n"+
		"  - pass the backends yourself, comma-separated, e.g.\n"+
		"      -hosts %s,<backend2>,<backend3>,...\n"+
		"    (the hostnames this host can ssh to, as in `weka cluster container`)", lastErr, host)
	return nil
}

// remoteFilelist runs the selection script on host via ssh+sudo, stdin-fed so
// no quoting layer can eat it.
func remoteFilelist(host string, from, to int64) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()
	cmd := sshCommand(ctx, host, remoteSelect(from, to))
	cmd.Stdin = strings.NewReader(selectScript)
	var se bytes.Buffer
	cmd.Stderr = &se
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("listing files timed out after %s (host unresponsive?)", listTimeout)
	}
	if err != nil {
		return nil, fmt.Errorf("listing files: %v %s", err, firstLine(se.String()))
	}
	var files []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			files = append(files, l)
		}
	}
	return files, nil
}

func remoteDu(host string, files []string) int64 {
	if len(files) == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()
	cmd := sshCommand(ctx, host, remoteDuCmd)
	cmd.Stdin = strings.NewReader(strings.Join(files, "\n") + "\n")
	out, _ := cmd.Output()
	var n int64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
	return n
}

type hostPlan struct {
	name  string
	files []string
	est   int64
	err   error
}

// planHosts lists and sizes every host in parallel (bounded), so the run
// knows its total before it copies a byte — and a host that can't even be
// listed is reported up front instead of hanging the run.
func planHosts(hosts []string, from, to int64, parallel int) []hostPlan {
	plans := make([]hostPlan, len(hosts))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p := hostPlan{name: h}
			p.files, p.err = remoteFilelist(h, from, to)
			if p.err == nil {
				p.est = remoteDu(h, p.files)
			}
			plans[i] = p
		}(i, h)
	}
	wg.Wait()
	return plans
}

// stallReader notices when a Read on the remote stream has been blocked too
// long. Only time spent INSIDE Read counts: when the uploader is busy (slow
// uplink, full disk) nobody is reading, and that is backpressure, not a
// silent host.
type stallReader struct {
	r     io.Reader
	mu    sync.Mutex
	in    bool
	since time.Time
	total *int64
}

func (s *stallReader) Read(p []byte) (int, error) {
	s.mu.Lock()
	s.in, s.since = true, time.Now()
	s.mu.Unlock()
	n, err := s.r.Read(p)
	s.mu.Lock()
	s.in = false
	s.mu.Unlock()
	atomic.AddInt64(s.total, int64(n))
	return n, err
}

func (s *stallReader) blockedFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.in {
		return 0
	}
	return time.Since(s.since)
}

// lineLogger turns a child's stderr into logf lines (so tar warnings reach
// the status beacon too) and remembers the last one for error messages.
type lineLogger struct {
	prefix string
	mu     sync.Mutex
	buf    []byte
	last   string
}

func (l *lineLogger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(l.buf[:i]))
		l.buf = l.buf[i+1:]
		if line != "" {
			l.last = line
			logf("%s%s", l.prefix, line)
		}
	}
	return len(p), nil
}

func (l *lineLogger) lastLine() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == "" && len(l.buf) > 0 {
		return strings.TrimSpace(string(l.buf))
	}
	return l.last
}

var errStalled = errors.New("stalled")

// streamHostIntoTar pulls `sudo tar` of the file list from host and re-emits
// every entry into tw under <prefix>hosts/<host>/, renamed from its absolute
// origin. Nothing is staged on disk. If the host sends nothing for `stall`
// while we are waiting on it, the ssh is killed and errStalled returned.
// read accumulates the bytes pulled off the host (progress reporting).
func streamHostIntoTar(ctx context.Context, tw *tar.Writer, prefix, host string, files []string,
	stall time.Duration, read *int64) (nfiles int, bytesOut int64, err error) {
	if read == nil {
		read = new(int64)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := sshCommand(ctx, host, remoteTarCmd)
	cmd.Stdin = strings.NewReader(strings.Join(files, "\n") + "\n")
	ll := &lineLogger{prefix: "[" + host + "] "}
	cmd.Stderr = ll
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, 0, err
	}
	sr := &stallReader{r: pipe, total: read}
	var stalled int32
	wdDone := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-wdDone:
				return
			case <-t.C:
				if d := sr.blockedFor(); d > stall {
					atomic.StoreInt32(&stalled, 1)
					logf("[%s] STALLED: no data for %s — dropping this host and moving on", host, d.Round(time.Second))
					cancel() // CommandContext kills ssh
					return
				}
			}
		}
	}()
	finish := func(e error) (int, int64, error) {
		close(wdDone)
		cancel()
		cmd.Wait()
		if atomic.LoadInt32(&stalled) == 1 {
			return nfiles, bytesOut, fmt.Errorf("%w: no data from %s for %s (after %d files, %s)",
				errStalled, host, stall, nfiles, humanBytes(bytesOut))
		}
		return nfiles, bytesOut, e
	}

	tr := tar.NewReader(sr)
	for {
		hdr, rerr := tr.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return finish(fmt.Errorf("reading the tar stream from %s: %v %s", host, rerr, ll.lastLine()))
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "/")
		switch {
		case strings.HasPrefix(name, "opt/weka/wtracer/traces/"):
			name = "wtracer/" + strings.TrimPrefix(name, "opt/weka/wtracer/traces/")
		case strings.HasPrefix(name, "opt/weka/traces/"):
			name = "traces/" + strings.TrimPrefix(name, "opt/weka/traces/")
		default:
			name = "other/" + path.Base(name)
		}
		hdr.Name = prefix + "hosts/" + host + "/" + name
		if werr := tw.WriteHeader(hdr); werr != nil {
			return finish(werr)
		}
		n, werr := io.Copy(tw, tr)
		bytesOut += n
		if werr != nil {
			return finish(fmt.Errorf("writing %s: %v", hdr.Name, werr))
		}
		nfiles++
	}
	// Clean end-of-archive. Drain the record padding so tar can exit.
	io.Copy(io.Discard, sr)
	close(wdDone)
	werr := cmd.Wait()
	if atomic.LoadInt64(read) == 0 {
		// An empty stream also reads as a clean EOF — that is ssh or sudo
		// failing before tar ever ran.
		return 0, 0, fmt.Errorf("no data from %s: %v %s", host, werr, ll.lastLine())
	}
	if werr != nil {
		// The archive itself ended cleanly, so what we have is complete;
		// GNU tar exits non-zero for shards that changed or vanished mid-read.
		logf("[%s] note: remote tar exited with %v after a complete archive — kept", host, werr)
	}
	return nfiles, bytesOut, nil
}

// addFileToTar copies one local file into the tar at the given entry name.
func addFileToTar(tw *tar.Writer, localPath, name string) error {
	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: fi.Size(), ModTime: fi.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// verifyTarEnd checks the archive's end-of-archive marker (two 512-byte zero
// blocks). A transfer cut mid-stream leaves a tarball that lists fine until
// the cut — this catches it at the source, where the size is still knowable.
func verifyTarEnd(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() < 1024 {
		return fmt.Errorf("file too small to be a tar archive")
	}
	buf := make([]byte, 1024)
	if _, err := f.ReadAt(buf, fi.Size()-1024); err != nil {
		return err
	}
	for _, b := range buf {
		if b != 0 {
			return fmt.Errorf("missing end-of-archive blocks (truncated?)")
		}
	}
	return nil
}

// addBytesToTar writes an in-memory blob as a tar entry.
func addBytesToTar(tw *tar.Writer, b []byte, name string) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func writeCmdOutput(path string, name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		out = append(out, []byte("\n(timed out after 45s)\n")...)
	} else if err != nil && len(out) == 0 {
		out = []byte(err.Error())
	}
	os.WriteFile(path, out, 0644)
}

func collectMetadata(metaDir string, o opts, from, to time.Time) {
	writeCmdOutput(filepath.Join(metaDir, "weka-version.txt"), "weka", "version")
	writeCmdOutput(filepath.Join(metaDir, "weka-status.json"), "weka", "status", "-J")
	writeCmdOutput(filepath.Join(metaDir, "cluster-container.json"), "weka", "cluster", "container", "-J")
	writeCmdOutput(filepath.Join(metaDir, "cluster-process.json"), "weka", "cluster", "process", "-J")
	writeCmdOutput(filepath.Join(metaDir, "traces-status.txt"), "weka", "debug", "traces", "status")
	writeCmdOutput(filepath.Join(metaDir, "traces-freeze.txt"), "weka", "debug", "traces", "freeze", "show")
	writeCmdOutput(filepath.Join(metaDir, "local-ps.txt"), "weka", "local", "ps")
	win := fmt.Sprintf("start=%s\nend=%s\nmargin_min=%d\nfrom_epoch=%d\nto_epoch=%d\ncollected_at=%s\noffline_traces_uploader_version=%s\n",
		o.start, o.end, o.marginMin, from.Unix(), to.Unix(), time.Now().UTC().Format(time.RFC3339), version)
	os.WriteFile(filepath.Join(metaDir, "window.txt"), []byte(win), 0644)
}

// copyShippedElfCaches pulls /weka/elf_cache/*.cache.zstd out of a running
// container's rootfs (via /proc/<pid>/root). These let the offline reader
// decode without the matching weka binaries.
func copyShippedElfCaches(dstDir string) int {
	out, err := weka("local", "ps", "--no-header")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "Running" {
			continue
		}
		src := fmt.Sprintf("/proc/%s/root/weka/elf_cache", f[7])
		entries, err := os.ReadDir(src)
		if err != nil {
			continue
		}
		n := 0
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".cache.zstd") {
				continue
			}
			if b, err := os.ReadFile(filepath.Join(src, e.Name())); err == nil {
				if os.WriteFile(filepath.Join(dstDir, e.Name()), b, 0644) == nil {
					n++
				}
			}
		}
		if n > 0 {
			return n
		}
	}
	return 0
}

var errFreezeExists = fmt.Errorf("a freeze period is already set")

func setFreeze(from, to time.Time, days int) error {
	_, se, err := runT(cliTimeout, "weka", "debug", "traces", "freeze", "set",
		"--start-time", from.UTC().Format("2006-01-02 15:04:05")+"Z",
		"--end-time", to.UTC().Format("2006-01-02 15:04:05")+"Z",
		"--retention", fmt.Sprintf("%dd", days),
		"--comment", fmt.Sprintf("offline_traces_uploader %s", time.Now().UTC().Format(time.RFC3339)))
	if err == nil {
		return nil
	}
	if strings.Contains(se, "already set") {
		return errFreezeExists
	}
	return fmt.Errorf("%v: %s", err, firstLine(se))
}

// loginInteractively prompts for WEKA cluster credentials on the controlling
// terminal (password without echo) and runs `weka user login`. Returns true
// on a successful login; false when there is no terminal or login failed.
func loginInteractively() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false // no terminal (cron/CI) — keep the old warning path
	}
	defer tty.Close()
	fmt.Fprint(tty, "\nWEKA CLI is not logged in — freeze needs ClusterAdmin.\n")
	fmt.Fprint(tty, "WEKA username [admin]: ")
	rd := bufio.NewReader(tty)
	user, _ := rd.ReadString('\n')
	user = strings.TrimSpace(user)
	if user == "" {
		user = "admin"
	}
	fmt.Fprint(tty, "WEKA password: ")
	// no-echo via stty on the same tty; restored right after the read
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	pass, _ := rd.ReadString('\n')
	exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	fmt.Fprintln(tty)
	pass = strings.TrimSpace(pass)
	if pass == "" {
		return false
	}
	if out, err := weka("user", "login", user, pass); err != nil {
		logf("weka login failed: %v %s", err, out)
		return false
	}
	logf("logged in as %s", user)
	return true
}

func clusterName() string {
	out, _, err := runT(45*time.Second, "weka", "status", "-J")
	if err != nil {
		return "cluster"
	}
	var j struct {
		Name string `json:"name"`
	}
	if json.Unmarshal([]byte(out), &j) == nil && j.Name != "" {
		return j.Name
	}
	return "cluster"
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// freeSpace returns available and total bytes of the filesystem holding p.
func freeSpace(p string) (avail, total int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}

// mountOf returns the mount point and fs type holding p (longest prefix in
// /proc/self/mounts).
func mountOf(p string) (mnt, fstype string) {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	p, _ = filepath.Abs(p)
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		m := strings.ReplaceAll(f[1], "\\040", " ")
		if (p == m || strings.HasPrefix(p, strings.TrimRight(m, "/")+"/") || m == "/") && len(m) >= len(mnt) {
			mnt, fstype = m, f[2]
		}
	}
	return mnt, fstype
}
