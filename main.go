// offline_traces_uploader (formerly wekatrace) — collect WEKA trace shards from a cluster and (optionally)
// upload them to a WEKA-provided drop URL for offline analysis.
//
// Run on ONE backend of the cluster, as root (sudo). Host discovery and the
// transfer path reuse the cluster's own fan-out mechanics (`weka debug pdsh`
// resolves hosts from the cluster config; transfers ride the same plain-ssh
// path pdsh itself uses). The remote ssh login is whatever user the cluster's
// authorized_keys map to — usually NOT root — so every remote command runs
// under its own sudo.
//
// What lands in the tarball, per host: trace shards covering the requested
// window, the ELF caches lying in the trace dirs, and the dumper config.json
// files. Once per run: the shipped ELF caches from the running container
// image (decode-critical, ~55MB) and cluster metadata (version, status,
// container/process maps, traces + freeze state, window record).
//
// The upload URL is a write-only, expiring token handed out by WEKA per
// engagement. It can only PUT objects — it cannot list or read anything.
package main

import (
	"archive/tar"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var version = "dev" // stamped at build time via -ldflags "-X main.version=..."

// Selection: window shards by mtime, every ELF cache, dumper configs, and —
// so a missed window still yields something readable per stream — the newest
// shard of every <util>_slot<N>_<area>_<container> group (shard names end in
// _<seq>_<seq>_<timestamp>.shard; ls -1t + first-seen-per-prefix keeps the
// newest of each).
const selectScript = `
FROM_EPOCH="$1"; TO_EPOCH="$2"
for d in /opt/weka/traces /opt/weka/wtracer/traces; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f -name '*.shard' \
       -newermt "@$FROM_EPOCH" ! -newermt "@$TO_EPOCH" 2>/dev/null
  find "$d" -maxdepth 1 -type f -name '*cache*' 2>/dev/null
  find "$d" -maxdepth 2 -type f -name 'config.json' 2>/dev/null
  ls -1t "$d"/*.shard 2>/dev/null | awk '{
    p=$0; sub(/_[0-9]+_[0-9]+_[^_\/]*\.shard$/,"",p);
    if (!(p in seen)) { seen[p]=1; print }
  }'
done | sort -u
`

// sshArgs mirrors what `weka debug pdsh --dry-run` shows the CLI itself using.
var sshArgs = []string{
	"-o", "LogLevel=ERROR",
	"-o", "UserKnownHostsFile=/dev/null",
	"-o", "StrictHostKeyChecking=no",
	"-o", "ConnectTimeout=15",
}

type opts struct {
	start, end   string
	last         string
	fromFreeze   bool
	estimate     bool
	dest         string
	marginMin    int
	hosts        string
	noFreeze     bool
	freezeDays   int
	uploadURL    string
	customer     string
	keepWorkdir  bool
	printVersion bool
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, a...))
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: %s\n", fmt.Sprintf(format, a...))
	os.Exit(1)
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
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
	out, err := weka("debug", "traces", "freeze", "show", "-J")
	if err != nil {
		return start, end, fmt.Errorf("cannot read freeze period — are you logged in? (weka user login)")
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

func discoverHosts(o opts) []string {
	if o.hosts != "" {
		var hs []string
		for _, h := range strings.Split(o.hosts, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hs = append(hs, h)
			}
		}
		return hs
	}
	// `weka debug pdsh` resolves hosts from the cluster config. On a cluster
	// that only just formed (containers still applying resources) the config
	// dump fails transiently, so retry before giving up — and surface the
	// CLI's own stderr, which names the real problem.
	var out string
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		out, err = weka("debug", "pdsh", "--drives", "--print-hosts")
		if err == nil {
			break
		}
		if attempt < 3 {
			logf("host discovery attempt %d failed, retrying in 10s...", attempt)
			time.Sleep(10 * time.Second)
		}
	}
	if err != nil {
		detail := ""
		if ee, ok := err.(*exec.ExitError); ok {
			detail = strings.TrimSpace(string(ee.Stderr))
		}
		die("host discovery failed: %v %s\n"+
			"  - is WEKA up on this host? (weka local ps)\n"+
			"  - a just-formed cluster can take a few minutes before this works\n"+
			"  - or pass the backends yourself: -hosts host1,host2,...", err, detail)
	}
	seen := map[string]bool{}
	var hs []string
	for _, line := range strings.Split(out, "\n") {
		h := strings.TrimSpace(line)
		if h != "" && !seen[h] {
			seen[h] = true
			hs = append(hs, h)
		}
	}
	sort.Strings(hs)
	return hs
}

// remoteFilelist runs the selection script on host via ssh+sudo, stdin-fed so
// no quoting layer can eat it.
func remoteFilelist(host string, from, to int64) ([]string, error) {
	args := append(append([]string{}, sshArgs...), host,
		fmt.Sprintf("sudo bash -s '%d' '%d'", from, to))
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(selectScript)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing files on %s: %v", host, err)
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
	args := append(append([]string{}, sshArgs...), host,
		"sudo xargs -r -d '\\n' du -cb 2>/dev/null | tail -1 | cut -f1")
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(strings.Join(files, "\n") + "\n")
	out, _ := cmd.Output()
	var n int64
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
	return n
}

// streamHostIntoTar pulls `sudo tar` of the file list from host and re-emits
// every entry into the final tar under hosts/<host>/, renamed from its
// absolute origin. The remote tar stream frames each file's size, so nothing
// is staged on disk — the final tarball is the only copy ("tar while
// saving"; a 2026-10 field run filled a small /tmp with the old two-phase
// layout's double footprint). Remote tar exit 1 ("file changed as we read
// it", the open shard; GNU pads the entry to its header size) is expected.
func streamHostIntoTar(tw *tar.Writer, prefix, host string, files []string) (nfiles int, bytes int64, err error) {
	args := append(append([]string{}, sshArgs...), host,
		"sudo tar -cf - --absolute-names --warning=no-file-changed -T -")
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(strings.Join(files, "\n") + "\n")
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, 0, err
	}
	tr := tar.NewReader(pipe)
	for {
		hdr, rerr := tr.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return nfiles, bytes, fmt.Errorf("reading tar stream from %s: %v", host, rerr)
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
			cmd.Process.Kill()
			cmd.Wait()
			return nfiles, bytes, werr
		}
		n, werr := io.Copy(tw, tr)
		bytes += n
		if werr != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return nfiles, bytes, fmt.Errorf("writing %s: %v", hdr.Name, werr)
		}
		nfiles++
	}
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nfiles, bytes, nil // open shard changed mid-read — fine
		}
		return nfiles, bytes, fmt.Errorf("remote tar on %s: %v", host, err)
	}
	return nfiles, bytes, nil
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

// addBytesToTar writes an in-memory blob as a tar entry.
func addBytesToTar(tw *tar.Writer, b []byte, name string) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func writeCmdOutput(path string, name string, args ...string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
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
	_, err := weka("debug", "traces", "freeze", "set",
		"--start-time", from.UTC().Format("2006-01-02 15:04:05")+"Z",
		"--end-time", to.UTC().Format("2006-01-02 15:04:05")+"Z",
		"--retention", fmt.Sprintf("%dd", days),
		"--comment", fmt.Sprintf("offline_traces_uploader %s", time.Now().UTC().Format(time.RFC3339)))
	if err == nil {
		return nil
	}
	detail := ""
	if ee, ok := err.(*exec.ExitError); ok {
		detail = strings.TrimSpace(string(ee.Stderr))
	}
	if strings.Contains(detail, "already set") {
		return errFreezeExists
	}
	return fmt.Errorf("%v: %s", err, detail)
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
	rd := make([]byte, 256)
	n, _ := tty.Read(rd)
	user := strings.TrimSpace(string(rd[:n]))
	if user == "" {
		user = "admin"
	}
	fmt.Fprint(tty, "WEKA password: ")
	// no-echo via stty on the same tty; restored right after the read
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	n, _ = tty.Read(rd)
	exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	fmt.Fprintln(tty)
	pass := strings.TrimSpace(string(rd[:n]))
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
	out, err := weka("status", "-J")
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

func upload(o opts, tarPath, cluster string) error {
	object := fmt.Sprintf("%s/%s_%s.tar", o.customer, time.Now().UTC().Format("2006-01-02_150405"), cluster)
	url := strings.TrimRight(o.uploadURL, "/") + "/" + object
	fi, err := os.Stat(tarPath)
	if err != nil {
		return err
	}
	logf("uploading %s (%s) as: %s", tarPath, humanBytes(fi.Size()), object)

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		f, err := os.Open(tarPath)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPut, url, f)
		if err != nil {
			f.Close()
			return err
		}
		req.ContentLength = fi.Size()
		req.Header.Set("Content-Type", "application/x-tar")
		resp, err := (&http.Client{Timeout: 4 * time.Hour}).Do(req)
		f.Close()
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				logf("UPLOAD OK: %s", object)
				logf("local copy kept at %s — delete once WEKA confirms receipt", tarPath)
				return nil
			}
			lastErr = fmt.Errorf("upload got HTTP %d", resp.StatusCode)
			// 4xx = token expired/invalid/bad path; retrying won't help.
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				break
			}
		} else {
			lastErr = err
		}
		logf("upload attempt %d failed: %v", attempt, lastErr)
		time.Sleep(time.Duration(attempt*5) * time.Second)
	}
	return fmt.Errorf("upload failed: %v — tarball is still at %s", lastErr, tarPath)
}

func main() {
	var o opts
	flag.StringVar(&o.start, "start", "", "window start (any 'date -d' parsable string); required unless -from-freeze/-last")
	flag.StringVar(&o.end, "end", "", "window end (default: now)")
	flag.StringVar(&o.last, "last", "", "collect the last N of traces ending now, e.g. -last 60m or -last 2h (replaces -start/-end)")
	flag.BoolVar(&o.fromFreeze, "from-freeze", false, "use the existing freeze period as the window (sets nothing)")
	flag.BoolVar(&o.estimate, "estimate", false, "print per-host sizes and exit; nothing is copied")
	flag.StringVar(&o.dest, "dest", "/tmp", "output directory (peak usage ~2x the estimate)")
	flag.IntVar(&o.marginMin, "margin-min", 15, "margin in minutes added to each side of the window")
	flag.StringVar(&o.hosts, "hosts", "", "comma-separated hostnames (overrides discovery)")
	flag.BoolVar(&o.noFreeze, "no-freeze", false, "do not set a freeze for the window")
	flag.IntVar(&o.freezeDays, "freeze-days", 7, "freeze retention in days")
	flag.StringVar(&o.uploadURL, "upload", "", "WEKA-provided upload URL (write-only, expiring)")
	flag.StringVar(&o.customer, "customer", "", "customer name for the upload folder (required with -upload)")
	flag.BoolVar(&o.printVersion, "version", false, "print version and exit")
	flag.Parse()

	if o.printVersion {
		fmt.Println("offline_traces_uploader", version)
		return
	}
	if _, err := exec.LookPath("weka"); err != nil {
		die("weka CLI not found — run on a cluster backend")
	}
	if os.Geteuid() != 0 {
		die("run as root (sudo) — host discovery needs it, remote reads use remote sudo")
	}
	if o.uploadURL != "" {
		if o.customer == "" {
			die("-upload requires -customer <name>")
		}
		o.customer = strings.ToLower(o.customer)
		if !regexp.MustCompile(`^[a-z0-9._-]+$`).MatchString(o.customer) {
			die("-customer may only contain lowercase letters, digits, dot, dash, underscore")
		}
		if !strings.HasPrefix(o.uploadURL, "https://") || !strings.Contains(o.uploadURL, "/o") {
			die("-upload must be the URL WEKA handed you (https://...../o/)")
		}
	} else if o.customer != "" {
		die("-customer only makes sense together with -upload")
	}

	var startT, endT time.Time
	var err error
	switch {
	case o.last != "":
		if o.start != "" || o.end != "" || o.fromFreeze {
			die("-last replaces -start/-end/-from-freeze")
		}
		d, derr := time.ParseDuration(o.last)
		if derr != nil || d <= 0 {
			die("cannot parse -last %q (use e.g. 60m, 2h, 90m)", o.last)
		}
		endT = time.Now()
		startT = endT.Add(-d)
		logf("using the last %s (ending now)", d)
	case o.fromFreeze:
		if o.start != "" || o.end != "" {
			die("-from-freeze replaces -start/-end")
		}
		startT, endT, err = freezeWindow()
		if err != nil {
			die("%v", err)
		}
		logf("using existing freeze window: %s .. %s", startT.UTC().Format(time.RFC3339), endT.UTC().Format(time.RFC3339))
		o.noFreeze = true // already frozen — never overwrite
	case o.start != "":
		if startT, err = parseTime(o.start); err != nil {
			die("%v", err)
		}
		if o.end != "" {
			if endT, err = parseTime(o.end); err != nil {
				die("%v", err)
			}
		} else {
			endT = time.Now()
		}
	default:
		die("-start is required (or -from-freeze / -last 60m); see -h")
	}
	if !endT.After(startT) {
		die("-end must be after -start")
	}
	margin := time.Duration(o.marginMin) * time.Minute
	from, to := startT.Add(-margin), endT.Add(margin)
	logf("window: %s .. %s (±%dm margin)", from.Format("2006-01-02 15:04:05"), to.Format("2006-01-02 15:04:05"), o.marginMin)

	hosts := discoverHosts(o)
	if len(hosts) == 0 {
		die("host discovery came up empty (try -hosts)")
	}
	logf("hosts (%d): %s", len(hosts), strings.Join(hosts, " "))

	if o.estimate {
		var total int64
		for _, h := range hosts {
			files, err := remoteFilelist(h, from.Unix(), to.Unix())
			if err != nil {
				logf("[%s] %v", h, err)
				continue
			}
			n := remoteDu(h, files)
			total += n
			fmt.Printf("%-45s %14d  (%s)\n", h, n, humanBytes(n))
		}
		fmt.Printf("%-45s %14d  (%s)\n", "TOTAL", total, humanBytes(total))
		return
	}

	if !o.noFreeze {
		logf("freezing trace window cluster-wide (retention %dd) — needs weka login", o.freezeDays)
		err := setFreeze(from, to, o.freezeDays)
		if err != nil && err != errFreezeExists {
			// Most likely cause: no WEKA CLI login. When a human is at the
			// terminal, ask for the cluster credentials and retry once.
			if loginInteractively() {
				err = setFreeze(from, to, o.freezeDays)
			}
		}
		switch {
		case err == nil:
		case err == errFreezeExists:
			// Never override an existing freeze automatically — on a customer
			// cluster it may be WEKA support's. Say so and carry on.
			if fs, fe, ferr := freezeWindow(); ferr == nil {
				logf("NOTE: a freeze already exists (%s .. %s) and was left untouched.",
					fs.UTC().Format("2006-01-02 15:04"), fe.UTC().Format("2006-01-02 15:04"))
				logf("      Your window is only protected where it overlaps it. To collect the")
				logf("      frozen window instead, rerun with -from-freeze.")
			} else {
				logf("NOTE: a freeze already exists and was left untouched (rerun with -from-freeze to collect it).")
			}
		default:
			logf("WARNING: freeze failed (%v) — continuing WITHOUT freeze; retention may rotate shards away mid-copy", err)
			time.Sleep(5 * time.Second)
		}
	}

	cluster := clusterName()
	stamp := time.Now().Format("20060102-150405")
	prefix := fmt.Sprintf("weka-traces-%s-%s/", cluster, stamp)
	out := filepath.Join(o.dest, fmt.Sprintf("weka-traces-%s-%s.tar", cluster, stamp))

	// Everything streams straight into the final tarball — no work dir, so
	// peak disk usage is the tarball itself (field lesson: the old two-phase
	// layout needed double the space and filled a small /tmp). Only the tiny
	// metadata + ELF caches (~55MB) touch a staging dir, briefly.
	stage, err := os.MkdirTemp(o.dest, ".traces-stage-*")
	if err != nil {
		die("cannot create staging dir in %s: %v", o.dest, err)
	}
	defer os.RemoveAll(stage)

	f, err := os.Create(out)
	if err != nil {
		die("cannot create %s: %v", out, err)
	}
	tw := tar.NewWriter(f)

	logf("collecting cluster metadata")
	metaDir := filepath.Join(stage, "meta")
	elfDir := filepath.Join(stage, "elf_cache")
	os.MkdirAll(metaDir, 0755)
	os.MkdirAll(elfDir, 0755)
	collectMetadata(metaDir, o, from, to)
	logf("shipped elf caches: %d files", copyShippedElfCaches(elfDir))
	for _, d := range []string{"meta", "elf_cache"} {
		entries, _ := os.ReadDir(filepath.Join(stage, d))
		for _, e := range entries {
			if err := addFileToTar(tw, filepath.Join(stage, d, e.Name()), prefix+d+"/"+e.Name()); err != nil {
				die("writing %s into the tarball: %v", e.Name(), err)
			}
		}
	}

	// Hosts stream one after another: a single tar stream can only grow at
	// one end, and one intra-cluster ssh stream is plenty fast.
	failed := false
	for _, h := range hosts {
		files, err := remoteFilelist(h, from.Unix(), to.Unix())
		if err != nil {
			logf("[%s] FAILED: %v", h, err)
			failed = true
			continue
		}
		if len(files) == 0 {
			logf("[%s] WARNING: no shards matched the window", h)
		}
		addBytesToTar(tw, []byte(strings.Join(files, "\n")+"\n"), prefix+"hosts/"+h+"/filelist.txt")
		logf("[%s] streaming %d files...", h, len(files))
		n, sz, err := streamHostIntoTar(tw, prefix, h, files)
		if err != nil {
			logf("[%s] FAILED mid-stream (%d files, %s in): %v", h, n, humanBytes(sz), err)
			failed = true
			continue
		}
		logf("[%s] %d files, %s", h, n, humanBytes(sz))
	}
	if failed {
		logf("WARNING: one or more hosts failed — check output above")
	}

	if err := tw.Close(); err != nil {
		die("finalizing tarball: %v", err)
	}
	if err := f.Close(); err != nil {
		die("closing tarball: %v", err)
	}
	fi, _ := os.Stat(out)
	logf("DONE: %s (%s)", out, humanBytes(fi.Size()))

	if o.uploadURL != "" {
		if err := upload(o, out, cluster); err != nil {
			die("%v", err)
		}
	} else {
		logf("Ship this single file — per-host shards + ELF caches + cluster metadata.")
	}
}
