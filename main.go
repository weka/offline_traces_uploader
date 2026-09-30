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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var version = "dev" // stamped at build time via -ldflags "-X main.version=..."

const selectScript = `
FROM_EPOCH="$1"; TO_EPOCH="$2"
for d in /opt/weka/traces /opt/weka/wtracer/traces; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f -name '*.shard' \
       -newermt "@$FROM_EPOCH" ! -newermt "@$TO_EPOCH" 2>/dev/null
  find "$d" -maxdepth 1 -type f -name '*cache*' 2>/dev/null
  find "$d" -maxdepth 2 -type f -name 'config.json' 2>/dev/null
  ls -1t "$d"/*.shard 2>/dev/null | head -1
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

// remoteTar streams `sudo tar` of the file list on host into dst.
// tar exit code 1 ("file changed as we read it", the open shard) is expected.
func remoteTar(host string, files []string, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	args := append(append([]string{}, sshArgs...), host,
		"sudo tar -cf - --absolute-names --warning=no-file-changed -T -")
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = strings.NewReader(strings.Join(files, "\n") + "\n")
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nil // open shard changed mid-read — fine
		}
		return fmt.Errorf("streaming tar from %s: %v", host, err)
	}
	return nil
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
	flag.StringVar(&o.start, "start", "", "window start (any 'date -d' parsable string); required unless -from-freeze")
	flag.StringVar(&o.end, "end", "", "window end (default: now)")
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
		die("-start is required (or -from-freeze); see -h")
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
		_, err := weka("debug", "traces", "freeze", "set",
			"--start-time", from.UTC().Format("2006-01-02 15:04:05")+"Z",
			"--end-time", to.UTC().Format("2006-01-02 15:04:05")+"Z",
			"--retention", fmt.Sprintf("%dd", o.freezeDays),
			"--comment", fmt.Sprintf("offline_traces_uploader %s", time.Now().UTC().Format(time.RFC3339)))
		if err != nil {
			logf("WARNING: freeze failed (not logged in?) — continuing WITHOUT freeze; retention may rotate shards away mid-copy")
			time.Sleep(5 * time.Second)
		}
	}

	cluster := clusterName()
	stamp := time.Now().Format("20060102-150405")
	work := filepath.Join(o.dest, fmt.Sprintf("weka-traces-%s-%s", cluster, stamp))
	for _, d := range []string{"meta", "hosts", "elf_cache"} {
		if err := os.MkdirAll(filepath.Join(work, d), 0755); err != nil {
			die("cannot create %s: %v", work, err)
		}
	}

	logf("collecting cluster metadata")
	collectMetadata(filepath.Join(work, "meta"), o, from, to)
	logf("shipped elf caches: %d files", copyShippedElfCaches(filepath.Join(work, "elf_cache")))

	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := false
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			hdir := filepath.Join(work, "hosts", h)
			os.MkdirAll(hdir, 0755)
			files, err := remoteFilelist(h, from.Unix(), to.Unix())
			if err != nil {
				logf("[%s] FAILED: %v", h, err)
				mu.Lock()
				failed = true
				mu.Unlock()
				return
			}
			os.WriteFile(filepath.Join(hdir, "filelist.txt"), []byte(strings.Join(files, "\n")+"\n"), 0644)
			if len(files) == 0 {
				logf("[%s] WARNING: no shards matched the window", h)
			}
			dst := filepath.Join(hdir, "traces.tar")
			if err := remoteTar(h, files, dst); err != nil {
				logf("[%s] FAILED: %v", h, err)
				mu.Lock()
				failed = true
				mu.Unlock()
				return
			}
			fi, _ := os.Stat(dst)
			var sz int64
			if fi != nil {
				sz = fi.Size()
			}
			logf("[%s] %d files, %s", h, len(files), humanBytes(sz))
		}(h)
	}
	wg.Wait()
	if failed {
		logf("WARNING: one or more hosts failed — check output above")
	}

	out := filepath.Join(o.dest, fmt.Sprintf("weka-traces-%s-%s.tar", cluster, stamp))
	logf("packing %s", out)
	cmd := exec.Command("tar", "-C", o.dest, "-cf", out, filepath.Base(work))
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		die("packing failed: %v", err)
	}
	os.RemoveAll(work)
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
