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
// Two modes:
//
//	-upload (connected cluster): every host streams straight into its own
//	object in WEKA's bucket (<customer>/<stamp>_<cluster>/hosts/<host>.tar),
//	a few hosts at a time, as multipart uploads. Nothing touches the local
//	disk, there is no size cap, a silent host is dropped after -stall instead
//	of freezing the run, and a live progress.json lets WEKA watch the run.
//
//	no -upload (dark site): one tarball in -dest, after checking it fits and
//	is not on a WEKA filesystem. Carry it out and push it with -upload-file
//	(any Linux box with internet) or the dialog's "Upload from local".
//
// The upload URL is a write-only, expiring token handed out by WEKA per
// engagement. It can only PUT objects — it cannot list or read anything.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var version = "dev" // stamped at build time via -ldflags "-X main.version=..."

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
	printVersion bool
	parallel     int
	inflight     int
	partMiB      int
	stall        time.Duration
	drop         string
	uploadFile   string
}

func logf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stderr, "[%s] %s\n", ts, line)
	remember("[" + ts + "] " + line)
}

func die(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "ERROR: %s\n", msg)
	remember("ERROR: " + msg)
	if prog != nil {
		prog.finish("failed", firstLine(msg))
	}
	os.Exit(1)
}

var dropNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func safeName(s string) string {
	s = regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(s, "-")
	if s == "" {
		return "cluster"
	}
	return s
}

func pickPartSize(est int64, minMiB int) int64 {
	ps := int64(minMiB) << 20
	// stay well under OCI's 10,000-part ceiling even if the host grows 30%
	if need := est * 13 / 10 / 9000; need > ps {
		ps = (need + (1<<20 - 1)) &^ (1<<20 - 1)
	}
	if ps > 1<<30 {
		ps = 1 << 30
	}
	return ps
}

func main() {
	var o opts
	flag.StringVar(&o.start, "start", "", "window start (any 'date -d' parsable string); required unless -from-freeze/-last")
	flag.StringVar(&o.end, "end", "", "window end (default: now)")
	flag.StringVar(&o.last, "last", "", "collect the last N of traces ending now, e.g. -last 60m or -last 2h (replaces -start/-end)")
	flag.BoolVar(&o.fromFreeze, "from-freeze", false, "use the existing freeze period as the window (sets nothing)")
	flag.BoolVar(&o.estimate, "estimate", false, "print per-host sizes and exit; nothing is copied")
	flag.StringVar(&o.dest, "dest", "/tmp", "output directory for the tarball when NOT uploading (needs the full size free)")
	flag.IntVar(&o.marginMin, "margin-min", 15, "margin in minutes added to each side of the window")
	flag.StringVar(&o.hosts, "hosts", "", "comma-separated hostnames (overrides discovery)")
	flag.BoolVar(&o.noFreeze, "no-freeze", false, "do not set a freeze for the window")
	flag.IntVar(&o.freezeDays, "freeze-days", 7, "freeze retention in days")
	flag.StringVar(&o.uploadURL, "upload", "", "WEKA-provided upload URL (write-only, expiring)")
	flag.StringVar(&o.customer, "customer", "", "customer name for the upload folder (required with -upload)")
	flag.BoolVar(&o.printVersion, "version", false, "print version and exit")
	flag.IntVar(&o.parallel, "parallel", 3, "hosts uploaded at the same time (with -upload)")
	flag.IntVar(&o.inflight, "inflight", 3, "upload parts in flight per host (RAM use ~ parallel x (inflight+1) x part size)")
	flag.IntVar(&o.partMiB, "part-mib", 32, "upload part size in MiB (raised automatically for very large hosts)")
	flag.DurationVar(&o.stall, "stall", 3*time.Minute, "give up on a host that sends nothing for this long")
	flag.StringVar(&o.drop, "drop", "", "add to an existing drop (re-collect failed hosts; the summary prints the exact command)")
	flag.StringVar(&o.uploadFile, "upload-file", "", "upload an already-collected tarball (no cluster or root needed); use with -upload and -customer")
	flag.Parse()

	if o.printVersion {
		fmt.Println("offline_traces_uploader", version)
		return
	}
	if o.uploadURL != "" || o.uploadFile != "" {
		if o.uploadURL == "" {
			die("-upload-file needs -upload <URL> as well")
		}
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
	if o.drop != "" && !dropNameRe.MatchString(o.drop) {
		die("-drop must be the drop name from the earlier run's summary (letters, digits, . _ -)")
	}
	if o.parallel < 1 || o.inflight < 1 || o.partMiB < 8 || o.stall < 10*time.Second {
		die("-parallel/-inflight must be >= 1, -part-mib >= 8, -stall >= 10s")
	}

	if o.uploadFile != "" {
		uploadFile(o)
		return
	}

	if _, err := exec.LookPath("weka"); err != nil {
		die("weka CLI not found — run on a cluster backend")
	}
	if os.Geteuid() != 0 {
		die("run as root (sudo) — host discovery needs it, remote reads use remote sudo")
	}

	// Connected mode: open the status beacon FIRST, so even a run that dies
	// at discovery or the freeze is visible to WEKA, with its output.
	var pc *parClient
	var dropName, dropPrefix string
	cluster := ""
	if !o.estimate {
		cluster = clusterName() // bounded: weka status may hang on a sick cluster
	}
	if o.uploadURL != "" && !o.estimate {
		var err error
		if pc, err = newPARClient(o.uploadURL); err != nil {
			die("%v", err)
		}
		dropName = o.drop
		if dropName == "" {
			dropName = time.Now().UTC().Format("2006-01-02_150405") + "_" + safeName(cluster)
		}
		dropPrefix = o.customer + "/" + dropName + "/"
		host, _ := os.Hostname()
		url := o.uploadURL
		redact := func(s string) string { return strings.ReplaceAll(s, url, "<upload-url>") }
		b := newBeacon(pc, dropPrefix, progressDoc{
			Version: version, Customer: o.customer, Cluster: cluster, Drop: dropName,
			RunsOn: host, Command: strings.Join(os.Args, " "), State: "starting",
		}, redact)
		if o.drop != "" {
			b.object = dropPrefix + "progress-" + time.Now().UTC().Format("150405") + ".json"
		}
		// The first write doubles as the upload-code check: an expired code
		// fails here, before anything is collected.
		if err := b.flush(60 * time.Second); err != nil {
			var oe *ociError
			if errors.As(err, &oe) && oe.status < 500 {
				die("the upload code was refused — nothing was collected: %v", err)
			}
			logf("WARNING: cannot reach WEKA's bucket yet (%v) — continuing, uploads retry on their own", err)
		}
		prog = b
		prog.run(10 * time.Second)
		logf("WEKA can follow this run live (drop %s)", dropPrefix)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() {
			s := <-sig
			logf("interrupted (%v) — stopping; already-finished hosts stay uploaded", s)
			prog.finish("interrupted", "stopped by the operator")
			os.Exit(130)
		}()
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
	logf("window: %s .. %s UTC (±%dm margin)", from.UTC().Format("2006-01-02 15:04:05"), to.UTC().Format("2006-01-02 15:04:05"), o.marginMin)
	prog.update(func(d *progressDoc) {
		d.From, d.To = from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339)
		d.State = "discovering"
	})

	hosts := discoverHosts(o)
	if len(hosts) == 0 {
		die("host discovery came up empty (try -hosts)")
	}
	logf("hosts (%d): %s", len(hosts), strings.Join(hosts, " "))
	for _, h := range hosts {
		prog.hostDo(h, func(hp *hostProgress) { hp.State = "listing" })
	}
	prog.update(func(d *progressDoc) { d.State = "listing" })

	logf("listing + sizing the window on every host...")
	plans := planHosts(hosts, from.Unix(), to.Unix(), 8)
	var total int64
	for _, p := range plans {
		p := p
		if p.err != nil {
			logf("[%s] cannot list: %v", p.name, p.err)
		} else {
			if len(p.files) == 0 {
				logf("[%s] WARNING: no trace files found", p.name)
			}
			total += p.est
		}
		prog.hostDo(p.name, func(hp *hostProgress) {
			hp.Files, hp.EstBytes = len(p.files), p.est
			if p.err != nil {
				hp.State, hp.Error = "failed", p.err.Error()
			} else {
				hp.State = "queued"
			}
		})
	}
	if o.estimate {
		for _, p := range plans {
			if p.err != nil {
				fmt.Printf("%-45s %14s  (%v)\n", p.name, "-", p.err)
				continue
			}
			fmt.Printf("%-45s %14d  (%s, %d files)\n", p.name, p.est, humanBytes(p.est), len(p.files))
		}
		fmt.Printf("%-45s %14d  (%s)\n", "TOTAL", total, humanBytes(total))
		return
	}
	logf("total to collect: %s across %d hosts", humanBytes(total), len(hosts))
	prog.update(func(d *progressDoc) { d.EstTotal = total })

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

	stamp := time.Now().Format("20060102-150405")
	prefix := fmt.Sprintf("weka-traces-%s-%s/", safeName(cluster), stamp)

	// Metadata + shipped ELF caches (~55MB) — small, staged briefly.
	stage, err := os.MkdirTemp("", ".traces-stage-*")
	if err != nil {
		die("cannot create a staging dir: %v", err)
	}
	defer os.RemoveAll(stage)
	logf("collecting cluster metadata")
	metaDir := filepath.Join(stage, "meta")
	elfDir := filepath.Join(stage, "elf_cache")
	os.MkdirAll(metaDir, 0755)
	os.MkdirAll(elfDir, 0755)
	collectMetadata(metaDir, o, from, to)
	logf("shipped elf caches: %d files", copyShippedElfCaches(elfDir))
	writeMeta := func(tw *tar.Writer) {
		for _, d := range []string{"meta", "elf_cache"} {
			entries, _ := os.ReadDir(filepath.Join(stage, d))
			for _, e := range entries {
				if err := addFileToTar(tw, filepath.Join(stage, d, e.Name()), prefix+d+"/"+e.Name()); err != nil {
					die("writing %s into the tarball: %v", e.Name(), err)
				}
			}
		}
	}

	if pc != nil {
		os.Exit(runUpload(o, pc, dropName, dropPrefix, prefix, plans, from, to, writeMeta))
	}
	runLocal(o, cluster, stamp, prefix, plans, total, writeMeta)
}

// runUpload streams every host into its own object, o.parallel at a time.
// Returns the process exit code: 0 all hosts landed, 3 partial.
func runUpload(o opts, pc *parClient, dropName, dropPrefix, prefix string, plans []hostPlan,
	from, to time.Time, writeMeta func(*tar.Writer)) int {
	prog.update(func(d *progressDoc) { d.State = "collecting" })

	var mb bytes.Buffer
	mtw := tar.NewWriter(&mb)
	writeMeta(mtw)
	mtw.Close()
	if _, err := pc.uploadStream(context.Background(), dropPrefix+"meta.tar", bytes.NewReader(mb.Bytes()),
		32<<20, 2, nil); err != nil {
		die("uploading cluster metadata: %v", err)
	}
	logf("metadata uploaded (%s)", humanBytes(int64(mb.Len())))

	var (
		uploadedAll int64
		mu          sync.Mutex
		failed      []string
		okCount     int
		okBytes     int64
	)
	startAll := time.Now()
	var estTotal int64
	for _, p := range plans {
		if p.err == nil {
			estTotal += p.est
		}
	}

	// Terminal heartbeat every 30s: what's moving and how fast.
	hbDone := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-hbDone:
				return
			case <-t.C:
				up := atomic.LoadInt64(&uploadedAll)
				el := time.Since(startAll).Seconds()
				rate := float64(up) / el
				eta := ""
				if rate > 0 && estTotal > up {
					eta = fmt.Sprintf(", ETA ~%s", (time.Duration(float64(estTotal-up)/rate) * time.Second).Round(time.Minute))
				}
				mu.Lock()
				done := okCount + len(failed)
				mu.Unlock()
				logf("progress: %d/%d hosts finished, %s of ~%s uploaded (%.0f MB/s%s)",
					done, len(plans), humanBytes(up), humanBytes(estTotal), rate/1e6, eta)
			}
		}
	}()

	jobs := make(chan hostPlan)
	var wg sync.WaitGroup
	for w := 0; w < o.parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				n, err := uploadHost(o, pc, dropPrefix, prefix, p, &uploadedAll)
				mu.Lock()
				if err != nil {
					failed = append(failed, p.name)
				} else {
					okCount++
					okBytes += n
				}
				mu.Unlock()
			}
		}()
	}
	for _, p := range plans {
		if p.err != nil {
			mu.Lock()
			failed = append(failed, p.name)
			mu.Unlock()
			continue
		}
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(hbDone)

	sort.Strings(failed)
	el := time.Since(startAll).Round(time.Second)
	if len(failed) == 0 {
		logf("UPLOAD OK: all %d hosts, %s in %s — drop %s", okCount, humanBytes(okBytes), el, dropPrefix)
		logf("WEKA sees it now in the Offline Traces dialog; nothing was written to this host's disk.")
		prog.finish("done", fmt.Sprintf("all %d hosts uploaded (%s)", okCount, humanBytes(okBytes)))
		return 0
	}
	rerun := fmt.Sprintf("sudo %s -start '%s UTC' -end '%s UTC' -margin-min 0 -no-freeze -drop '%s' -hosts '%s' -customer '%s' -upload '%s'",
		os.Args[0], from.UTC().Format("2006-01-02 15:04:05"), to.UTC().Format("2006-01-02 15:04:05"),
		dropName, strings.Join(failed, ","), o.customer, o.uploadURL)
	logf("PARTIAL: %d of %d hosts uploaded (%s); failed: %s", okCount, len(plans), humanBytes(okBytes), strings.Join(failed, " "))
	logf("Everything that finished is already with WEKA. To retry ONLY the failed hosts into the same drop:")
	fmt.Fprintln(os.Stderr, "\n  "+rerun+"\n")
	prog.update(func(d *progressDoc) { d.Rerun = rerun })
	prog.finish("partial", fmt.Sprintf("%d of %d hosts uploaded; failed: %s", okCount, len(plans), strings.Join(failed, " ")))
	return 3
}

// uploadHost pipes one host's remote tar stream straight into a multipart
// upload of <drop>/hosts/<host>.tar. Nothing is staged on disk.
func uploadHost(o opts, pc *parClient, dropPrefix, prefix string, p hostPlan, uploadedAll *int64) (int64, error) {
	return uploadHostWithPart(o, pc, dropPrefix, prefix, p, uploadedAll, pickPartSize(p.est, o.partMiB))
}

func uploadHostWithPart(o opts, pc *parClient, dropPrefix, prefix string, p hostPlan, uploadedAll *int64, partSize int64) (int64, error) {
	h := p.name
	started := time.Now()
	prog.hostDo(h, func(hp *hostProgress) {
		hp.State, hp.Started, hp.Error = "streaming", started.UTC().Format(time.RFC3339), ""
		hp.ReadBytes, hp.UploadedBytes = 0, 0
	})
	logf("[%s] streaming %d files (~%s) to WEKA...", h, len(p.files), humanBytes(p.est))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	var read int64
	type res struct {
		n   int
		sz  int64
		err error
	}
	done := make(chan res, 1)
	go func() {
		tw := tar.NewWriter(pw)
		err := addBytesToTar(tw, []byte(strings.Join(p.files, "\n")+"\n"), prefix+"hosts/"+h+"/filelist.txt")
		var n int
		var sz int64
		if err == nil {
			n, sz, err = streamHostIntoTar(ctx, tw, prefix, h, p.files, o.stall, &read)
		}
		if err == nil {
			err = tw.Close()
		}
		if err != nil {
			pw.CloseWithError(fmt.Errorf("collecting from %s: %w", h, err))
		} else {
			pw.Close()
		}
		done <- res{n, sz, err}
	}()

	// Mirror read progress into the beacon while it runs.
	pdone := make(chan struct{})
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pdone:
				return
			case <-t.C:
				r := atomic.LoadInt64(&read)
				prog.hostDo(h, func(hp *hostProgress) { hp.ReadBytes = r })
			}
		}
	}()

	var up int64
	_, uerr := pc.uploadStream(ctx, dropPrefix+"hosts/"+h+".tar", pr,
		partSize, o.inflight, func(n int64) {
			atomic.AddInt64(&up, n)
			atomic.AddInt64(uploadedAll, n)
			v := atomic.LoadInt64(&up)
			prog.hostDo(h, func(hp *hostProgress) { hp.UploadedBytes = v })
		})
	if uerr != nil {
		cancel() // stop the remote tar
	}
	pr.CloseWithError(errors.New("upload stopped"))
	r := <-done
	close(pdone)

	el := time.Since(started)
	finished := time.Now().UTC().Format(time.RFC3339)
	// Which side failed first decides the message: a stalled host, else the
	// upload's own error (which already carries a collection error that
	// ended the stream), else the collection error.
	var ferr error
	state := "failed"
	switch {
	case r.err != nil && errors.Is(r.err, errStalled):
		ferr, state = r.err, "stalled"
	case uerr != nil:
		ferr = uerr
	case r.err != nil:
		ferr = r.err
	}
	if ferr != nil {
		logf("[%s] FAILED: %v", h, ferr)
		prog.hostDo(h, func(hp *hostProgress) { hp.State, hp.Error, hp.Finished = state, oneLine(ferr.Error()), finished })
		return 0, ferr
	}
	u := atomic.LoadInt64(&up)
	logf("[%s] done: %d files, %s in %s (%.0f MB/s)", h, r.n, humanBytes(u), el.Round(time.Second), float64(u)/el.Seconds()/1e6)
	prog.hostDo(h, func(hp *hostProgress) {
		hp.State, hp.Finished, hp.ReadBytes, hp.UploadedBytes = "done", finished, atomic.LoadInt64(&read), u
	})
	return u, nil
}

// runLocal (dark site): one tarball in -dest. Refuses to start when it would
// not fit, or when -dest is on a WEKA filesystem (in an incident, writes
// there can hang) — instead of filling a production backend's disk halfway.
func runLocal(o opts, cluster, stamp, prefix string, plans []hostPlan, total int64, writeMeta func(*tar.Writer)) {
	if err := os.MkdirAll(o.dest, 0755); err != nil {
		die("cannot use -dest %s: %v", o.dest, err)
	}
	if mnt, fst := mountOf(o.dest); fst == "wekafs" {
		die("-dest %s is on a WEKA filesystem (%s). During an incident writes there can hang —\n"+
			"  point -dest at a local disk with %s free.", o.dest, mnt, humanBytes(total))
	}
	need := total + 128<<20
	avail, size, err := freeSpace(o.dest)
	if err == nil {
		reserve := size / 10 // never take the filesystem past 90%
		if reserve < 2<<30 {
			reserve = 2 << 30
		}
		if avail-need < reserve {
			die("-dest %s has %s free; this collection needs %s and must leave %s spare.\n"+
				"  Options: -dest <a bigger local disk>, -hosts <fewer hosts>, a smaller -margin-min,\n"+
				"  or upload directly with -upload (writes nothing locally). Per-host sizes: run with -estimate.",
				o.dest, humanBytes(avail), humanBytes(need), humanBytes(reserve))
		}
	}

	out := filepath.Join(o.dest, fmt.Sprintf("weka-traces-%s-%s.tar", safeName(cluster), stamp))
	f, err := os.Create(out)
	if err != nil {
		die("cannot create %s: %v", out, err)
	}
	tw := tar.NewWriter(f)
	writeMeta(tw)

	// Hosts stream one after another: a single tar stream can only grow at
	// one end, and one intra-cluster ssh stream is plenty fast.
	var failed []string
	for _, p := range plans {
		h := p.name
		if p.err != nil {
			failed = append(failed, h)
			continue
		}
		addBytesToTar(tw, []byte(strings.Join(p.files, "\n")+"\n"), prefix+"hosts/"+h+"/filelist.txt")
		logf("[%s] streaming %d files (~%s)...", h, len(p.files), humanBytes(p.est))
		n, sz, err := streamHostIntoTar(context.Background(), tw, prefix, h, p.files, o.stall, nil)
		if err != nil {
			logf("[%s] FAILED (%d files, %s in): %v", h, n, humanBytes(sz), err)
			failed = append(failed, h)
			if !errors.Is(err, errStalled) && strings.Contains(err.Error(), "writing ") {
				// a local write error (disk full) poisons the archive — stop
				tw.Close()
				f.Close()
				die("cannot keep writing %s: %v", out, err)
			}
			continue
		}
		logf("[%s] %d files, %s", h, n, humanBytes(sz))
	}
	if err := tw.Close(); err != nil {
		die("finalizing tarball: %v", err)
	}
	if err := f.Close(); err != nil {
		die("closing tarball: %v", err)
	}
	fi, _ := os.Stat(out)
	if err := verifyTarEnd(out); err != nil {
		die("the tarball failed its end-of-archive check (%v) — do not ship it", err)
	}
	logf("DONE: %s (%s, %d bytes)", out, humanBytes(fi.Size()), fi.Size())
	if len(failed) > 0 {
		sort.Strings(failed)
		logf("WARNING: these hosts are NOT in the tarball: %s (rerun with -hosts for them)", strings.Join(failed, ","))
	}
	logf("verified: archive ends cleanly. CONFIRM THE BYTE COUNT after every copy hop —")
	logf("a cut transfer leaves a tarball that looks fine until extraction (field lesson).")
	logf("To send it to WEKA from any Linux box with internet:")
	logf("  ./offline_traces_uploader -upload-file %s -customer <name> -upload '<URL from WEKA>'", filepath.Base(out))
}

// uploadFile pushes an existing tarball (dark-site carry-out, or a v0.1.x
// leftover) in parallel parts. No cluster, no root.
func uploadFile(o opts) {
	fi, err := os.Stat(o.uploadFile)
	if err != nil {
		die("%v", err)
	}
	if err := verifyTarEnd(o.uploadFile); err != nil {
		die("%s is not a complete tarball (%v) — copy it again and compare the byte count", o.uploadFile, err)
	}
	pc, err := newPARClient(o.uploadURL)
	if err != nil {
		die("%v", err)
	}
	base := safeName(strings.TrimSuffix(filepath.Base(o.uploadFile), ".tar")) + ".tar"
	object := fmt.Sprintf("%s/%s_%s", o.customer, time.Now().UTC().Format("2006-01-02_150405"), base)
	f, err := os.Open(o.uploadFile)
	if err != nil {
		die("%v", err)
	}
	defer f.Close()
	logf("uploading %s (%s) as %s", o.uploadFile, humanBytes(fi.Size()), object)
	var up int64
	start := time.Now()
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				u := atomic.LoadInt64(&up)
				rate := float64(u) / time.Since(start).Seconds()
				eta := ""
				if rate > 0 {
					eta = fmt.Sprintf(", ETA ~%s", (time.Duration(float64(fi.Size()-u)/rate) * time.Second).Round(time.Second))
				}
				logf("  %s / %s (%.0f%%, %.1f MB/s%s)", humanBytes(u), humanBytes(fi.Size()),
					float64(u)*100/float64(fi.Size()), rate/1e6, eta)
			}
		}
	}()
	_, err = pc.uploadStream(context.Background(), object, f, pickPartSize(fi.Size(), o.partMiB), 4,
		func(n int64) { atomic.AddInt64(&up, n) })
	close(stop)
	if err != nil {
		die("upload failed: %v — the file is untouched, just run the same command again", err)
	}
	logf("UPLOAD OK: %s (%s in %s) — WEKA sees it in the Offline Traces dialog now",
		object, humanBytes(fi.Size()), time.Since(start).Round(time.Second))
}
