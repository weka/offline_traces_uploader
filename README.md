# offline_traces_uploader

Collect WEKA trace shards from a cluster and upload them to WEKA for offline
analysis — one command.

WEKA support hands you an **upload code** (an expiring, write-only URL). You
run `offline_traces_uploader` on **one backend** of the cluster; it gathers the
trace window from every backend and streams each host straight to WEKA.
Nothing else leaves the cluster, and the upload code cannot read or list
anything — it can only deposit files.

## Quick start

```bash
# download a prebuilt binary (or build from source: go build .)
curl -fsSLo offline_traces_uploader https://github.com/weka/offline_traces_uploader/releases/latest/download/offline_traces_uploader-linux-amd64
chmod +x offline_traces_uploader

# incident window already frozen? (weka debug traces freeze show)
sudo ./offline_traces_uploader -from-freeze -customer '<your-company>' -upload '<upload-code-from-weka>'

# otherwise pick the window yourself
sudo ./offline_traces_uploader -last 60m \
     -customer '<your-company>' -upload '<upload-code-from-weka>'

# size check first — copies nothing
sudo ./offline_traces_uploader -from-freeze -estimate
```

## What happens during an upload (v0.2+)

- Every host streams **directly** into its own object at WEKA, a few hosts at a
  time, in 32 MiB pieces that each retry on their own. **Nothing is written to
  the local disk**, and there is no size limit (v0.1.x sent one tarball in a
  single request, which the cloud refuses above 50 GiB).
- WEKA support sees the run **live** — per-host progress and the tool's own
  output — so nobody has to guess whether anything is arriving.
- A host that sends nothing for 3 minutes (`-stall`) is skipped instead of
  freezing the whole run. Everything that finished stays uploaded, and the
  summary prints the exact command that re-collects only the missing hosts into
  the same upload (`-drop`).
- Every WEKA CLI call and every ssh has a deadline; a sick cluster can slow the
  tool down but not hang it.
- Exit codes: `0` all hosts uploaded, `3` partial (re-run command printed), `1` error.

## Dark sites (no internet on the cluster)

Collect without `-upload`; one tarball lands in `-dest` (default `/tmp`). The
tool checks first that it fits (and leaves 10% of the filesystem free) and
refuses a WEKA filesystem as the destination. Carry the tarball out and send
it from any machine with internet:

```bash
./offline_traces_uploader -upload-file weka-traces-<cluster>-<stamp>.tar \
     -customer '<your-company>' -upload '<upload-code-from-weka>'
```

`-upload-file` needs no cluster and no root; binaries for Linux and macOS are
on the releases page.

## Requirements

- Run on one **backend** of the cluster, as root (`sudo`).
- The backends can ssh each other (the same path `weka debug pdsh` uses — if
  `sudo weka debug pdsh -- hostname` prints every backend, you are good). If
  host discovery fails (the tool prints why), pass `-hosts a,b,c`.
- The remote ssh user can `sudo` without a password.
- Freezing or reading the freeze window needs a logged-in WEKA CLI
  (`weka user login`); collection itself does not.
- Outbound HTTPS for the upload.
- RAM: about `-parallel` x (`-inflight`+1) x 32 MiB (~400 MiB with defaults).

## What it collects

Per backend: trace shards (`/opt/weka/traces`, plus `/opt/weka/wtracer/traces`
where present) whose time falls in the window ±15 min, the ELF decode caches
sitting in those directories, and the trace-dumper `config.json` files. Only if
a host has nothing in the window, the newest shard of every trace stream
instead. Once per run: the shipped ELF caches from the WEKA container image
(~55 MB) and cluster metadata (`weka version`, `weka status`, container/process
maps, traces config, freeze state, the window itself).

`-estimate` is an upper bound: shards still being written are preallocated at
64 MiB and shrink to their real size when they close.

## Flags

```
-start / -end     collection window ('date -d' syntax; -end defaults to now)
-last 60m         the last N minutes/hours, ending now
-from-freeze      use the cluster's existing freeze period as the window
-estimate         print per-host sizes and exit
-margin-min N     window margin on each side (default 15)
-hosts a,b,c      override host discovery
-no-freeze        don't set a freeze first
-freeze-days N    freeze retention when one is set (default 7)
-customer NAME    folder your upload lands in (required with -upload)
-upload URL       the write-only upload code from WEKA
-parallel N       hosts uploading at once (default 3)
-inflight N       pieces in flight per host (default 3)
-part-mib N       piece size in MiB (default 32, raised automatically for huge hosts)
-stall DUR        skip a host that sends nothing for this long (default 3m)
-drop NAME        add hosts to an earlier upload (the summary prints the command)
-dest DIR         dark site: where the tarball lands (default /tmp)
-upload-file F    send an already-collected tarball (no cluster, no root)
-version          print version
```

## Security notes

- The upload code is scoped **write-only**: it cannot list the bucket or read
  any object, including the ones you just uploaded. It expires automatically
  (72 hours by default).
- `offline_traces_uploader` contains no credentials. The only secret involved
  is the upload code you were handed, passed on the command line; it is never
  written into the status WEKA sees.
- Uploads land in a private WEKA bucket and are automatically deleted after
  180 days.

## Build from source

```bash
CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=0.2.0" -o offline_traces_uploader .
go test ./...
```

Static binary, stdlib only; linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.
