# offline_traces_uploader

Collect WEKA trace shards from a cluster and upload them to WEKA for offline
analysis — one command, one tarball.

WEKA support hands you an **upload code** (an expiring, write-only URL). You
run `offline_traces_uploader` on **one backend** of the cluster; it gathers the trace window
from every backend, packs a single tarball, and uploads it. Nothing else
leaves the cluster, and the upload code cannot read or list anything — it can
only deposit files.

## Quick start

```bash
# download a prebuilt binary (or build from source: go build .)
curl -fsSLo offline_traces_uploader https://github.com/weka/offline_traces_uploader/releases/latest/download/offline_traces_uploader-linux-amd64
chmod +x offline_traces_uploader

# incident window already frozen? (weka debug traces freeze show)
sudo ./offline_traces_uploader -from-freeze -customer '<your-company>' -upload '<upload-code-from-weka>'

# otherwise pick the window yourself
sudo ./offline_traces_uploader -start '2026-09-30 14:00' -end '2026-09-30 14:30' \
     -customer '<your-company>' -upload '<upload-code-from-weka>'

# size check first — copies nothing
sudo ./offline_traces_uploader -from-freeze -estimate
```

## Requirements

- Run on one **backend** of the cluster, as root (`sudo`).
- The backends can ssh each other (the same path `weka debug pdsh` uses — if
  `sudo weka debug pdsh -- hostname` prints every backend, you are good).
- The remote ssh user can `sudo` without a password.
- Freezing or reading the freeze window needs a logged-in WEKA CLI
  (`weka user login`); collection itself does not.
- Outbound HTTPS for the upload (or run without `-upload` and ship the
  tarball from `/tmp` yourself).

## What it collects

Per backend: trace shards (`/opt/weka/traces`, plus `/opt/weka/wtracer/traces`
where present) covering the window ±15 min, the ELF decode caches sitting in
those directories, and the trace-dumper `config.json` files. Once per run:
the shipped ELF caches from the WEKA container image (~55 MB) and cluster
metadata (`weka version`, `weka status`, container/process maps, traces
config, freeze state, the window itself).

Rule of thumb at LOW trace verbosity: **~45 MB per minute per host** — a
30-minute window on 8 backends is roughly 12 GB, not hundreds.

## Flags

```
-start / -end     collection window ('date -d' syntax; -end defaults to now)
-from-freeze      use the cluster's existing freeze period as the window
-estimate         print per-host sizes and exit
-margin-min N     window margin on each side (default 15)
-dest DIR         where the tarball lands (default /tmp; needs ~2x estimate)
-hosts a,b,c      override host discovery
-no-freeze        don't set a freeze first
-freeze-days N    freeze retention when one is set (default 7)
-customer NAME    folder your upload lands in (required with -upload)
-upload URL       the write-only upload code from WEKA
-version          print version
```

## Security notes

- The upload code is scoped **write-only**: it cannot list the bucket or read
  any object, including the one you just uploaded. It expires automatically
  (72 hours by default).
- `offline_traces_uploader` contains no credentials. The only secret involved is the upload
  code you were handed, passed on the command line.
- Uploads land in a private WEKA bucket and are automatically deleted after
  180 days.

## Build from source

```bash
CGO_ENABLED=0 go build -ldflags "-s -w" -o offline_traces_uploader .
```

Static binary, stdlib only, linux/amd64 and linux/arm64.
