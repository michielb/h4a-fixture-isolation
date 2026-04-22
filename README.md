# h4a-probe — container-isolation probe fixture

Single-binary Go fixture that runs a deterministic set of isolation probes
inside a container and emits a structured JSON report. Consumed by
`tests/isolation/isolation_test.go` (runs with `//go:build isolation`) to
assert the platform's container-isolation posture meets the M4.9
(MB-451) exit criterion.

## What it tests

Five probe groups, ~18 probes total:

1. **Capabilities + privilege** — `capget()` effective set, `mount -t tmpfs`,
   `unshare(CLONE_NEWUSER)`, `setuid(0)` from non-root.
2. **Filesystem** — `/dev/kmem`, `/dev/mem`, host block-device enumeration
   under `/sys/class/block`, `mount -o remount,rw /`, writing `/etc/hosts`.
3. **Kernel info leak** — `/proc/kallsyms` address leak, `/proc` PID-count
   (PID namespace intact), `/proc/sys/kernel/version` (control probe).
4. **Seccomp** — 5 syscalls from Docker's default-blocked list (`add_key`,
   `kexec_load`, `init_module`, `finit_module`, `delete_module`).
5. **Network** — cross-tenant container TCP reach (opt-in via
   `PROBE_SIBLING_ADDR`), `:80` bind (`EACCES`), `169.254.169.254:80`
   metadata connect.

The fixture is deliberately a probe, not an exploit: every check inspects
public-interface behaviour. No CVE-targeting, no kernel-fuzzing. That
work lives post-M6.

## Running locally

```
go run .                          # runs the probes, prints JSON, serves :8080
PROBE_SIBLING_ADDR=10.0.0.2:8080 go run .
PROBE_LISTEN=:9090 PROBE_OUTPUT=/tmp/probe.json go run .
```

On a non-Linux host a lot of the syscall probes will report `not
supported` — only Linux containers give meaningful results.

## Deploying via h4a for the runner

The runner expects two probe workloads to be live at the time it runs: one
on `runc` (platform default), one on `runsc` (gVisor, opt-in via
`sandbox: strict` in `.h4a.yaml`). Both live in the `h4a-test` tenant so
the blast radius of a misbehaving probe is contained.

```
# Operator workflow (rebuild + redeploy when the probe changes):
gh repo create michielb/h4a-fixture-isolation --public   # once
# ... commit this directory's contents + push

bin/h4a deploy probe-runc  --tenant h4a-test --repo github.com/michielb/h4a-fixture-isolation
bin/h4a deploy probe-runsc --tenant h4a-test --repo github.com/michielb/h4a-fixture-isolation
# probe-runsc's repo must carry a .h4a.yaml with `sandbox: strict`
```

Then, against live URLs:

```
H4A_ISOLATION_RUNC_URL=https://probe-runc.h4a.site \
H4A_ISOLATION_RUNSC_URL=https://probe-runsc.h4a.site \
go test -tags=isolation -run TestIsolation -v -timeout 20m ./tests/isolation/...
```

## Report schema

```json
{
  "fixture_version": "mb-451-v1",
  "runtime": "runc",
  "started_at": "2026-04-21T14:30:00Z",
  "finished_at": "2026-04-21T14:30:02Z",
  "probes": [
    {
      "name": "caps.capget",
      "category": "caps",
      "blocked": true,
      "expected": "effective_set_empty",
      "actual": "eff=0x0/0x0"
    },
    ...
  ]
}
```

`blocked=true` means the platform's isolation held as expected. Each
probe documents what it expected in the `expected` field so diffs are
meaningful when the posture changes.

`informational=true` flags probes whose outcome is recorded but not
asserted at v0 (today: cross-tenant reach on the shared Docker bridge,
`/etc/hosts` writability, the `/proc/sys/kernel/version` control probe).

## Adding a new probe

1. Write `probeXxx()` returning a `Result`. Put it in the matching
   `probesXxx()` group.
2. Export the behaviour in its `expected` / `actual` strings — the runner
   diffs on these when rendering a report.
3. Set `Informational: true` if the posture is not yet asserted at v0.
4. Add the probe's name to `tests/isolation/isolation_test.go`'s
   category expectations if it should be blocked by the runner.
