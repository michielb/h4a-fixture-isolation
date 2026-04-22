//go:build linux

// Command h4a-probe is the container-isolation probe fixture for MB-451. It
// runs a series of syscall / filesystem / network probes inside a container
// and emits a structured JSON report describing which isolation boundaries
// held. It is NOT an exploit; every probe inspects public-interface
// behaviour. Designed to be deployed via `h4a deploy` (so the container
// inherits the platform's default posture) and polled via HTTP by the
// runner at tests/isolation/isolation_test.go.
//
// The fixture runs exactly once at startup, caches the result in memory,
// writes it to `/var/log/h4a-probe.json` (for `h4a logs` consumers), and
// serves the same JSON on `http://:8080/` so the platform's health check
// passes and the runner can fetch results over HTTPS.
//
// Environment variables:
//
//	PROBE_SIBLING_ADDR   host:port of a probe deployed in a sibling tenant.
//	                     When set, network.cross_tenant_container attempts
//	                     a 2s TCP connect against it. Unset → probe is
//	                     recorded as informational/skipped.
//	PROBE_LISTEN         HTTP listen address. Default ":8080".
//	PROBE_OUTPUT         Path to write the JSON report. Default
//	                     "/var/log/h4a-probe.json". Empty disables.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// Report is the top-level JSON document written by the probe. Fields are
// stable by name — the runner in tests/isolation/isolation_test.go parses
// them to assert isolation guarantees.
type Report struct {
	FixtureVersion string   `json:"fixture_version"`
	Runtime        string   `json:"runtime"` // self-reported, from PROBE_RUNTIME_CLASS env
	StartedAt      string   `json:"started_at"`
	FinishedAt     string   `json:"finished_at"`
	Probes         []Result `json:"probes"`
}

// Result is one probe outcome.
//
//	blocked=true means the platform's isolation held as expected (the probe
//	            hit an EPERM / ENOENT / EROFS / EACCES / timeout, or returned
//	            a sanitised value like a zero kallsyms address).
//	blocked=false means the probe observed the forbidden behaviour — action
//	              required. The runner asserts this against a category-level
//	              policy (runc blocks groups 1-4; runsc blocks 1-5).
//
// `informational=true` flags probes whose outcome is recorded but not
// asserted at v0 (the cross-tenant-network probe today).
type Result struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	Blocked       bool   `json:"blocked"`
	Informational bool   `json:"informational,omitempty"`
	Expected      string `json:"expected"`
	Actual        string `json:"actual"`
	Error         string `json:"error,omitempty"`
}

const fixtureVersion = "mb-451-v1"

func main() {
	listen := envOr("PROBE_LISTEN", ":8080")
	output := envOr("PROBE_OUTPUT", "/var/log/h4a-probe.json")

	started := time.Now().UTC()
	log.Printf("[h4a-probe] %s starting; running probe set", fixtureVersion)
	probes := runAllProbes()
	finished := time.Now().UTC()

	report := Report{
		FixtureVersion: fixtureVersion,
		Runtime:        envOr("PROBE_RUNTIME_CLASS", "unknown"),
		StartedAt:      started.Format(time.RFC3339),
		FinishedAt:     finished.Format(time.RFC3339),
		Probes:         probes,
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("[h4a-probe] marshal report: %v", err)
	}
	log.Printf("[h4a-probe] completed %d probes in %s", len(probes), finished.Sub(started).Round(time.Millisecond))
	// Log summary per category so `h4a logs` readers see the headline even
	// without hitting the HTTP endpoint.
	for _, cat := range []string{"caps", "filesystem", "kernel", "seccomp", "network"} {
		blocked, total := 0, 0
		for _, p := range probes {
			if p.Category != cat {
				continue
			}
			total++
			if p.Blocked {
				blocked++
			}
		}
		if total > 0 {
			log.Printf("[h4a-probe] %-10s %d/%d blocked", cat, blocked, total)
		}
	}
	// Full JSON to stdout so `h4a logs` can pipe it to the runner when HTTP
	// is inconvenient (e.g. cross-tenant, not-yet-networked).
	os.Stdout.Write(body)
	os.Stdout.WriteString("\n")

	if output != "" {
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			log.Printf("[h4a-probe] mkdir for %s: %v (continuing)", output, err)
		} else if err := os.WriteFile(output, body, 0o644); err != nil {
			log.Printf("[h4a-probe] write %s: %v (continuing; HTTP endpoint still serves)", output, err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("[h4a-probe] http listen %s", listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[h4a-probe] http serve: %v", err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// --- probe set --------------------------------------------------------------

func runAllProbes() []Result {
	var out []Result
	out = append(out, probesCaps()...)
	out = append(out, probesFilesystem()...)
	out = append(out, probesKernel()...)
	out = append(out, probesSeccomp()...)
	out = append(out, probesNetwork()...)
	return out
}

// 1. Capabilities + privilege -------------------------------------------------

func probesCaps() []Result {
	return []Result{
		probeCapget(),
		probeMountTmpfs(),
		probeUnshareUser(),
		probeSetuidZero(),
	}
}

// LINUX_CAPABILITY_VERSION_3 — stable constant from <linux/capability.h>.
const linuxCapabilityVersion3 = 0x20080522

type capUserHeader struct {
	Version uint32
	Pid     int32
}

type capUserData struct {
	Effective, Permitted, Inheritable uint32
}

// probeCapget reads the process's effective capability set. A properly
// dropped container has effective=0. Uses raw SYS_CAPGET via unsafe to
// avoid pulling in golang.org/x/sys/unix and keep the fixture stdlib-only.
func probeCapget() Result {
	var hdr = capUserHeader{Version: linuxCapabilityVersion3}
	var data [2]capUserData
	_, _, errno := syscall.Syscall(syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return Result{
			Name:     "caps.capget",
			Category: "caps",
			Expected: "effective_set_empty",
			Actual:   "capget_failed",
			Error:    errno.Error(),
			Blocked:  false,
		}
	}
	actual := fmt.Sprintf("eff=%#x/%#x", data[0].Effective, data[1].Effective)
	blocked := data[0].Effective == 0 && data[1].Effective == 0
	return Result{
		Name:     "caps.capget",
		Category: "caps",
		Expected: "effective_set_empty",
		Actual:   actual,
		Blocked:  blocked,
	}
}

// probeMountTmpfs attempts `mount -t tmpfs` — needs CAP_SYS_ADMIN, which we
// drop. Expect EPERM.
func probeMountTmpfs() Result {
	dir, err := os.MkdirTemp("", "h4a-probe-mnt-*")
	if err != nil {
		return Result{
			Name: "caps.mount_tmpfs", Category: "caps",
			Expected: "EPERM", Actual: "mkdirtemp_failed", Error: err.Error(),
		}
	}
	defer os.RemoveAll(dir)
	merr := syscall.Mount("none", dir, "tmpfs", 0, "")
	if merr == nil {
		// Surprise: we got a tmpfs. Clean it up + record the break.
		_ = syscall.Unmount(dir, 0)
		return Result{
			Name: "caps.mount_tmpfs", Category: "caps",
			Expected: "EPERM", Actual: "mount_succeeded", Blocked: false,
		}
	}
	return Result{
		Name: "caps.mount_tmpfs", Category: "caps",
		Expected: "EPERM", Actual: merr.Error(),
		Blocked: errors.Is(merr, syscall.EPERM) || errors.Is(merr, syscall.EACCES),
	}
}

// probeUnshareUser attempts CLONE_NEWUSER. Our seccomp profile + no_new_privs
// typically block this (or make it meaningless without CAP_SYS_ADMIN).
func probeUnshareUser() Result {
	err := syscall.Unshare(syscall.CLONE_NEWUSER)
	if err == nil {
		return Result{
			Name: "caps.unshare_user", Category: "caps",
			Expected: "EPERM_or_no_new_caps", Actual: "unshare_succeeded",
			Blocked: false,
		}
	}
	return Result{
		Name: "caps.unshare_user", Category: "caps",
		Expected: "EPERM_or_no_new_caps", Actual: err.Error(),
		Blocked: errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EINVAL),
	}
}

// probeSetuidZero tries to become root from whatever UID we're currently
// running as. Only meaningful when the probe runs non-root (see the
// fixture's Dockerfile: USER 1000:1000).
func probeSetuidZero() Result {
	uid := os.Geteuid()
	if uid == 0 {
		return Result{
			Name: "caps.setuid_zero", Category: "caps",
			Expected: "EPERM_from_nonroot", Actual: "already_root_uid0",
			Blocked: false, Informational: true,
		}
	}
	err := syscall.Setuid(0)
	if err == nil {
		return Result{
			Name: "caps.setuid_zero", Category: "caps",
			Expected: "EPERM_from_nonroot", Actual: "setuid_succeeded",
			Blocked: false,
		}
	}
	return Result{
		Name: "caps.setuid_zero", Category: "caps",
		Expected: "EPERM_from_nonroot", Actual: err.Error(),
		Blocked: errors.Is(err, syscall.EPERM),
	}
}

// 2. Filesystem --------------------------------------------------------------

func probesFilesystem() []Result {
	return []Result{
		probeOpenPath("filesystem.open_dev_kmem", "/dev/kmem"),
		probeOpenPath("filesystem.open_dev_mem", "/dev/mem"),
		probeBlockDeviceEnum(),
		probeRemountRW(),
		probeWriteEtcHosts(),
	}
}

// probeOpenPath tries to open a path that should NOT be accessible inside a
// properly-built container (host /dev specials).
func probeOpenPath(name, path string) Result {
	f, err := os.Open(path)
	if err == nil {
		_ = f.Close()
		return Result{
			Name: name, Category: "filesystem",
			Expected: "ENOENT_or_EPERM", Actual: "opened", Blocked: false,
		}
	}
	return Result{
		Name: name, Category: "filesystem",
		Expected: "ENOENT_or_EPERM", Actual: err.Error(),
		Blocked: errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) ||
			errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES),
	}
}

// probeBlockDeviceEnum enumerates /sys/class/block and reports entries that
// look like host physical devices. A safe container shows either an empty
// list or only docker's own loop/overlay pseudo-devices.
func probeBlockDeviceEnum() Result {
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		// /sys not mounted at all is an even stronger isolation posture.
		return Result{
			Name: "filesystem.block_device_enum", Category: "filesystem",
			Expected: "no_host_block_devices", Actual: "sys_class_block_unreadable",
			Error: err.Error(), Blocked: true,
		}
	}
	var hostLikelies []string
	for _, e := range entries {
		name := e.Name()
		// sda, sdb, nvme0n1, vda, hda — these are strong hints the host
		// block namespace is exposed.
		if strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "nvme") ||
			strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "hd") {
			hostLikelies = append(hostLikelies, name)
		}
	}
	if len(hostLikelies) > 0 {
		return Result{
			Name: "filesystem.block_device_enum", Category: "filesystem",
			Expected: "no_host_block_devices",
			Actual:   "found: " + strings.Join(hostLikelies, ","),
			Blocked:  false,
		}
	}
	return Result{
		Name: "filesystem.block_device_enum", Category: "filesystem",
		Expected: "no_host_block_devices",
		Actual:   fmt.Sprintf("entries=%d (none host-like)", len(entries)),
		Blocked:  true,
	}
}

// probeRemountRW tries to make the read-only rootfs writable. A properly
// configured container either drops CAP_SYS_ADMIN (so this EPERMs) OR has
// the rootfs mounted read-only at the runtime level.
func probeRemountRW() Result {
	err := syscall.Mount("", "/", "", syscall.MS_REMOUNT, "")
	if err == nil {
		return Result{
			Name: "filesystem.remount_rw", Category: "filesystem",
			Expected: "EPERM_or_EROFS", Actual: "remount_succeeded",
			Blocked: false,
		}
	}
	return Result{
		Name: "filesystem.remount_rw", Category: "filesystem",
		Expected: "EPERM_or_EROFS", Actual: err.Error(),
		Blocked: errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EROFS) ||
			errors.Is(err, syscall.EACCES),
	}
}

// probeWriteEtcHosts tries to write to /etc/hosts. Docker bind-mounts
// /etc/hosts as writable by default; this probe is therefore EXPECTED to
// succeed unless we override the default. Recorded as informational so the
// runner doesn't fail the suite — but useful to track if the posture ever
// gets tightened.
func probeWriteEtcHosts() Result {
	err := os.WriteFile("/etc/hosts", []byte("# h4a-probe: if this persists, the probe broke the rootfs readonly guarantee\n"), 0o644)
	if err == nil {
		return Result{
			Name: "filesystem.write_etc_hosts", Category: "filesystem",
			Expected: "EROFS_if_readonly_rootfs", Actual: "write_succeeded",
			Blocked:       false,
			Informational: true,
		}
	}
	return Result{
		Name: "filesystem.write_etc_hosts", Category: "filesystem",
		Expected: "EROFS_if_readonly_rootfs", Actual: err.Error(),
		Blocked: errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EPERM) ||
			errors.Is(err, syscall.EACCES),
	}
}

// 3. Kernel info leak --------------------------------------------------------

func probesKernel() []Result {
	return []Result{
		probeKallsymsZeroed(),
		probeProcPidsContainerOnly(),
		probeProcVersionControl(),
	}
}

// probeKallsymsZeroed reads /proc/kallsyms and checks that symbol addresses
// are zeroed (kptr_restrict=1 or 2). A non-zero address leak would be a
// kernel-pointer infoleak — kASLR oracle.
func probeKallsymsZeroed() Result {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return Result{
			Name: "kernel.kallsyms_zeroed", Category: "kernel",
			Expected: "zero_addresses_or_ENOENT", Actual: err.Error(),
			Blocked: true,
		}
	}
	defer f.Close()
	// Read first 2 KiB and check at least one non-zero sym exists AND that
	// every sym address is zero. kptr_restrict=1 → non-root sees zeros;
	// kptr_restrict=2 → everyone sees zeros.
	buf := make([]byte, 2048)
	n, _ := io.ReadFull(f, buf)
	lines := strings.Split(string(buf[:n]), "\n")
	nonZeroFound := false
	sampled := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		sampled++
		// Format: "ffffffff81000000 T _text" — first field is the address.
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		addr := fields[0]
		allZero := true
		for _, c := range addr {
			if c != '0' {
				allZero = false
				break
			}
		}
		if !allZero {
			nonZeroFound = true
			break
		}
	}
	if sampled == 0 {
		return Result{
			Name: "kernel.kallsyms_zeroed", Category: "kernel",
			Expected: "zero_addresses", Actual: "empty_file", Blocked: true,
		}
	}
	if nonZeroFound {
		return Result{
			Name: "kernel.kallsyms_zeroed", Category: "kernel",
			Expected: "zero_addresses", Actual: "leaked_kernel_pointer",
			Blocked: false,
		}
	}
	return Result{
		Name: "kernel.kallsyms_zeroed", Category: "kernel",
		Expected: "zero_addresses",
		Actual:   fmt.Sprintf("sampled=%d; all zero", sampled),
		Blocked:  true,
	}
}

// probeProcPidsContainerOnly checks that /proc shows only our own process
// tree — i.e. the PID namespace is active. A leaky namespace would expose
// the host's docker daemon, systemd, kthreadd, etc.
func probeProcPidsContainerOnly() Result {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return Result{
			Name: "kernel.proc_pids_container_only", Category: "kernel",
			Expected: "only_container_pids", Actual: err.Error(),
			Blocked: false,
		}
	}
	pidCount := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		allDigits := true
		for _, c := range name {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			pidCount++
		}
	}
	// A scratch container with PID namespace active typically shows ≤5 PIDs
	// (us + maybe a few transient children). A leaky namespace would show
	// dozens (host init, kthreads, user services).
	return Result{
		Name: "kernel.proc_pids_container_only", Category: "kernel",
		Expected: "pid_count<=5",
		Actual:   fmt.Sprintf("pid_count=%d", pidCount),
		Blocked:  pidCount <= 5,
	}
}

// probeProcVersionControl is a CONTROL probe: /proc is mounted, kernel
// version is readable. Always expected to succeed. Fails only if /proc is
// completely broken, which would be news.
func probeProcVersionControl() Result {
	b, err := os.ReadFile("/proc/sys/kernel/version")
	if err != nil {
		return Result{
			Name: "kernel.proc_version_readable", Category: "kernel",
			Expected: "readable_control", Actual: err.Error(),
			Blocked: false, Informational: true,
		}
	}
	return Result{
		Name: "kernel.proc_version_readable", Category: "kernel",
		Expected: "readable_control",
		Actual:   strings.TrimSpace(string(b)),
		Blocked:  true, Informational: true,
	}
}

// 4. Seccomp -----------------------------------------------------------------

// These syscall numbers are linux/amd64-specific. Docker's default seccomp
// profile blocks them (among ~40 others) as "privileged / dangerous".
const (
	sysAddKey       = 248
	sysKexecLoad    = 246
	sysInitModule   = 175
	sysFinitModule  = 313
	sysDeleteModule = 176
)

type seccompProbe struct {
	Name string
	Num  uintptr
}

var seccompProbes = []seccompProbe{
	{"seccomp.add_key", sysAddKey},
	{"seccomp.kexec_load", sysKexecLoad},
	{"seccomp.init_module", sysInitModule},
	{"seccomp.finit_module", sysFinitModule},
	{"seccomp.delete_module", sysDeleteModule},
}

func probesSeccomp() []Result {
	var out []Result
	for _, p := range seccompProbes {
		out = append(out, probeSeccomp(p))
	}
	return out
}

// probeSeccomp invokes a syscall that Docker's default seccomp should
// reject with EPERM (not ENOSYS — seccomp's SECCOMP_RET_ERRNO(EPERM) is
// the convention). We pass zero args; the syscalls don't reach their real
// argument validation because seccomp intercepts first.
func probeSeccomp(p seccompProbe) Result {
	_, _, errno := syscall.Syscall(p.Num, 0, 0, 0)
	if errno == 0 {
		return Result{
			Name: p.Name, Category: "seccomp",
			Expected: "EPERM", Actual: "syscall_succeeded",
			Blocked: false,
		}
	}
	return Result{
		Name: p.Name, Category: "seccomp",
		Expected: "EPERM", Actual: errno.Error(),
		// EPERM is the seccomp block signature; we also accept EACCES (some
		// profiles return that).
		Blocked: errno == syscall.EPERM || errno == syscall.EACCES,
	}
}

// 5. Network -----------------------------------------------------------------

func probesNetwork() []Result {
	return []Result{
		probeCrossTenantReach(),
		probeBindPort80(),
		probeHetznerMetadata(),
	}
}

// probeCrossTenantReach tries to TCP-connect to PROBE_SIBLING_ADDR for 2s.
// An unset env disables the probe (recorded as informational). A
// successful connection indicates cross-tenant container reachability on
// the shared Docker bridge — unacceptable long-term, but only flagged at
// v0; it motivates a per-tenant user-defined network follow-up.
func probeCrossTenantReach() Result {
	addr := os.Getenv("PROBE_SIBLING_ADDR")
	if addr == "" {
		return Result{
			Name: "network.cross_tenant_reach", Category: "network",
			Expected: "refused_or_timeout", Actual: "skipped_no_PROBE_SIBLING_ADDR",
			Informational: true, Blocked: true,
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return Result{
			Name: "network.cross_tenant_reach", Category: "network",
			Expected: "refused_or_timeout", Actual: "connected",
			Informational: true, Blocked: false,
		}
	}
	return Result{
		Name: "network.cross_tenant_reach", Category: "network",
		Expected:      "refused_or_timeout",
		Actual:        err.Error(),
		Informational: true, Blocked: true,
	}
}

// probeBindPort80 expects EACCES because we drop CAP_NET_BIND_SERVICE.
func probeBindPort80() Result {
	ln, err := net.Listen("tcp", ":80")
	if err == nil {
		_ = ln.Close()
		return Result{
			Name: "network.bind_port_80", Category: "network",
			Expected: "EACCES", Actual: "listen_succeeded",
			Blocked: false,
		}
	}
	msg := err.Error()
	return Result{
		Name: "network.bind_port_80", Category: "network",
		Expected: "EACCES", Actual: msg,
		// net.Listen wraps the errno in an *OpError; string-match is the
		// pragmatic way to catch EACCES / EPERM here.
		Blocked: strings.Contains(msg, "permission denied") ||
			strings.Contains(msg, "operation not permitted"),
	}
}

// probeHetznerMetadata tries to reach the link-local metadata address.
// Hetzner doesn't expose anything at 169.254.169.254 today, but a working
// connection would be a network-boundary leak worth knowing about. 2s
// timeout; container bridge should drop the packet or return no-route.
func probeHetznerMetadata() Result {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", "169.254.169.254:80")
	if err == nil {
		_ = conn.Close()
		return Result{
			Name: "network.metadata_169_254", Category: "network",
			Expected: "no_route_or_refused", Actual: "connected",
			Blocked: false,
		}
	}
	return Result{
		Name: "network.metadata_169_254", Category: "network",
		Expected: "no_route_or_refused", Actual: err.Error(),
		Blocked: true,
	}
}
