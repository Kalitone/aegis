"""
AEGIS — Linux eBPF Process Monitor
===================================
Push-based replacement for the psutil polling in `monitors/process.py`.
Hooks the kernel's `sched_process_exec` tracepoint via eBPF and emits
`proc.create` events with sub-millisecond latency — no missed PIDs
even when a binary forks-execs-exits inside a single 500 ms poll
interval.

Status
------
**Linux only.** On Windows / macOS / any platform without `bcc`
Python bindings, the monitor cleanly disables itself with a clear
log line and returns. AEGIS continues to use the polling
`monitors/process.py` everywhere the eBPF monitor can't load.

When both run side-by-side on Linux, every exec produces two events
(one from polling, one from eBPF). The polling monitor should be
disabled in YAML when this one is active — see
`config/aegis.yaml` `monitors.proc_ebpf` block.

Threat-model upgrade vs psutil polling
--------------------------------------
- **Zero-loss**. The 500 ms polling interval misses any process
  whose lifetime is shorter than its sample window. eBPF sees every
  exec the kernel processes.
- **Microsecond latency**. The detection / response chain fires
  before the spawned process has had time to drop persistence,
  exfiltrate data, or chain into another exec.
- **Argv as the kernel saw it**. psutil reads /proc/<pid>/cmdline
  AFTER the process has executed; an attacker can `prctl(PR_SET_NAME)`
  or write to /proc/self/cmdline to obscure. eBPF captures the argv
  array at the syscall boundary — pre-tamper.

Not in v1
---------
- `connect()` / `openat()` hooks. Same eBPF approach extends to
  socket and file telemetry — left as a follow-up so the v1 module
  is reviewable and the C program small.
- libbpf + CO-RE. We use bcc's runtime-compile path because it's
  the simplest install on Debian/Ubuntu/Fedora today. CO-RE would
  let the BPF object be precompiled and shipped with AEGIS, which
  is the right Phase 2 once we have an empirical kernel-version
  matrix.
- Tetragon sidecar mode. A future flag could swap the bcc backend
  for a Tetragon-events consumer; the public class surface here
  doesn't change.

Distro install notes
--------------------
- Debian / Ubuntu:  `sudo apt install python3-bpfcc bpfcc-tools`
- Fedora / RHEL:    `sudo dnf install python3-bcc bcc-tools`
- Arch:             `sudo pacman -S bcc bcc-tools python-bcc`

Requires CAP_BPF (or CAP_SYS_ADMIN on older kernels) and a kernel
with BPF + kprobes/tracepoints enabled (every Linux distro since
~2019). Run AEGIS as root or with the right file capabilities.
"""

from __future__ import annotations

import logging
import os
import platform
import threading
import time
from typing import Any, Optional

from aegis.core import EventBus, Event, EventCategory, Severity

logger = logging.getLogger("aegis.monitors.proc_ebpf")


# ── eBPF C program ──────────────────────────────────────────────────
# Hooks the `sched_process_exec` tracepoint (one of the most stable
# tracepoints across kernel versions — has been ABI-stable since
# ~Linux 4.3). Pushes a small struct to userland via a perf_event
# ring buffer for each exec.
#
# We deliberately keep the kernel-side simple: just the values bcc
# can read without bouncing in and out of helper functions. argv is
# captured up to ARGV_MAX_LEN bytes total to bound the per-event
# size; truncation is acceptable since malware giveaways are
# typically in the first ~256 chars (`-EncodedCommand QQ...`,
# `bash -i >& /dev/tcp/...`).

EBPF_C_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define COMM_LEN     16
#define ARGV_MAX_LEN 512
#define FILENAME_LEN 256

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 ts_ns;
    char comm[COMM_LEN];
    char filename[FILENAME_LEN];
    char argv[ARGV_MAX_LEN];
};

BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    evt.pid  = bpf_get_current_pid_tgid() >> 32;
    evt.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.gid  = bpf_get_current_uid_gid() >> 32;
    evt.ts_ns = bpf_ktime_get_ns();
    evt.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    /* Filename comes from the tracepoint args — this is the
     * kernel-resolved executable path, not what argv[0] claims. */
    unsigned int fname_off = args->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&evt.filename, sizeof(evt.filename),
                       (void *)args + fname_off);

    /* Argv reconstruction is the messy part — we read up to N
     * tokens from the userland argv array. v1 keeps it conservative
     * with a fixed unrolled loop; if we need more we'll switch to
     * a per-CPU scratch map. */
    /* Note: `args` for sched_process_exec doesn't carry argv
     * directly; we read the task's mm_struct arg pointer block. */
    struct mm_struct *mm = task->mm;
    if (mm) {
        unsigned long arg_start = mm->arg_start;
        unsigned long arg_end = mm->arg_end;
        if (arg_end > arg_start) {
            unsigned long len = arg_end - arg_start;
            if (len > ARGV_MAX_LEN - 1) len = ARGV_MAX_LEN - 1;
            bpf_probe_read_user(&evt.argv, len, (void *)arg_start);
        }
    }

    exec_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""


# ── Event mapping ──────────────────────────────────────────────────

def _decode_argv(raw: bytes) -> str:
    """Translate the NUL-delimited argv blob into a single space-joined
    string. Replaces NULs with spaces and strips the trailing one.
    """
    if not raw:
        return ""
    s = raw.split(b"\x00\x00", 1)[0]    # tail padding
    s = s.replace(b"\x00", b" ").strip()
    try:
        return s.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _bytes_to_str(raw: Any) -> str:
    """Robust ctypes-buffer / bytes / str → str conversion."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return str(raw)


def map_kernel_event(evt: dict) -> dict:
    """Translate one eBPF struct into the AEGIS PROC_CREATE data
    payload. Pure function — no bus, no IO, fully testable."""
    pid = int(evt.get("pid") or 0)
    ppid = int(evt.get("ppid") or 0)
    uid = int(evt.get("uid") or 0)
    gid = int(evt.get("gid") or 0)
    comm = _bytes_to_str(evt.get("comm"))
    filename = _bytes_to_str(evt.get("filename"))
    argv_blob = evt.get("argv") or b""
    if isinstance(argv_blob, str):
        argv_blob = argv_blob.encode("utf-8", "replace")
    cmdline = _decode_argv(argv_blob)
    return {
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "gid": gid,
        "name": comm,
        "exe": filename,
        "cmdline": cmdline,
        "telemetry_source": "ebpf.sched_process_exec",
    }


# ── Monitor ────────────────────────────────────────────────────────

class EbpfProcessMonitor:
    """Loads the eBPF program on `start()`, drains the perf ring
    buffer on a background thread. Soft-fails everywhere it can't
    load (non-Linux, missing bcc, insufficient privileges, kernel
    too old, …) — AEGIS continues with the polling monitor."""

    def __init__(self, event_bus: EventBus, config: dict):
        self.bus = event_bus
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", False))
        self.ring_pages = int(self.config.get("ringbuf_pages", 64))
        self.poll_interval_ms = int(self.config.get("poll_interval_ms", 100))
        # Test/DI: caller can supply a pre-built BPF stand-in.
        self._bpf: Any = self.config.get("_bpf_override")
        self._program_text: str = self.config.get("_program_override",
                                                  EBPF_C_PROGRAM)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._event_count = 0

    # -- public ----------------------------------------------------
    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def event_count(self) -> int:
        return self._event_count

    def start(self):
        if not self.enabled:
            logger.info("EbpfProcessMonitor: disabled in config")
            return
        if not self._is_supported_platform():
            logger.info(
                "EbpfProcessMonitor: not supported on "
                f"{platform.system()} — staying disabled"
            )
            self.enabled = False
            return
        if self._bpf is None:
            try:
                self._bpf = self._build_bpf()
            except Exception as e:
                logger.warning(
                    f"EbpfProcessMonitor: bcc load failed ({e}). "
                    "Falling back to polling process monitor. See module "
                    "docstring for distro install instructions."
                )
                self.enabled = False
                return

        try:
            self._bpf["exec_events"].open_perf_buffer(
                self._on_kernel_event,
                page_cnt=self.ring_pages,
            )
        except Exception as e:
            logger.warning(
                f"EbpfProcessMonitor: open_perf_buffer failed: {e}"
            )
            self.enabled = False
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="aegis-ebpf-proc",
        )
        self._thread.start()
        logger.info(
            f"EbpfProcessMonitor started "
            f"(ring_pages={self.ring_pages}, poll={self.poll_interval_ms} ms)"
        )

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
        # Detach probes — important if the operator restarts AEGIS
        # without reboot; orphan probes hold kernel memory.
        if self._bpf is not None and hasattr(self._bpf, "cleanup"):
            try:
                self._bpf.cleanup()
            except Exception:
                pass

    def ingest_kernel_event(self, evt: dict):
        """Public hook used by tests + the perf-buffer callback. The
        callback wraps this; tests call it directly to avoid having
        to fake the bcc ring buffer."""
        try:
            data = map_kernel_event(evt)
        except Exception as e:
            logger.debug(f"map_kernel_event failed: {e}")
            return
        self._event_count += 1
        self.bus.publish(Event(
            category=EventCategory.PROC_CREATE,
            severity=Severity.INFO,
            source="proc_ebpf",
            data=data,
            timestamp=time.time(),
        ))

    # -- internals -------------------------------------------------
    @staticmethod
    def _is_supported_platform() -> bool:
        return platform.system().lower() == "linux"

    def _build_bpf(self):
        """Lazy-import bcc and compile the eBPF program. Raises if
        bcc isn't installed or compilation fails."""
        from bcc import BPF                  # type: ignore
        return BPF(text=self._program_text)

    def _on_kernel_event(self, cpu, data, size):
        """bcc perf-buffer callback. Translates the ctypes struct
        into a dict and hands off to ingest_kernel_event."""
        try:
            evt = self._bpf["exec_events"].event(data)
        except Exception as e:
            logger.debug(f"perf event decode failed: {e}")
            return
        self.ingest_kernel_event({
            "pid": getattr(evt, "pid", 0),
            "ppid": getattr(evt, "ppid", 0),
            "uid": getattr(evt, "uid", 0),
            "gid": getattr(evt, "gid", 0),
            "comm": bytes(getattr(evt, "comm", b"") or b""),
            "filename": bytes(getattr(evt, "filename", b"") or b""),
            "argv": bytes(getattr(evt, "argv", b"") or b""),
            "ts_ns": getattr(evt, "ts_ns", 0),
        })

    def _loop(self):
        """Pump the perf buffer on a background thread. bcc's
        `perf_buffer_poll` blocks for up to `timeout` ms or until
        events arrive — same blocking semantics as `epoll_wait`."""
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=self.poll_interval_ms)
            except KeyboardInterrupt:
                return
            except Exception as e:
                logger.debug(f"perf_buffer_poll error: {e}")
                # Don't spin on a broken poll — back off.
                time.sleep(0.5)


__all__ = [
    "EbpfProcessMonitor",
    "EBPF_C_PROGRAM",
    "map_kernel_event",
]
