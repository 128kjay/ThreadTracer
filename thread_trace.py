import sys
import time
import argparse
import ctypes
from ctypes import wintypes

# ----- Basic Windows / ctypes setup -----

if sys.platform != "win32":
    print("This tool only runs on Windows.", file=sys.stderr)
    sys.exit(1)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Snapshot flags
TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_NO_MORE_FILES = 18

# Thread access rights
THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800  # Vista+

# Structures

# typedef struct tagTHREADENTRY32 {
#   DWORD   dwSize;
#   DWORD   cntUsage;
#   DWORD   th32ThreadID;
#   DWORD   th32OwnerProcessID;
#   LONG    tpBasePri;
#   LONG    tpDeltaPri;
#   DWORD   dwFlags;
# } THREADENTRY32;
class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",            wintypes.DWORD),
        ("cntUsage",          wintypes.DWORD),
        ("th32ThreadID",      wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri",         wintypes.LONG),
        ("tpDeltaPri",        wintypes.LONG),
        ("dwFlags",           wintypes.DWORD),
    ]


# typedef struct _FILETIME {
#   DWORD dwLowDateTime;
#   DWORD dwHighDateTime;
# } FILETIME;
class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime",  wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


# Prototypes

kernel32.CreateToolhelp32Snapshot.argtypes = [
    wintypes.DWORD,  # dwFlags
    wintypes.DWORD,  # th32ProcessID (ignored for threads)
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Thread32First.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
]
kernel32.Thread32First.restype = wintypes.BOOL

kernel32.Thread32Next.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
]
kernel32.Thread32Next.restype = wintypes.BOOL

kernel32.OpenThread.argtypes = [
    wintypes.DWORD,  # dwDesiredAccess
    wintypes.BOOL,   # bInheritHandle
    wintypes.DWORD,  # dwThreadId
]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetThreadTimes.argtypes = [
    wintypes.HANDLE,                  # hThread
    ctypes.POINTER(FILETIME),         # lpCreationTime
    ctypes.POINTER(FILETIME),         # lpExitTime
    ctypes.POINTER(FILETIME),         # lpKernelTime
    ctypes.POINTER(FILETIME),         # lpUserTime
]
kernel32.GetThreadTimes.restype = wintypes.BOOL

kernel32.GetCurrentProcessId.argtypes = []
kernel32.GetCurrentProcessId.restype = wintypes.DWORD

kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD

# ----- Error helper -----

def format_last_error(code=None):
    """Return a human-readable message for GetLastError()."""
    if code is None:
        code = ctypes.get_last_error()

    if code == 0:
        return "No error"

    FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
    FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

    buf = ctypes.create_unicode_buffer(2048)

    kernel32.FormatMessageW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    kernel32.FormatMessageW.restype = wintypes.DWORD

    flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
    size = kernel32.FormatMessageW(
        flags,
        None,
        code,
        0,
        buf,
        len(buf),
        None,
    )

    if size == 0:
        return f"Unknown error {code}"
    return f"{buf.value.strip()} (code {code})"


def raise_last_error(prefix="Win32 error"):
    code = ctypes.get_last_error()
    msg = format_last_error(code)
    raise OSError(f"{prefix}: {msg}")


# ----- Helpers -----

def filetime_to_int(ft: FILETIME) -> int:
    """FILETIME -> integer 100-ns ticks."""
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


# ----- Core functionality -----

def enumerate_threads(pid: int = None):
    """Return a list of (thread_id, owner_pid)."""
    if pid is None:
        pid = kernel32.GetCurrentProcessId()

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise_last_error("CreateToolhelp32Snapshot(THREAD) failed")

    threads = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)

        if not kernel32.Thread32First(snapshot, ctypes.byref(entry)):
            raise_last_error("Thread32First failed")

        while True:
            if entry.th32OwnerProcessID == pid:
                threads.append((entry.th32ThreadID, entry.th32OwnerProcessID))

            if not kernel32.Thread32Next(snapshot, ctypes.byref(entry)):
                err = ctypes.get_last_error()
                if err == ERROR_NO_MORE_FILES:
                    break
                raise_last_error("Thread32Next failed")
    finally:
        kernel32.CloseHandle(snapshot)

    return threads


def list_threads(pid: int = None):
    """Print threads for a process."""
    if pid is None:
        pid = kernel32.GetCurrentProcessId()

    threads = enumerate_threads(pid)
    if not threads:
        print(f"No threads found for PID {pid}")
        return

    print(f"Threads for PID {pid}:")
    print("-" * 40)
    print(f"{'TID':>10}    {'OwnerPID':>10}")
    print("-" * 40)
    for tid, owner in threads:
        print(f"{tid:10d}    {owner:10d}")


def trace_thread_cpu(pid: int = None, duration: float = 5.0, interval: float = 0.5):
    """
    Sample per-thread CPU time periodically and visualize as ASCII bars.

    For each thread in the target process:
      - Open the thread handle with query access.
      - Sample GetThreadTimes() at fixed intervals.
      - Compute CPU delta (user+kernel) per interval.
      - Render a simple text timeline with one column per sample.
    """
    if pid is None:
        pid = kernel32.GetCurrentProcessId()

    if duration <= 0 or interval <= 0:
        raise ValueError("duration and interval must be positive")

    num_samples = int(duration / interval)
    if num_samples < 1:
        num_samples = 1

    threads = enumerate_threads(pid)
    if not threads:
        print(f"No threads found for PID {pid}")
        return

    print(f"Tracing CPU usage for PID {pid} for {duration:.2f}s "
          f"at {interval:.2f}s intervals ({num_samples} samples).")
    print()

    # Open thread handles and initial times
    thread_info = {}  # tid -> dict with handle, last_time, samples[]
    desired_access = THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION

    for tid, _ in threads:
        h_thread = kernel32.OpenThread(desired_access, False, tid)
        if not h_thread:
            err = format_last_error()
            print(f"[WARN] OpenThread({tid}) failed: {err}")
            continue

        # Initial times for baseline
        creation = FILETIME()
        exit_time = FILETIME()
        kernel_time = FILETIME()
        user_time = FILETIME()

        if not kernel32.GetThreadTimes(
            h_thread,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            err = format_last_error()
            print(f"[WARN] GetThreadTimes (initial) failed for TID {tid}: {err}")
            kernel32.CloseHandle(h_thread)
            continue

        k = filetime_to_int(kernel_time)
        u = filetime_to_int(user_time)

        thread_info[tid] = {
            "handle": h_thread,
            "last_kt": k,
            "last_ut": u,
            "samples": [],  # per-sample CPU ms
        }

    if not thread_info:
        print("No threads could be opened for tracing.")
        return

    # Sampling loop
    try:
        for sample_idx in range(num_samples):
            time.sleep(interval)

            for tid, info in list(thread_info.items()):
                h_thread = info["handle"]

                creation = FILETIME()
                exit_time = FILETIME()
                kernel_time = FILETIME()
                user_time = FILETIME()

                if not kernel32.GetThreadTimes(
                    h_thread,
                    ctypes.byref(creation),
                    ctypes.byref(exit_time),
                    ctypes.byref(kernel_time),
                    ctypes.byref(user_time),
                ):
                    # Thread might have exited
                    err_code = kernel32.GetLastError()
                    if err_code != 0:
                        # You could log this; for learning, we just note it once.
                        print(f"[INFO] TID {tid} likely exited (GetThreadTimes error {err_code}).")
                        # Stop sampling this thread but keep existing samples
                        kernel32.CloseHandle(h_thread)
                        del thread_info[tid]
                    continue

                k_now = filetime_to_int(kernel_time)
                u_now = filetime_to_int(user_time)

                dk = k_now - info["last_kt"]
                du = u_now - info["last_ut"]
                info["last_kt"] = k_now
                info["last_ut"] = u_now

                # FILETIME is 100-ns ticks; convert to ms
                cpu_ms = (dk + du) / 10_000.0
                info["samples"].append(cpu_ms)

    finally:
        # Close all handles
        for tid, info in thread_info.items():
            h = info["handle"]
            if h:
                kernel32.CloseHandle(h)

    # Visualization
    print()
    print("Per-thread CPU time per interval (approximate):")
    print("One row per thread; one column per sampling interval.\n")

    # Compute global max sample scaling
    global_max = 0.0
    for info in thread_info.values():
        if info["samples"]:
            local_max = max(info["samples"])
            if local_max > global_max:
                global_max = local_max

    # Scale so that the max bar is ~50 chars.
    # Even if global_max == 0 (completely idle), print a timeline.
    max_bar_chars = 50
    scale = global_max / max_bar_chars if global_max > 0 else 1.0

    # Print header
    header = "Sample idx : " + " ".join(f"{i:02d}" for i in range(num_samples))
    print(header)
    print("-" * len(header))

    for tid, info in sorted(thread_info.items(), key=lambda kv: kv[0]):
        samples = info["samples"]
        # Pad missing samples with 0 if some sampling steps failed for this thread
        if len(samples) < num_samples:
            samples = samples + [0.0] * (num_samples - len(samples))

        bars = []
        for ms in samples:
            if global_max == 0.0:
                # No CPU usage at all -> show idle (.)
                bar_char = "."
            else:
                # Number of characters in bar 
                length = int(ms / scale + 0.5)
                if length == 0 and ms > 0:
                    length = 1  # usage 
                bar_char = "#" if length > 0 else "."
            bars.append(bar_char)

        timeline = " ".join(bars)
        avg_ms = sum(samples) / len(samples) if samples else 0.0
        print(f"TID {tid:5d}: {timeline}   (avg {avg_ms:.4f} ms/interval)")


# ----- Main entry point -----
def main():
    parser = argparse.ArgumentParser(
        description="Enumerate threads and visualize a simple CPU-time trace per thread."
    )
    parser.add_argument(
        "--pid",
        type=int,
        help="Target process ID (default: current process)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List threads for the target PID.",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Trace per-thread CPU time for the target PID.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=5.0,
        help="Trace duration in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.5,
        help="Sampling interval in seconds (default: 0.5).",
    )

    args = parser.parse_args()

    pid = args.pid

    if not args.list and not args.trace:
        parser.print_help()
        return

    if args.list:
        list_threads(pid)
        print()

    if args.trace:
        trace_thread_cpu(pid, duration=args.duration, interval=args.interval)


if __name__ == "__main__":
    main()
