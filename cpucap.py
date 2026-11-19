"""cpucap.py - HARD CPU LIMIT for the relay (Wispbyte kills a server that stays above ~15% CPU).

How: `python main.py` starts this governor first.  The governor starts the real relay as a child process and every
20 ms looks at how much CPU the child used (/proc/<pid>/stat).  The child may use CPU_LIMIT percent of one core on average;
if it uses more it is paused with SIGSTOP and continued with SIGCONT (like the 'cpulimit' tool).  While it is paused
no CPU is used at all, the sockets just fill up and TCP slows the video down by itself - nothing breaks, nothing is lost.
The governor itself only sleeps (about 0.2% CPU).

  CPU_LIMIT=11     percent of one core the relay may use (0 = governor off).  Default 11: measured peaks stay <= 13-14% in any 1 s window.
  CPU_BURST=0.01   cpu-seconds the relay may use in a quick burst (smaller = smoother, never a spike above the limit)
  CPU_CAP_LOG=1    print one line every 30 s: how much cpu was used, how long the relay was paused, its RAM
  RSS_SOFT_MB=0    (off by default) restart the relay by itself when its RAM is above this AND nobody has used it for 20 s (0 with RSS_HARD_MB=0 = off)
  RSS_HARD_MB=0    (off by default) restart it at any time above this (server limit is 512 MB; the old build grew until it was killed)
"""
import os
import signal
import subprocess
import sys
import time

TICK = 0.02          # while the relay is busy: look every 20 ms
TICK_IDLE = 0.1      # while it is idle (no cpu for 2 s): look only 10 times a second (was 50 times a second all day)
PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def _cpu_seconds(pid, hz):
    """user+system cpu seconds of the whole process (all threads) - None if it cannot be read"""
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read()
        rest = data[data.rindex(b")") + 2:].split()
        return (int(rest[11]) + int(rest[12])) / float(hz)      # utime + stime
    except Exception:
        return None


def _rss_mb(pid):
    """resident memory of the process in MB - None if it cannot be read"""
    try:
        with open("/proc/%d/statm" % pid, "rb") as f:
            return int(f.read().split()[1]) * PAGE / 1048576.0
    except Exception:
        return None


def _pdeathsig():
    try:
        import ctypes
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGKILL)      # PR_SET_PDEATHSIG: child dies with the governor
    except Exception:
        pass


def govern(argv, env, limit, burst=0.01, log=False, soft_mb=280.0, hard_mb=380.0):
    """run argv as a child and keep its cpu at <= limit percent. returns the child's exit code.
    Also watches the child's RAM: above soft_mb (when nobody is watching a video) or hard_mb (always) the child is restarted
    by itself - no manual redeploy needed any more. 0 = off."""
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    L = limit / 100.0
    cur = {"child": None, "pid": 0, "stopped": False}

    def start():
        c = subprocess.Popen(argv, env=env, preexec_fn=_pdeathsig)
        cur["child"], cur["pid"], cur["stopped"] = c, c.pid, False
        return c

    def forward(sig, _frame):
        try:
            if cur["stopped"]:
                os.kill(cur["pid"], signal.SIGCONT)
                cur["stopped"] = False
            os.kill(cur["pid"], sig)
        except ProcessLookupError:
            pass
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, forward)

    def restart(why):
        c = cur["child"]
        print("[cap] restarting the relay: %s" % why, flush=True)
        try:
            os.kill(cur["pid"], signal.SIGCONT)
            os.kill(cur["pid"], signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            c.wait(timeout=5)
        except Exception:
            try:
                c.kill()
                c.wait(timeout=5)
            except Exception:
                pass
        return start()

    child = start()
    print("[cap] CPU limit %.1f%% of one core (hard, SIGSTOP/SIGCONT governor), child pid %d%s" % (
        limit, child.pid, (", RAM restart at %d MB idle / %d MB always" % (soft_mb, hard_mb)) if hard_mb > 0 else ""), flush=True)
    last_cpu = _cpu_seconds(cur["pid"], hz) or 0.0
    last_t = time.monotonic()
    last_active = last_t
    last_rss_check = last_t
    tokens = burst
    t_log, cpu_log, paused_log = last_t, last_cpu, 0.0
    restarts = 0
    while True:
        rc = child.poll()
        if rc is not None:
            return rc
        time.sleep(TICK if time.monotonic() - last_active < 2.0 else TICK_IDLE)
        now = time.monotonic()
        pid = cur["pid"]
        cpu = _cpu_seconds(pid, hz)
        if cpu is None:
            continue
        dt = max(0.001, now - last_t)
        if (cpu - last_cpu) / dt > 0.03:
            last_active = now
        tokens = min(burst, tokens + L * dt - (cpu - last_cpu))
        last_t, last_cpu = now, cpu
        if tokens < 0:
            wait = min(-tokens / L, 1.0)
            try:
                os.kill(pid, signal.SIGSTOP)
                cur["stopped"] = True
            except ProcessLookupError:
                continue
            t0 = time.monotonic()
            time.sleep(wait)
            if cur["stopped"]:
                try:
                    os.kill(pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
                cur["stopped"] = False
            paused_log += time.monotonic() - t0
            last_active = now
        if hard_mb > 0 and now - last_rss_check >= 5:
            last_rss_check = now
            rss = _rss_mb(pid)
            if rss is not None:
                idle = now - last_active > 20
                if rss > hard_mb or (rss > soft_mb and idle):
                    restarts += 1
                    child = restart("RAM %.0f MB (%s)" % (rss, "idle" if idle else "over the hard limit"))
                    last_cpu = _cpu_seconds(cur["pid"], hz) or 0.0
                    last_t = time.monotonic()
                    last_active = last_t
                    tokens = burst
                    t_log, cpu_log, paused_log = last_t, last_cpu, 0.0
                    continue
        if log and now - t_log >= 30:
            rss = _rss_mb(pid)
            print("[cap] last %ds: cpu used %.1f%% | relay paused %.0f%% of the time | RAM %s MB | restarts %d" % (
                now - t_log, 100.0 * (cpu - cpu_log) / (now - t_log), 100.0 * paused_log / (now - t_log),
                ("%.0f" % rss) if rss is not None else "?", restarts), flush=True)
            t_log, cpu_log, paused_log = now, cpu, 0.0


def maybe_run(script):
    """call at the top of main.py (after .env is loaded). Runs the governor + child and exits, or returns to run normally."""
    if os.environ.get("CPU_CHILD") == "1":
        return
    try:
        limit = float(os.getenv("CPU_LIMIT", "11"))
    except ValueError:
        limit = 11.0
    if limit <= 0:
        return
    if _cpu_seconds(os.getpid(), 100) is None:
        print("[cap] /proc not readable - CPU limit is OFF", flush=True)
        return
    env = dict(os.environ, CPU_CHILD="1")
    try:
        soft = float(os.getenv("RSS_SOFT_MB", "0"))
        hard = float(os.getenv("RSS_HARD_MB", "0"))
    except ValueError:
        soft, hard = 0.0, 0.0
    rc = govern([sys.executable, "-u", script] + sys.argv[1:], env, limit,
                float(os.getenv("CPU_BURST", "0.01")), os.getenv("CPU_CAP_LOG", "0") == "1", soft, hard)
    sys.exit(rc)
