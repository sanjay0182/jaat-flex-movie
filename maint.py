"""maint.py - once a day: delete everything that is older than 1 day (nothing else is touched, RAM works as before).

Every MAINT_EVERY seconds (default 86400 = 1 day) it removes entries older than MAINT_AGE seconds (default 86400 = 1 day) from
the relay's memory: idle CDN connections, DNS, TLS sessions, host memory, playlists, resolved links.
MAINT_EVERY=0 switches it off.
"""
import asyncio
import os
import time

EVERY = int(os.getenv("MAINT_EVERY", "86400"))
AGE = int(os.getenv("MAINT_AGE", "86400"))


def _prune(d, old):
    """delete every entry of dict d for which old(value) is true"""
    try:
        for k, v in list(d.items()):
            try:
                if old(v):
                    d.pop(k, None)
            except Exception:
                d.pop(k, None)
    except Exception:
        pass


def sweep():
    import rawpipe
    import tlspass
    import worker
    now = time.time()
    try:
        for key in list(rawpipe._POOL):
            keep = []
            for item in rawpipe._POOL.get(key) or []:
                r, w, t = item
                if now - t < AGE and not w.is_closing():
                    keep.append(item)
                else:
                    try:
                        w.close()
                    except Exception:
                        pass
            if keep:
                rawpipe._POOL[key] = keep
            else:
                rawpipe._POOL.pop(key, None)
    except Exception:
        pass
    _prune(rawpipe._HTTP_MEM, lambda v: now - v[1] > AGE)
    _prune(rawpipe._PASS_BAD, lambda v: now - v > AGE)
    _prune(rawpipe._HTTP_LOG, lambda v: now - v > AGE)
    _prune(tlspass._DNS, lambda v: now - v[1] > AGE)
    _prune(tlspass._SESS, lambda v: now - v[2] > AGE)
    _prune(worker._HOSTMAP, lambda v: now - (v[2] - worker.HOST_TTL) > AGE)
    _prune(worker._PLCACHE, lambda v: now - v[0] > AGE)
    _prune(worker._cache, lambda v: now - v[0] > AGE)
    try:
        for k in list(worker._locks):
            if k not in worker._cache and not worker._locks[k].locked():
                worker._locks.pop(k, None)
    except Exception:
        pass


async def loop():
    if EVERY <= 0:
        return
    while True:
        await asyncio.sleep(EVERY)
        try:
            sweep()
        except Exception:
            pass
