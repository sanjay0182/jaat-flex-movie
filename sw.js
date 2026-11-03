/* sw.js - the phone opens the video itself.
   The page asks the relay for  /p?e=..&t=..  (video or playlist segment).  This worker asks  /pt?e=..&t=..  instead.
   The relay then does NOT decrypt the CDN's TLS: it sends the locked bytes plus the key of that one connection
   (header X-Tls) and this worker opens them with WebCrypto (AES-GCM, hardware) and hands plain video to the player.
   NEW: this worker also asks for  &k=1  = "I work out the key myself".  The relay then sends X-Tls2 = master secret + the two
   random numbers + hash + key length of that connection, and tlsdec.js derive() makes the key here (HMAC through WebCrypto).
   An older relay that does not know k=1 still sends X-Tls (finished key) - both are understood.
   Anything unusual (no X-Tls / X-Tls2 header = the relay used the normal way, errors, bad data) -> the normal /p request.
   LOG: every request writes lines starting with [sw #n] to the console (chrome://inspect -> service worker): how long each step took.
   Open-ended Range requests are cut into pieces of CHUNK bytes; the player simply asks for the next piece. */
importScripts("/tlsdec.js");

const CHUNK = 12 * 1024 * 1024;     /* bigger pieces = fewer new connections/handshakes on the relay */
let fails = 0, offUntil = 0, seqNo = 0;
const LOG = false;                                     /* false = no [sw] lines in the console */
const now = () => (self.performance && performance.now) ? performance.now() : Date.now();
function log(id, msg) { if (LOG) try { console.log("[sw #" + id + "] " + msg); } catch (e) {} }

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));

function cap(r) {
  if (!r) return null;
  const m = /^bytes=(\d+)-(\d*)$/.exec(r.trim());
  if (!m) return r;
  const a = +m[1];
  let b = m[2] === "" ? Infinity : +m[2];
  if (b - a + 1 > CHUNK) b = a + CHUNK - 1;
  return "bytes=" + a + "-" + (isFinite(b) ? b : "");
}

function bad(why) {
  fails++;
  if (fails >= 5) { offUntil = Date.now() + 30 * 60 * 1000; fails = 0; }
  try { console.warn("[sw] pass-through failed:", why); } catch (e) {}
}

async function go(rq, u, strict) {
  const id = ++seqNo, t0 = now();
  try {
    const pt = new URL(u.href);
    pt.pathname = "/pt";
    pt.searchParams.set("k", "1");                      /* "I work out the key myself" (an old relay ignores it) */
    const h = {};
    const range = cap(rq.headers.get("range"));
    if (range) h.Range = range;
    const dev = rq.headers.get("x-device");
    if (dev) h["X-Device"] = dev;
    log(id, "ask the relay /pt  range=" + (range || "-") + (rq.headers.get("range") !== range ? " (player asked " + rq.headers.get("range") + ")" : ""));
    const r = await fetch(pt.href, { headers: h, mode: "cors", credentials: "omit", cache: "no-store" });
    const t1 = now();
    const x2 = r.headers.get("x-tls2"), x = r.headers.get("x-tls");
    log(id, "relay answered in " + (t1 - t0).toFixed(0) + "ms (this is the relay's whole setup: handshake with the CDN etc.)  http " + r.status + "  key header: " + (x2 ? "X-Tls2 (I work out the key)" : x ? "X-Tls (relay worked out the key)" : "none"));
    if (!x && !x2) { log(id, "relay used the normal way (plain http / playlist / error): passing its answer on as it is"); return r; }
    let info, how;
    if (x2) {
      const [ms, cr, sr, hh, klen, q] = x2.split(".");
      const d = await TLSDEC.derive({ ms: ms, cr: cr, sr: sr, h: +hh, klen: +klen });
      info = { k: d.k, s: d.s, q: +q };
      how = "worked out the key here in " + d.ms.toFixed(2) + "ms (HMAC-SHA" + hh + ", " + (+klen * 8) + " bit key)";
    } else {
      const [k, s, q] = x.split(".");
      info = { k: k, s: s, q: +q };
      how = "key came from the relay";
    }
    log(id, how);
    info.onend = (st, why) => log(id, "body done (" + why + "): " + (st.plainBytes / 1048576).toFixed(2) + "MB opened from " + (st.rawBytes / 1048576).toFixed(2) +
      "MB locked | " + st.recs + " records | waiting for the network " + st.netMs.toFixed(0) + "ms (" + st.reads + " reads) | decrypting (AES-GCM) " + st.decMs.toFixed(0) +
      "ms | whole request " + (now() - t0).toFixed(0) + "ms");
    const t2 = now();
    const o = await TLSDEC.open(r.body.getReader(), info);
    log(id, "read + decrypted the CDN's answer head in " + (now() - t2).toFixed(0) + "ms: cdn status " + o.status + ", content-length " + (o.headers["content-length"] || "-") + ", content-range " + (o.headers["content-range"] || "-"));
    if (o.status !== 200 && o.status !== 206) throw new Error("cdn status " + o.status);
    const hd = new Headers();
    hd.set("Content-Type", o.headers["content-type"] || "video/mp4");
    if (o.headers["content-length"]) hd.set("Content-Length", o.headers["content-length"]);
    if (o.headers["content-range"]) hd.set("Content-Range", o.headers["content-range"]);
    hd.set("Accept-Ranges", "bytes");
    fails = 0;
    log(id, "player gets the video after " + (now() - t0).toFixed(0) + "ms");
    return new Response(o.body, { status: o.status, headers: hd });
  } catch (e) {
    log(id, "FAILED after " + (now() - t0).toFixed(0) + "ms: " + (e && e.message) + (strict ? "  (download: no fallback)" : "  -> using the normal /p way"));
    if (strict) throw e;                                /* download: no fallback to the relay-decrypt way */
    bad(e && e.message);
    return fetch(rq);                                   /* the normal way */
  }
}

/* ===== DOWNLOAD ON THE PHONE =====
   The page opens (hidden iframe)  /__sw_dl?u=<relay /p link>&n=<file name>.  This worker then asks the relay for the file piece by piece
   (the same pass-through as the player: the relay does NOT decrypt, this phone does; NO fallback to any other way) and hands the plain bytes to the browser's download
   manager with Content-Disposition: attachment.  Nothing of the file goes through Render.  Failed piece = tried again from the same byte. */
const DL_PATH = "/__sw_dl";
const dlSafe = n => String(n || "").replace(/[^A-Za-z0-9._-]+/g, "").slice(0, 120) || "video.mp4";
const dlSleep = ms => new Promise(r => setTimeout(r, ms));
function dlTell(ok) { try { self.clients.matchAll({ includeUncontrolled: true }).then(l => l.forEach(c => c.postMessage({ t: "dl-end", ok: ok !== false }))).catch(() => {}); } catch (e) {} }
function dlPiece(link, a, b) {
  const rq = new Request(link.href, { headers: { Range: "bytes=" + a + "-" + b }, mode: "cors", credentials: "omit" });
  return go(rq, link, true);                                     /* pass-through on the phone only (same as the player), NO fallback; a failed piece is simply asked again */
}
async function dlHandle(u, fin) {
  const end = ok => { dlTell(ok); try { fin(); } catch (e) {} };
  let link;
  try { link = new URL(u.searchParams.get("u") || ""); } catch (_) { end(false); return new Response("bad link", { status: 400 }); }
  if (link.pathname !== "/p" || !link.searchParams.has("e") || !link.searchParams.has("t")) { end(false); return new Response("bad link", { status: 400 }); }
  const name = dlSafe(u.searchParams.get("n"));
  let first = null;
  for (let i = 0; i < 3 && !first; i++) {
    try { const x = await dlPiece(link, 0, CHUNK - 1); if (x.status === 200 || x.status === 206) first = x; } catch (e) {}
    if (!first) await dlSleep(1000 * (i + 1));
  }
  if (!first) { end(false); return new Response("Download failed", { status: 502 }); }
  const cm = /\/(\d+)\s*$/.exec(first.headers.get("content-range") || "");
  const whole = first.status === 200;                                   /* the server ignored Range: this body is the whole file */
  const total = cm ? +cm[1] : (whole ? (+first.headers.get("content-length") || 0) : 0);
  let ct = first.headers.get("content-type") || "video/mp4";
  if (!/^(video|application)\//i.test(ct)) ct = "video/mp4";
  let reader = first.body.getReader(), pos = 0, piece = 0, bad = 0;
  const body = new ReadableStream({
    async pull(ctrl) {
      try {
        for (;;) {
          let r;
          try { r = await reader.read(); } catch (e) { r = { done: true, broken: true }; }
          if (!r.done) { pos += r.value.length; piece += r.value.length; bad = 0; ctrl.enqueue(r.value); return; }
          if (whole && !r.broken) { ctrl.close(); end(); return; }
          if (!r.broken && (total ? pos >= total : piece < CHUNK)) { ctrl.close(); end(); return; }
          if (whole) throw new Error("connection lost");
          if (++bad > 6) throw new Error("download stopped at byte " + pos);
          piece = 0;
          let nx = null;
          try { nx = await dlPiece(link, pos, pos + CHUNK - 1); } catch (e) { nx = null; }
          if (nx && nx.status === 416) { ctrl.close(); end(); return; }
          if (!nx || nx.status !== 206) { await dlSleep(1000 * bad); continue; }
          try { reader.cancel(); } catch (e) {}
          reader = nx.body.getReader();
        }
      } catch (e) { end(false); ctrl.error(e); }
    },
    cancel() { try { reader.cancel(); } catch (e) {} end(); }
  });
  const hd = new Headers({ "Content-Type": ct, "Content-Disposition": 'attachment; filename="' + name + '"', "Cache-Control": "no-store" });
  if (total) hd.set("Content-Length", String(total));
  return new Response(body, { status: 200, headers: hd });
}
self.addEventListener("message", () => {});                   /* a ping from the page while a download runs: keeps this worker alive */

self.addEventListener("fetch", e => {
  const rq = e.request;
  let u0;
  try { u0 = new URL(rq.url); } catch (_) { return; }
  if (rq.method === "GET" && u0.origin === self.location.origin && u0.pathname === DL_PATH) {
    let fin; const dp = new Promise(r => { fin = r; });
    e.waitUntil(dp);
    e.respondWith(dlHandle(u0, fin));
    return;
  }
  if (rq.method !== "GET" || Date.now() < offUntil) return;
  let u;
  try { u = new URL(rq.url); } catch (_) { return; }
  if (u.origin === self.location.origin || u.pathname !== "/p" || !u.searchParams.has("e") || !u.searchParams.has("t")) return;
  e.respondWith(go(rq, u));
});

if (typeof module !== "undefined") module.exports = { go, cap };
