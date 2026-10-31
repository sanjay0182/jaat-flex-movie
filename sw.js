/* sw.js - the phone opens the video itself.
   The page asks the relay for  /p?e=..&t=..  (video or playlist segment).  This worker asks  /pt?e=..&t=..  instead.
   The relay then does NOT decrypt the CDN's TLS: it sends the locked bytes plus the key of that one connection
   (header X-Tls) and this worker opens them with WebCrypto (AES-GCM, hardware) and hands plain video to the player.
   Anything unusual (no X-Tls header = the relay used the normal way, errors, bad data) -> the normal /p request.
   Open-ended Range requests are cut into pieces of CHUNK bytes; the player simply asks for the next piece. */
importScripts("/tlsdec.js");

const CHUNK = 6 * 1024 * 1024;
let fails = 0, offUntil = 0;

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

async function go(rq, u) {
  try {
    const pt = new URL(u.href);
    pt.pathname = "/pt";
    const h = {};
    const range = cap(rq.headers.get("range"));
    if (range) h.Range = range;
    const dev = rq.headers.get("x-device");
    if (dev) h["X-Device"] = dev;
    const r = await fetch(pt.href, { headers: h, mode: "cors", credentials: "omit", cache: "no-store" });
    const x = r.headers.get("x-tls");
    if (!x) return r;                                   /* relay answered the normal way (plain http / playlist / error) */
    const [k, s, q] = x.split(".");
    const o = await TLSDEC.open(r.body.getReader(), { k: k, s: s, q: +q });
    if (o.status !== 200 && o.status !== 206) throw new Error("cdn status " + o.status);
    const hd = new Headers();
    hd.set("Content-Type", o.headers["content-type"] || "video/mp4");
    if (o.headers["content-length"]) hd.set("Content-Length", o.headers["content-length"]);
    if (o.headers["content-range"]) hd.set("Content-Range", o.headers["content-range"]);
    hd.set("Accept-Ranges", "bytes");
    fails = 0;
    return new Response(o.body, { status: o.status, headers: hd });
  } catch (e) {
    bad(e && e.message);
    return fetch(rq);                                   /* the normal way */
  }
}

self.addEventListener("fetch", e => {
  const rq = e.request;
  if (rq.method !== "GET" || Date.now() < offUntil) return;
  let u;
  try { u = new URL(rq.url); } catch (_) { return; }
  if (u.origin === self.location.origin || u.pathname !== "/p" || !u.searchParams.has("e") || !u.searchParams.has("t")) return;
  e.respondWith(go(rq, u));
});

if (typeof module !== "undefined") module.exports = { go, cap };
