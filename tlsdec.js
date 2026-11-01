/* tlsdec.js - opens the TLS 1.2 AES-GCM records that the relay copied from the CDN without decrypting them.
   Used by sw.js (importScripts) and by the tests (require). Needs WebCrypto (crypto.subtle). */
(function (root) {
  "use strict";
  var subtle = (root.crypto && root.crypto.subtle) || (typeof require === "function" ? require("crypto").webcrypto.subtle : null);

  function hex(h) {
    var o = new Uint8Array(h.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16);
    return o;
  }

  function now() { return (root.performance && root.performance.now) ? root.performance.now() : Date.now(); }

  function concat() {
    var n = 0, i;
    for (i = 0; i < arguments.length; i++) n += arguments[i].length;
    var o = new Uint8Array(n), p = 0;
    for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }

  /* The phone works out the key of the relay's CDN connection itself (TLS 1.2 key expansion, RFC 5246 section 5 + 6.3):
       key_block = PRF(master_secret, "key expansion", server_random + client_random)
       PRF = P_hash:  A(0) = seed,  A(i) = HMAC(secret, A(i-1)),  output = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) ...
     key_block = client_write_key | server_write_key | client_write_IV(4) | server_write_IV(4)  -> we need the server ones.
     info: {ms, cr, sr: hex strings, h: 256 | 384, klen: key bytes (16 or 32)}  ->  {k: Uint8Array key, s: Uint8Array 4 byte salt, ms: time it took} */
  async function derive(info) {
    var t0 = now();
    var hash = +info.h === 384 ? "SHA-384" : "SHA-256";
    var klen = info.klen | 0, need = 2 * klen + 8;
    var seed = concat(new TextEncoder().encode("key expansion"), hex(info.sr), hex(info.cr));
    var key = await subtle.importKey("raw", hex(info.ms), { name: "HMAC", hash: hash }, false, ["sign"]);
    var out = new Uint8Array(0), a = seed;
    while (out.length < need) {
      a = new Uint8Array(await subtle.sign("HMAC", key, a));
      out = concat(out, new Uint8Array(await subtle.sign("HMAC", key, concat(a, seed))));
    }
    return { k: out.slice(klen, 2 * klen), s: out.slice(2 * klen + 4, 2 * klen + 8), ms: now() - t0 };
  }

  /* raw: ReadableStreamDefaultReader of Uint8Array (the locked bytes).
     info: {k: key (hex string OR Uint8Array), s: 4 byte salt (hex OR Uint8Array), q: first sequence number}
     -> an object with  read() -> {done, value}  giving the plain bytes (HTTP head + body)  and  stats  (what it did, for the log) */
  function opener(raw, info) {
    var keyP = subtle.importKey("raw", typeof info.k === "string" ? hex(info.k) : info.k, "AES-GCM", false, ["decrypt"]);
    var salt = typeof info.s === "string" ? hex(info.s) : info.s, seq = info.q || 0;
    var buf = new Uint8Array(0), eof = false, ended = false, out = [];
    var stats = { recs: 0, rawBytes: 0, plainBytes: 0, decMs: 0, netMs: 0, reads: 0 };

    function append(c) {
      var n = new Uint8Array(buf.length + c.length);
      n.set(buf, 0); n.set(c, buf.length); buf = n;
    }

    async function decryptAll(recs, key) {
      return Promise.all(recs.map(function (r) {
        var iv = new Uint8Array(12); iv.set(salt, 0); iv.set(r.explicit, 4);
        var aad = new Uint8Array(13), dv = new DataView(aad.buffer);
        dv.setUint32(0, Math.floor(r.seq / 4294967296)); dv.setUint32(4, r.seq >>> 0);
        aad[8] = r.type; aad[9] = 3; aad[10] = 3; dv.setUint16(11, r.plainLen);
        return subtle.decrypt({ name: "AES-GCM", iv: iv, additionalData: aad, tagLength: 128 }, key, r.ct)
          .then(function (p) { return { type: r.type, data: new Uint8Array(p) }; });
      }));
    }

    async function fill() {
      /* read until at least one whole record is in buf, then take every whole record that is there */
      for (;;) {
        var recs = [], pos = 0;
        while (buf.length - pos >= 5) {
          var len = (buf[pos + 3] << 8) | buf[pos + 4];
          if (len > 18432 + 2048) throw new Error("bad tls record length");
          if (buf.length - pos < 5 + len) break;
          var type = buf[pos];
          if (type !== 23 && type !== 21) throw new Error("unexpected tls record type " + type);
          if (len < 24) throw new Error("short tls record");
          recs.push({ type: type, seq: seq++, explicit: buf.subarray(pos + 5, pos + 13), ct: buf.slice(pos + 13, pos + 5 + len), plainLen: len - 24 });
          pos += 5 + len;
        }
        if (recs.length) {
          buf = buf.slice(pos);
          var td = now();
          var res = await decryptAll(recs, await keyP);
          stats.decMs += now() - td; stats.recs += recs.length;
          for (var i = 0; i < res.length; i++) {
            if (res[i].type === 21) { ended = true; break; }         /* alert (close_notify): end of data */
            if (res[i].data.length) { out.push(res[i].data); stats.plainBytes += res[i].data.length; }
          }
          if (out.length || ended) return;
          continue;
        }
        if (eof) { ended = true; return; }
        var tn = now();
        var r = await raw.read();
        stats.netMs += now() - tn; stats.reads++;
        if (r.done) eof = true; else { append(r.value); stats.rawBytes += r.value.length; }
      }
    }

    return {
      read: async function () {
        if (!out.length && !ended) await fill();
        if (out.length) return { done: false, value: out.shift() };
        return { done: true, value: undefined };
      },
      cancel: function () { try { return raw.cancel(); } catch (e) {} },
      stats: stats
    };
  }

  function indexOfHead(a) {
    for (var i = 0; i + 3 < a.length; i++) if (a[i] === 13 && a[i + 1] === 10 && a[i + 2] === 13 && a[i + 3] === 10) return i;
    return -1;
  }

  /* -> {status, headers: {lowercase name: value}, body: ReadableStream of the plain body bytes, limit: bytes the body should have (or -1), stats}
     info.onend(stats, why) (optional) is called once when the body is finished / cancelled */
  async function open(raw, info) {
    var o = opener(raw, info), head = new Uint8Array(0), rest = null;
    var ended = false;
    function fin(why) { if (ended) return; ended = true; try { if (info.onend) info.onend(o.stats, why); } catch (e) {} }
    for (;;) {
      var r = await o.read();
      if (r.done) throw new Error("closed before http head");
      var n = new Uint8Array(head.length + r.value.length); n.set(head, 0); n.set(r.value, head.length); head = n;
      var i = indexOfHead(head);
      if (i >= 0) { rest = head.slice(i + 4); head = head.slice(0, i); break; }
      if (head.length > 32768) throw new Error("http head too big");
    }
    var lines = new TextDecoder("latin1").decode(head).split("\r\n");
    var status = parseInt(lines[0].split(" ")[1], 10), headers = {};
    for (var j = 1; j < lines.length; j++) {
      var c = lines[j].indexOf(":");
      if (c > 0) headers[lines[j].slice(0, c).trim().toLowerCase()] = lines[j].slice(c + 1).trim();
    }
    if (headers["transfer-encoding"]) throw new Error("chunked body not supported");
    var limit = /^\d+$/.test(headers["content-length"] || "") ? parseInt(headers["content-length"], 10) : -1;
    var sent = 0, first = rest && rest.length ? rest : null;
    var body = new ReadableStream({
      async pull(ctrl) {
        var v;
        if (first) { v = first; first = null; }
        else {
          if (limit >= 0 && sent >= limit) { ctrl.close(); o.cancel(); fin("all " + sent + " bytes delivered"); return; }
          var r2 = await o.read();
          if (r2.done) { ctrl.close(); fin("connection ended after " + sent + " bytes"); return; }
          v = r2.value;
        }
        if (limit >= 0 && sent + v.length > limit) v = v.subarray(0, limit - sent);
        sent += v.length;
        ctrl.enqueue(v);
        if (limit >= 0 && sent >= limit) { ctrl.close(); o.cancel(); fin("all " + sent + " bytes delivered"); }
      },
      cancel: function () { o.cancel(); fin("player cancelled after " + sent + " bytes"); }
    });
    return { status: status, headers: headers, body: body, limit: limit, stats: o.stats };
  }

  root.TLSDEC = { open: open, opener: opener, hex: hex, derive: derive };
  if (typeof module !== "undefined" && module.exports) module.exports = root.TLSDEC;
})(typeof self !== "undefined" ? self : globalThis);
