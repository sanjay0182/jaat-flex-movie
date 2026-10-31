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

  /* raw: ReadableStreamDefaultReader of Uint8Array (the locked bytes).  info: {k: key hex, s: 4 byte salt hex, q: first sequence number}
     -> an object with  read() -> {done, value}  giving the plain bytes (HTTP head + body) */
  function opener(raw, info) {
    var keyP = subtle.importKey("raw", hex(info.k), "AES-GCM", false, ["decrypt"]);
    var salt = hex(info.s), seq = info.q || 0;
    var buf = new Uint8Array(0), eof = false, ended = false, out = [];

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
          var res = await decryptAll(recs, await keyP);
          for (var i = 0; i < res.length; i++) {
            if (res[i].type === 21) { ended = true; break; }         /* alert (close_notify): end of data */
            if (res[i].data.length) out.push(res[i].data);
          }
          if (out.length || ended) return;
          continue;
        }
        if (eof) { ended = true; return; }
        var r = await raw.read();
        if (r.done) eof = true; else append(r.value);
      }
    }

    return {
      read: async function () {
        if (!out.length && !ended) await fill();
        if (out.length) return { done: false, value: out.shift() };
        return { done: true, value: undefined };
      },
      cancel: function () { try { return raw.cancel(); } catch (e) {} }
    };
  }

  function indexOfHead(a) {
    for (var i = 0; i + 3 < a.length; i++) if (a[i] === 13 && a[i + 1] === 10 && a[i + 2] === 13 && a[i + 3] === 10) return i;
    return -1;
  }

  /* -> {status, headers: {lowercase name: value}, body: ReadableStream of the plain body bytes, limit: bytes the body should have (or -1)} */
  async function open(raw, info) {
    var o = opener(raw, info), head = new Uint8Array(0), rest = null;
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
          if (limit >= 0 && sent >= limit) { ctrl.close(); o.cancel(); return; }
          var r2 = await o.read();
          if (r2.done) { ctrl.close(); return; }
          v = r2.value;
        }
        if (limit >= 0 && sent + v.length > limit) v = v.subarray(0, limit - sent);
        sent += v.length;
        ctrl.enqueue(v);
        if (limit >= 0 && sent >= limit) { ctrl.close(); o.cancel(); }
      },
      cancel: function () { o.cancel(); }
    });
    return { status: status, headers: headers, body: body, limit: limit };
  }

  root.TLSDEC = { open: open, opener: opener, hex: hex };
  if (typeof module !== "undefined" && module.exports) module.exports = root.TLSDEC;
})(typeof self !== "undefined" ? self : globalThis);
