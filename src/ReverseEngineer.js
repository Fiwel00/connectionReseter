import pbkdf2Hmac from 'pbkdf2-hmac';
export async function resolve(challenge, password) {
    
    return challengeResolve(challenge, password).then((hashResponse) => {
        console.log(hashResponse)
        return hashResponse;
    })
}

function challengeResolve(challengeRaw, passwordRaw) {
return new Promise(
    (function (buildResponse, throwError) {
      let hash1,
        hash2,
        parsedChallenge = parseChallenge(challengeRaw),
        password = encodeUTF8(passwordRaw);
        try {
            hash1 = pbkdf2 (password, parsedChallenge.salt1, parsedChallenge.iterations1, 32)
        } catch (exception) {
            throwError(new Error('First pass failed: ' + exception.message))
        }
        try {
            hash2 = pbkdf2 (hash1, parsedChallenge.salt2, parsedChallenge.iterations2, 32)
        } catch (exception) {
            throwError(new Error('Second pass failed: ' + exception.message))
        }
        buildResponse(''.concat(ArrayBufferToHex(parsedChallenge.salt2), '$').concat(ArrayBufferToHex(hash2)))
    })
)
}

function parseChallenge(challengeRaw) {
  return function (challengeRaw) {
    const challenge = challengeRaw.trim().split('$');
    const prefix = challenge[0]
    const iteration1 = challenge[1]
    const hexSalt1 = challenge[2]
    const iteration2 = challenge[3]
    const hexSalt2 = challenge[4];
    if ('2' !== prefix) {
      throw new Error('Challenge has an unsupported version');
    }
    const iteration1Int = parseIterationToInt(iteration1);
    const iteration2Int = parseIterationToInt(iteration2);
    if (!hexSalt1 || !hexSalt2) {
      throw new Error('Missing salts');
    }
    return {
      salt1: parseHexSaltToIntArray(hexSalt1),
      salt2: parseHexSaltToIntArray(hexSalt2),
      iterations1: iteration1Int,
      iterations2: iteration2Int
    };
  } (challengeRaw);
}

function ArrayBufferToHex(arrayBuffer) {
    const utf8ArrayBuffer = new Uint8Array(arrayBuffer);
    return Array.from(utf8ArrayBuffer, (function (r) {
      return ('0' + r.toString(16)).slice( - 2)
    })).join('')
  }

function parseIterationToInt(r) {
    if (!r || !r.match(/^\d+$/)) throw new Error('Number of iterations is empty or invalid');
    var t;
    try {
        t = parseInt(r, 10)
    } catch (r) {
        throw new Error('Failed to parse iterations')
    }
    if (t <= 0) throw new Error('Number of iterations has to be greater than 0');
    return t
}
function encodeUTF8(r) {
    return new TextEncoder().encode(r)
}
function parseHexSaltToIntArray(r) {
    if (r.length % 2 != 0) throw new Error('String has an invalid length for a hex string');
    for (var t = [], n = 0; n < r.length; n += 2) {
        var e = void 0;
        try {
        e = parseInt(r.substr(n, 2), 16)
        } catch (r) {
        throw new Error('Invalid hex string')
        }
        t.push(e)
    }
    return new Uint8Array(t)
}


function pbkdf2 (password, salt, iteration, length) {
  var i = new o(password),
      a = i.digestLength,
      s = new Uint8Array(4),
      c = new Uint8Array(a),
      u = new Uint8Array(a),
      f = new Uint8Array(length)
    for (var index = 0;
      index * a < length;
      index++
    ) {
      var p = index + 1;
      s[0] = p >>> 24 & 255,
      s[1] = p >>> 16 & 255,
      s[2] = p >>> 8 & 255,
      s[3] = p >>> 0 & 255,
      i.reset(),
      i.update(salt),
      i.update(s),
      i.finish(u);
      for (var d = 0; d < a; d++) c[d] = u[d];
      for (d = 2; d <= iteration; d++) {
        i.reset(),
        i.update(u).finish(u);
        for (var v = 0; v < a; v++) c[v] ^= u[v]
      }
      for (d = 0; d < a && index * a + d < length; d++) f[index * a + d] = c[d]
    }
    for (index = 0; index < a; index++) c[index] = u[index] = 0;
    for (index = 0; index < 4; index++) s[index] = 0;
    return i.clean(),
    f
}



var o = function () {
    function t(t) {
      this.inner = new n,
      this.outer = new n,
      this.blockSize = this.inner.blockSize,
      this.digestLength = this.inner.digestLength;
      var e = new Uint8Array(this.blockSize);
      if (t.length > this.blockSize) (new n).update(t).finish(e).clean();
       else for (var r = 0; r < t.length; r++) e[r] = t[r];
      for (r = 0; r < e.length; r++) e[r] ^= 54;
      for (this.inner.update(e), r = 0; r < e.length; r++) e[r] ^= 106;
      for (
        this.outer.update(e),
        this.istate = new Uint32Array(8),
        this.ostate = new Uint32Array(8),
        this.inner._saveState(this.istate),
        this.outer._saveState(this.ostate),
        r = 0;
        r < e.length;
        r++
      ) e[r] = 0
    }
    return t.prototype.reset = function () {
      return this.inner._restoreState(this.istate, this.inner.blockSize),
      this.outer._restoreState(this.ostate, this.outer.blockSize),
      this
    },
    t.prototype.clean = function () {
      for (var t = 0; t < this.istate.length; t++) this.ostate[t] = this.istate[t] = 0;
      this.inner.clean(),
      this.outer.clean()
    },
    t.prototype.update = function (t) {
      return this.inner.update(t),
      this
    },
    t.prototype.finish = function (t) {
      return this.outer.finished ? this.outer.finish(t) : (
        this.inner.finish(t),
        this.outer.update(t, this.digestLength).finish(t)
      ),
      this
    },
    t.prototype.digest = function () {
      var t = new Uint8Array(this.digestLength);
      return this.finish(t),
      t
    },
    t
  }();

  var n = function () {
    function e() {
      this.digestLength = 32,
      this.blockSize = 64,
      this.state = new Int32Array(8),
      this.temp = new Int32Array(64),
      this.buffer = new Uint8Array(128),
      this.bufferLength = 0,
      this.bytesHashed = 0,
      this.finished = !1,
      this.reset()
    }
    return e.prototype.reset = function () {
      return this.state[0] = 1779033703,
      this.state[1] = 3144134277,
      this.state[2] = 1013904242,
      this.state[3] = 2773480762,
      this.state[4] = 1359893119,
      this.state[5] = 2600822924,
      this.state[6] = 528734635,
      this.state[7] = 1541459225,
      this.bufferLength = 0,
      this.bytesHashed = 0,
      this.finished = !1,
      this
    },
    e.prototype.clean = function () {
      for (var t = 0; t < this.buffer.length; t++) this.buffer[t] = 0;
      for (t = 0; t < this.temp.length; t++) this.temp[t] = 0;
      this.reset()
    },
    e.prototype.update = function (t, e) {
      if (void 0 === e && (e = t.length), this.finished) throw new Error('SHA256: can\'t update because hash was finished.');
      var n = 0;
      if (this.bytesHashed += e, this.bufferLength > 0) {
        for (; this.bufferLength < 64 && e > 0; ) this.buffer[this.bufferLength++] = t[n++],
        e--;
        64 === this.bufferLength &&
        (r(this.temp, this.state, this.buffer, 0, 64), this.bufferLength = 0)
      }
      for (e >= 64 && (n = r(this.temp, this.state, t, n, e), e %= 64); e > 0; ) this.buffer[this.bufferLength++] = t[n++],
      e--;
      return this
    },
    e.prototype.finish = function (t) {
      if (!this.finished) {
        var e = this.bytesHashed,
        n = this.bufferLength,
        o = e / 536870912 | 0,
        i = e << 3,
        a = e % 64 < 56 ? 64 : 128;
        this.buffer[n] = 128;
        for (var s = n + 1; s < a - 8; s++) this.buffer[s] = 0;
        this.buffer[a - 8] = o >>> 24 & 255,
        this.buffer[a - 7] = o >>> 16 & 255,
        this.buffer[a - 6] = o >>> 8 & 255,
        this.buffer[a - 5] = o >>> 0 & 255,
        this.buffer[a - 4] = i >>> 24 & 255,
        this.buffer[a - 3] = i >>> 16 & 255,
        this.buffer[a - 2] = i >>> 8 & 255,
        this.buffer[a - 1] = i >>> 0 & 255,
        r(this.temp, this.state, this.buffer, 0, a),
        this.finished = !0
      }
      for (s = 0; s < 8; s++) t[4 * s + 0] = this.state[s] >>> 24 & 255,
      t[4 * s + 1] = this.state[s] >>> 16 & 255,
      t[4 * s + 2] = this.state[s] >>> 8 & 255,
      t[4 * s + 3] = this.state[s] >>> 0 & 255;
      return this
    },
    e.prototype.digest = function () {
      var t = new Uint8Array(this.digestLength);
      return this.finish(t),
      t
    },
    e.prototype._saveState = function (t) {
      for (var e = 0; e < this.state.length; e++) t[e] = this.state[e]
    },
    e.prototype._restoreState = function (t, e) {
      for (var r = 0; r < this.state.length; r++) this.state[r] = t[r];
      this.bytesHashed = e,
      this.finished = !1,
      this.bufferLength = 0
    },
    e
  }();

  function r(t, r, n, o, i) {
    for (var a, s, c, u, f, l, p, d, v, h, y, g, m; i >= 64; ) {
      for (
        a = r[0],
        s = r[1],
        c = r[2],
        u = r[3],
        f = r[4],
        l = r[5],
        p = r[6],
        d = r[7],
        h = 0;
        h < 16;
        h++
      ) y = o + 4 * h,
      t[h] = (255 & n[y]) << 24 | (255 & n[y + 1]) << 16 | (255 & n[y + 2]) << 8 | 255 & n[y + 3];
      for (h = 16; h < 64; h++) g = ((v = t[h - 2]) >>> 17 | v << 15) ^ (v >>> 19 | v << 13) ^ v >>> 10,
      m = ((v = t[h - 15]) >>> 7 | v << 25) ^ (v >>> 18 | v << 14) ^ v >>> 3,
      t[h] = (g + t[h - 7] | 0) + (m + t[h - 16] | 0);
      for (h = 0; h < 64; h++) g = (((f >>> 6 | f << 26) ^ (f >>> 11 | f << 21) ^ (f >>> 25 | f << 7)) + (f & l ^ ~f & p) | 0) + (d + (e[h] + t[h] | 0) | 0) | 0,
      m = ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + (a & s ^ a & c ^ s & c) | 0,
      d = p,
      p = l,
      l = f,
      f = u + g | 0,
      u = c,
      c = s,
      s = a,
      a = g + m | 0;
      r[0] += a,
      r[1] += s,
      r[2] += c,
      r[3] += u,
      r[4] += f,
      r[5] += l,
      r[6] += p,
      r[7] += d,
      o += 64,
      i -= 64
    }
    return o
  }

  var e = new Uint32Array(
    [1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298]
  );