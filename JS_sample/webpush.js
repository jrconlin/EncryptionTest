/*
 * Browser-based Web Push client for the application server piece.
 *
 * Uses the WebCrypto API.
 * Uses the fetch API.  Polyfill: https://github.com/github/fetch
 */

  'use strict';
  var g = window;
  var RemoteShareKeyStr="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKai6v1IJr_HcWxR8TWur_exp1DUkPgnYVYToUyO0e95LMyUnlEu82hl7B_jEdckPZjbDm7MoJHKMf0CapvIRwg==";
  var staticSalt = "a4UV9oUyAtX6ztg4CNiLww";

  var P256DH = {
    name: 'ECDH',
    namedCurve: 'P-256'
  };
  var webCrypto = g.crypto.subtle;
  var ENCRYPT_INFO = new TextEncoder('utf-8').encode("Content-Encoding: aesgcm128");
  var NONCE_INFO = new TextEncoder('utf-8').encode("Content-Encoding: nonce");

  function chunkArray(array, size) {
    var start = array.byteOffset || 0;
    array = array.buffer || array;
    var index = 0;
    var result = [];
    while(index + size <= array.byteLength) {
      result.push(new Uint8Array(array, start + index, size));
      index += size;
    }
    if (index <= array.byteLength) {
      result.push(new Uint8Array(array, start + index));
    }
    return result;
  }

  /* I can't believe that this is needed here, in this day and age ...
   * Note: these are not efficient, merely expedient.
   */
  var base64url = {
    _strmap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
    encode: function(data) {
      data = new Uint8Array(data);
      var len = Math.ceil(data.length * 4 / 3);
      return chunkArray(data, 3).map(chunk => [
        chunk[0] >>> 2,
        ((chunk[0] & 0x3) << 4) | (chunk[1] >>> 4),
        ((chunk[1] & 0xf) << 2) | (chunk[2] >>> 6),
        chunk[2] & 0x3f
      ].map(v => base64url._strmap[v]).join('')).join('').slice(0, len);
    },
    _lookup: function(s, i) {
      return base64url._strmap.indexOf(s.charAt(i));
    },
    decode: function(str) {
      var v = new Uint8Array(Math.floor(str.length * 3 / 4));
      var vi = 0;
      for (var si = 0; si < str.length;) {
        var w = base64url._lookup(str, si++);
        var x = base64url._lookup(str, si++);
        var y = base64url._lookup(str, si++);
        var z = base64url._lookup(str, si++);
        v[vi++] = w << 2 | x >>> 4;
        v[vi++] = x << 4 | y >>> 2;
        v[vi++] = y << 6 | z;
      }
      return v;
    }
  };

  g.base64url = base64url;

  /* Coerces data into a Uint8Array */
  function ensureView(data) {
    if (typeof data === 'string') {
      return new TextEncoder('utf-8').encode(data);
    }
    if (data instanceof ArrayBuffer) {
      return new Uint8Array(data);
    }
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer);
    }
    throw new Error('webpush() needs a string or BufferSource');
  }

  function bsConcat(arrays) {
    var size = arrays.reduce((total, a) => total + a.byteLength, 0);
    var index = 0;
    return arrays.reduce((result, a) => {
      result.set(new Uint8Array(a), index);
      index += a.byteLength;
      return result;
    }, new Uint8Array(size));
  }

  function hmac(key) {
    this.keyPromise = webCrypto.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' },
                                          false, ['sign']);
  }
  hmac.prototype.hash = function(input) {
    return this.keyPromise.then(k => webCrypto.sign('HMAC', k, input));
  }

  function hkdf(salt, ikm) {
    this.prkhPromise = new hmac(salt).hash(ikm)
      .then(prk => new hmac(prk));
  }

  hkdf.prototype.generate = function(info, len) {
    var input = bsConcat([info, new Uint8Array([1])]);
    return this.prkhPromise
      .then(prkh => prkh.hash(input))
      .then(h => {
        if (h.byteLength < len) {
          throw new Error('Length is too long');
        }
        var reply;
        reply  = h.slice(0, len);
        // console.debug("hkdf gen", base64url.encode(new Int8Array(reply)));
        return reply;
      });
  };

  Promise.allMap = function(o) {
    var result = {};
    return Promise.all(
      Object.keys(o).map(
        k => Promise.resolve(o[k]).then(r => result[k] = r)
      )
    ).then(_ => result);
  };

  /* generate a 96-bit IV for use in GCM, 48-bits of which are populated */
  function generateNonce(base, index) {
    var nonce = base.slice(0, 12);
    for (var i = 0; i < 6; ++i) {
      nonce[nonce.length - 1 - i] ^= (index / Math.pow(256, i)) & 0xff;
    }
    return nonce;
  }

  function encrypt(localKey, remoteShare, salt, data) {
    return webCrypto.importKey('raw', remoteShare, P256DH, false, ['deriveBits'])
      .then(remoteKey =>
            webCrypto.deriveBits({ name: P256DH.name, public: remoteKey },
                                 localKey, 256))
      .then(rawKey => {
          // inject fake key here?
          console.debug("salt", base64url.encode(salt), "\n",
                        "sharedKey", base64url.encode(new Int8Array(rawKey)));
          var kdf = new hkdf(salt, rawKey);
          return Promise.allMap({
            key: kdf.generate(ENCRYPT_INFO, 16)
              .then(gcmBits => {
                console.debug('gcmB', base64url.encode(new Int8Array(gcmBits)));
                return webCrypto.importKey('raw', gcmBits, 'AES-GCM', false, ['encrypt'])}),
            nonce: kdf.generate(NONCE_INFO, 12)
              .then(n => {
                console.debug('nonce', base64url.encode(new Int8Array(n)));
                return n})
          })
      })
      .then(r => {
          // 4096 is the default size, though we burn 1 for padding
          console.debug("r",r);
          return Promise.all(chunkArray(data, 4095).map((slice, index) => {
            var padded = bsConcat([new Uint8Array([0]), slice]);
            var iv = generateNonce(r.nonce, index);
            console.debug("iv nonce :", base64url.encode(iv));
            return webCrypto.encrypt({
              name: 'AES-GCM',
              iv: iv,
            }, r.key, padded);
          }));
    }).then(bsConcat)
    .catch(x => console.error(x));
  }

  /*
   * Request push for a message.  This returns a promise that resolves when the
   * push has been delivered to the push service.
   *
   * @param subscription A PushSubscription that contains endpoint and p256dh
   *                     parameters.
   * @param data         The message to send.
   */
  function webpush(subscription, data) {
    data = ensureView(data);

    var salt;
    if (staticSalt) {
        console.debug("Using static salt");
        salt = base64url.decode(staticSalt);
    } else {
        console.debug("Making new salt");
        salt = g.crypto.getRandomValues(new Uint8Array(16));
    }
    return webCrypto.generateKey(P256DH, false, ['deriveBits'])
      .then(localKey => {

        return Promise.allMap({
          payload: encrypt(localKey.privateKey, subscription.p256dh, salt, data),
          // 1337 p-256 specific haxx to get the raw value out of the spki value
          pubkey: webCrypto.exportKey('raw', localKey.publicKey)
        });
      }).then(results => {
        var options = {
          method: 'PUT',
          headers: {
            'Encryption-Key': 'keyid=p256dh;dh=' + base64url.encode(results.pubkey),
            Encryption: 'keyid=p256dh;salt=' + base64url.encode(salt),
            'Content-Encoding': 'aesgcm128'
          },
          body: base64url.encode(results.payload),
        };
        console.debug("Output", options)
        //return fetch(subscription.endpoint, options);
      })
      /*.then(response => {
        if (response.status / 100 !== 2) {
          throw new Error('Unable to deliver message');
        }
      }
    );
    */
  }

var hkdf_test = new hkdf(base64url.decode(staticSalt), base64url.decode(RemoteShareKeyStr));
hkdf_test.generate(NONCE_INFO, 12).then(result => console.debug("hkdf_test", base64url.encode(result)));

webpush({p256dh: base64url.decode(RemoteShareKeyStr)},
        "Mary had a little lamb with some fresh mint jelly");