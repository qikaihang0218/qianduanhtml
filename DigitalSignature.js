/**
 * DigitalSignature.js
 * 基于 Web Crypto API 的 RSASSA-PKCS1-v1_5 / SHA-256 数字签名工具类。
 * 兼容浏览器（需安全上下文 localhost/HTTPS）与 Node.js（17+ 提供 globalThis.crypto）。
 * 纯本地运算，私钥只在浏览器内存中使用，永不上传。
 *
 * ── 浏览器中使用 ─────────────────────────────────────────────
 *   <script src="DigitalSignature.js"></script>
 *   (async () => {
 *     const ds  = new DigitalSignature();
 *     const { publicKeyPem, privateKeyPem } = await ds.generateKeyPair(); // 生成密钥对
 *     const signature = await ds.sign(privateKeyPem, '要签名的内容');       // 私钥签名 -> Base64
 *     const valid     = await ds.verify(publicKeyPem, signature, '要签名的内容'); // 公钥验签
 *     console.log(valid === true); // true
 *   })();
 *
 * ── Node.js 中使用 ──────────────────────────────────────────
 *   const { DigitalSignature } = require('./DigitalSignature.js'); // 或 import
 *   （同上用法）
 */
(function (root, factory) {
  const cls = factory();
  if (typeof module === 'object' && module && typeof module.exports === 'object') {
    module.exports = cls;                 // CommonJS
  } else if (typeof define === 'function' && define.amd) {
    define([], () => cls);                // AMD
  } else {
    root.DigitalSignature = cls;          // 浏览器全局
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class DigitalSignature {
    // RSASSA-PKCS1-v1_5，RSA-2048，哈希 SHA-256
    static DEFAULT_ALGO = {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    };

    constructor(options = {}) {
      if (!globalThis.crypto || !globalThis.crypto.subtle) {
        throw new Error('当前环境不支持 Web Crypto API。浏览器请通过 localhost 或 HTTPS 打开；Node.js 需要 17+。');
      }
      this.algo = Object.assign({}, DigitalSignature.DEFAULT_ALGO, options.algo || {});
    }

    /* ---------- 密钥对 ---------- */
    async generateKeyPair() {
      const keyPair = await globalThis.crypto.subtle.generateKey(this.algo, true, ['sign', 'verify']);
      const publicKeyPem = await this._export('spki', keyPair.publicKey, 'PUBLIC KEY');
      const privateKeyPem = await this._export('pkcs8', keyPair.privateKey, 'PRIVATE KEY');
      return { publicKeyPem, privateKeyPem };
    }

    /**
     * 导入公钥（PEM）。validForVerify 可选，默认 'verify'。
     */
    async importPublicKey(pem, usages = ['verify']) {
      const der = this.pemToDer(pem);
      return globalThis.crypto.subtle.importKey('spki', der, this.algo, true, usages);
    }

    /**
     * 导入私钥（PEM）。默认用途 'sign'。
     */
    async importPrivateKey(pem, usages = ['sign']) {
      const der = this.pemToDer(pem);
      return globalThis.crypto.subtle.importKey('pkcs8', der, this.algo, true, usages);
    }

    /**
     * 用私钥（字符串或 CryptoKey）对文本签名，返回 Base64 签名。
     */
    async sign(key, text) {
      const cryptoKey = typeof key === 'string' ? await this.importPrivateKey(key) : key;
      const data = new TextEncoder().encode(text);
      const sig = await globalThis.crypto.subtle.sign(this.algo.name, cryptoKey, data);
      return this._bufToB64(sig);
    }

    /**
     * 用公钥验签。返回布尔：true 有效，false 无效（或被篡改/不匹配）。
     */
    async verify(key, signatureBase64, text) {
      const cryptoKey = typeof key === 'string' ? await this.importPublicKey(key) : key;
      const data = new TextEncoder().encode(text);
      const sigBuf = this.b64ToBuf(signatureBase64);
      return await globalThis.crypto.subtle.verify(this.algo.name, cryptoKey, sigBuf, data);
    }

    /* ---------- 底层工具（也可直接复用） ---------- */
    async _export(format, cryptoKey, label) {
      const der = await globalThis.crypto.subtle.exportKey(format, cryptoKey);
      return this.derToPem(der, label);
    }

    derToPem(derBuffer, label) {
      const b64 = this._bufToB64(derBuffer).match(/.{1,64}/g).join('\n');
      return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
    }

    pemToDer(pem) {
      const b64 = pem
        .replace(/-----BEGIN [^-]+-----/, '')
        .replace(/-----END [^-]+-----/, '')
        .replace(/\s/g, '');
      return this.b64ToBuf(b64);
    }

    _bufToB64(buf) {
      const bytes = new Uint8Array(buf);
      let bin = '';
      const CH = 0x8000;
      for (let i = 0; i < bytes.length; i += CH) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
      }
      return btoa ? btoa(bin) : Buffer.from(bin, 'binary').toString('base64');
    }

    b64ToBuf(b64) {
      const bin = atob
        ? atob(b64.replace(/\s/g, ''))
        : Buffer.from(b64.replace(/\s/g, ''), 'base64').toString('binary');
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes.buffer;
    }
  }

  return DigitalSignature;
});
