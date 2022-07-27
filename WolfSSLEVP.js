"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
exports.WolfSSLDecryptionStream = exports.WolfSSLEncryptionStream = exports.WolfSSLDecryptor = exports.WolfSSLEncryptor = void 0;
var wolfcrypt = require('./build/Release/wolfcrypt');
var stream = require('stream');
var WolfSSLEVP = /** @class */ (function () {
    function WolfSSLEVP() {
        this.evp = wolfcrypt.EVP_CIPHER_CTX_new();
        this.totalInputLength = 0;
    }
    /**
     * Updates the internal state with data for cipher.
     *
     * @param data The data that will be added to the cipher.
     *
     * @returns The result data if possible.
     *
     * @throws {Error} If the decryption fails.
     *
     * @remarks This function should be called multiple times.
     */
    WolfSSLEVP.prototype.update = function (data) {
        this.totalInputLength += data.length;
        var outBuffer = Buffer.alloc(this.totalInputLength);
        var ret = wolfcrypt.EVP_CipherUpdate(this.evp, outBuffer, data, data.length);
        if (ret < 0) {
            throw 'Failed to update cipher';
        }
        if (ret > 0) {
            this.totalInputLength -= ret;
            return outBuffer.subarray(0, ret);
        }
        return Buffer.alloc(0);
    };
    /**
     * Finalize the decryption process.
     *
     * @returns The last block of decrypted data.
     *
     * @throws {Error} If the decryption fails.
     *
     * @remarks This function should be called once to finalize the decryption
     * process.
     */
    WolfSSLEVP.prototype.finalize = function () {
        if (this.totalInputLength % 16 != 0) {
            this.totalInputLength += (16 - this.totalInputLength % 16);
        }
        var outBuffer = Buffer.alloc(this.totalInputLength);
        this.totalInputLength = 0;
        var ret = wolfcrypt.EVP_CipherFinal(this.evp, outBuffer);
        wolfcrypt.EVP_CIPHER_CTX_free(this.evp);
        if (ret < 0) {
            throw 'Failed to finalize cipher';
        }
        if (ret > 0) {
            return outBuffer.subarray(0, ret);
        }
        return Buffer.alloc(0);
    };
    return WolfSSLEVP;
}());
var WolfSSLEncryptor = /** @class */ (function (_super) {
    __extends(WolfSSLEncryptor, _super);
    /**
     * Initializes a new instance of the WolfSSLEncryptor class.
     *
     * @param cipher The cipher name to use.
     * @param key    The decryption key to use.
     * @param iv     The initialization vector.
     *
     * @throws {Error} If cipher is not available or unknown.
     * @throws {Error} If the creation of the Decryption object failed.
     */
    function WolfSSLEncryptor(cipher, key, iv) {
        var _this = _super.call(this) || this;
        wolfcrypt.EVP_CipherInit(_this.evp, cipher, key, iv, 1);
        return _this;
    }
    return WolfSSLEncryptor;
}(WolfSSLEVP));
exports.WolfSSLEncryptor = WolfSSLEncryptor;
var WolfSSLDecryptor = /** @class */ (function (_super) {
    __extends(WolfSSLDecryptor, _super);
    /**
     * Initializes a new instance of the WolfSSLDecryptor class.
     *
     * @param cipher The cipher name to use.
     * @param key    The decryption key to use.
     * @param iv     The initialization vector.
     *
     * @throws {Error} If cipher is not available or unknown.
     * @throws {Error} If the creation of the Decryption object failed.
     */
    function WolfSSLDecryptor(cipher, key, iv) {
        var _this = _super.call(this) || this;
        wolfcrypt.EVP_CipherInit(_this.evp, cipher, key, iv, 0);
        return _this;
    }
    return WolfSSLDecryptor;
}(WolfSSLEVP));
exports.WolfSSLDecryptor = WolfSSLDecryptor;
var WolfSSLEncryptionStream = /** @class */ (function (_super) {
    __extends(WolfSSLEncryptionStream, _super);
    /**
     * Initializes a new instance of the WolfSSLEncryptionStream class.
     *
     * @param cipher The cipher name to use.
     * @param key    The decryption key to use.
     * @param iv     The initialization vector.
     *
     * @throws {Error} If cipher is not available or unknown.
     * @throws {Error} If the creation of the Decryption object failed.
     */
    function WolfSSLEncryptionStream(cipher, key, iv) {
        var _this = _super.call(this) || this;
        _this.encryptor = new WolfSSLEncryptor(cipher, key, iv);
        return _this;
    }
    WolfSSLEncryptionStream.prototype._transform = function (chunk, enc, cb) {
        var buffer = Buffer.isBuffer(chunk) ? chunk : new Buffer(chunk, enc);
        var ret_buffer = this.encryptor.update(chunk);
        if (ret_buffer.length > 0) {
            this.push(ret_buffer);
        }
        cb();
    };
    WolfSSLEncryptionStream.prototype._flush = function (cb) {
        var ret_buffer = this.encryptor.finalize();
        if (ret_buffer.length > 0) {
            this.push(ret_buffer);
        }
        cb();
    };
    return WolfSSLEncryptionStream;
}(stream.Transform));
exports.WolfSSLEncryptionStream = WolfSSLEncryptionStream;
var WolfSSLDecryptionStream = /** @class */ (function (_super) {
    __extends(WolfSSLDecryptionStream, _super);
    /**
     * Initializes a new instance of the WolfSSLEncryptionStream class.
     *
     * @param cipher The cipher name to use.
     * @param key    The decryption key to use.
     * @param iv     The initialization vector.
     *
     * @throws {Error} If cipher is not available or unknown.
     * @throws {Error} If the creation of the Decryption object failed.
     */
    function WolfSSLDecryptionStream(cipher, key, iv) {
        var _this = _super.call(this) || this;
        _this.encryptor = new WolfSSLDecryptor(cipher, key, iv);
        return _this;
    }
    WolfSSLDecryptionStream.prototype._transform = function (chunk, enc, cb) {
        var buffer = Buffer.isBuffer(chunk) ? chunk : new Buffer(chunk, enc);
        var ret_buffer = this.encryptor.update(chunk);
        if (ret_buffer.length > 0) {
            this.push(ret_buffer);
        }
        cb();
    };
    WolfSSLDecryptionStream.prototype._flush = function (cb) {
        var ret_buffer = this.encryptor.finalize();
        if (ret_buffer.length > 0) {
            this.push(ret_buffer);
        }
        cb();
    };
    return WolfSSLDecryptionStream;
}(stream.Transform));
exports.WolfSSLDecryptionStream = WolfSSLDecryptionStream;
