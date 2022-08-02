/* WolfSSLHmac.js
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
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
exports.WolfSSLHmacStream = exports.WolfSSLHmac = void 0;
var wolfcrypt = require('./build/Release/wolfcrypt');
var stream = require('stream');
var WolfSSLHmac = /** @class */ (function () {
    function WolfSSLHmac(type, key) {
        // actually holds a pointer but nodejs has no pointer type
        this.hmac = null;
        this.hashType = -1;
        this.digestLength = -1;
        this.hmac = Buffer.alloc(wolfcrypt.sizeof_Hmac());
        this.hashType = wolfcrypt.typeof_Hmac(type);
        this.digestLength = wolfcrypt.Hmac_digest_length(this.hashType);
        wolfcrypt.wc_HmacSetKey(this.hmac, this.hashType, key, key.length);
    }
    /**
     * Updates the internal state with data for hash.
     *
     * @param data The data that will be added to the hash.
     *
     * @throws {Error} If the hash fails.
     *
     * @remarks This function should be called multiple times.
     */
    WolfSSLHmac.prototype.update = function (data) {
        if (this.hmac == null) {
            throw 'Hmac is not allocated';
        }
        var ret = wolfcrypt.wc_HmacUpdate(this.hmac, data, data.length);
        if (ret != 0) {
            throw 'Failed to update hash';
        }
    };
    /**
     * Finalize the hmac process.
     *
     * @returns The digest of the hashed data.
     *
     * @throws {Error} If the digest fails.
     *
     * @remarks This function should be called once to finalize the hmac
     * process.
     */
    WolfSSLHmac.prototype.finalize = function () {
        if (this.hmac == null) {
            throw 'Hmac is not allocated';
        }
        var outBuffer = Buffer.alloc(this.digestLength);
        var ret = wolfcrypt.wc_HmacFinal(this.hmac, outBuffer);
        wolfcrypt.wc_HmacFree(this.hmac);
        this.hmac = null;
        if (ret != 0) {
            throw 'Failed to finalize digest';
        }
        return outBuffer;
    };
    WolfSSLHmac.prototype.free = function () {
        if (this.hmac != null) {
            wolfcrypt.wc_HmacFree(this.hmac);
            this.hmac = null;
        }
        else {
            throw 'Hmac is not allocated';
        }
    };
    return WolfSSLHmac;
}());
exports.WolfSSLHmac = WolfSSLHmac;
var WolfSSLHmacStream = /** @class */ (function (_super) {
    __extends(WolfSSLHmacStream, _super);
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
    function WolfSSLHmacStream(type, key) {
        var _this = _super.call(this) || this;
        _this.hmac = new WolfSSLHmac(type, key);
        return _this;
    }
    WolfSSLHmacStream.prototype._transform = function (chunk, enc, cb) {
        var buffer = Buffer.isBuffer(chunk) ? chunk : new Buffer(chunk, enc);
        this.hmac.update(chunk);
        cb();
    };
    WolfSSLHmacStream.prototype._flush = function (cb) {
        var ret_buffer = this.hmac.finalize();
        if (ret_buffer.length > 0) {
            this.push(ret_buffer);
        }
        cb();
    };
    return WolfSSLHmacStream;
}(stream.Transform));
exports.WolfSSLHmacStream = WolfSSLHmacStream;
