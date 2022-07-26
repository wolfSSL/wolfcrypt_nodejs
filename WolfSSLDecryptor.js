"use strict";
exports.__esModule = true;
exports.WolfSSLDecryptor = void 0;
var wolfcrypt = require('./build/Release/wolfcrypt');
//export class WolfSSLDecryptor implements Decryptor {
var WolfSSLDecryptor = /** @class */ (function () {
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
        //this.enableFips();
        this.evp = Buffer.alloc(wolfcrypt.sizeof_EVP_CIPHER_CTX());
        this.totalInputLength = 0;
        wolfcrypt.EVP_CipherInit(this.evp, cipher, key, iv);
    }
    /**
     * Updates the internal state with data for decryption.
     *
     * @param data The data that will be added for decryption.
     *
     * @returns The decrypted data if possible.
     *
     * @throws {Error} If the decryption fails.
     *
     * @remarks This function should be called multiple times.
     */
    WolfSSLDecryptor.prototype.update = function (data) {
        this.totalInputLength += data.length;
        var outBuffer = Buffer.alloc(this.totalInputLength);
        var ret = wolfcrypt.EVP_CipherUpdate(this.evp, outBuffer, data, data.length);
        if (ret > 0) {
            return outBuffer;
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
    WolfSSLDecryptor.prototype.finalize = function () {
        var outBuffer = Buffer.alloc(this.totalInputLength);
        var ret = wolfcrypt.EVP_CipherFinal(this.evp, outBuffer);
        if (ret > 0) {
            return outBuffer;
        }
        return Buffer.alloc(0);
    };
    return WolfSSLDecryptor;
}());
exports.WolfSSLDecryptor = WolfSSLDecryptor;
