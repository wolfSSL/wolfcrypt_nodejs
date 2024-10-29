/* pkcs12.js
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
const wolfcrypt = require( '../build/Release/wolfcrypt' )

class WolfSSL_PKCS12
{
    static PBE_MD5_DES = 0;
    static PBE_SHA1_RC4_128 = 1;
    static PBE_SHA1_DES = 2;
    static PBE_SHA1_DES3 = 3;
    static PBE_AES256_CBC = 4;
    static PBE_AES128_CBC = 5;
    static PBE_SHA1_40RC2_CBC = 6;
    static PBE_SHA1_RC4_128_SUM = 657;
    static PBE_SHA1_DES3_SUM = 659;
    static PBE_SHA1_40RC2_CBC_SUM = 662;
    static PBE_MD5_DES_SUM = 651;
    static PBE_SHA1_DES_SUM = 658;
    static PBES2_SUM = 661;
    static PBES2 = 13;
    static PBES1_MD5_DES = 3;
    static PBES1_SHA1_DES = 10;

    /**
     * Creates a new PKCS7 structure by calling sizeof_PKCS7 and wc_PKCS7_Init
     *
     * @remarks free must be called to free the ecc PKCS7 data
     */
    constructor() {
        this.pkcs12 = wolfcrypt.wc_PKCS12_new()
    }

    Create(pass, key, cert, derList, nidKey, nidCert, iter, macIter) {
        if (typeof pass == 'string') {
            pass = Buffer.from(pass)
        }

        if (!Buffer.isBuffer(pass)) {
            throw 'pass must be a string or Buffer'
        }

        if (typeof key == 'string') {
            key = Buffer.from(key)
        }

        if (!Buffer.isBuffer(key)) {
            throw 'key must be a string or Buffer'
        }

        if (typeof cert == 'string') {
            cert = Buffer.from(cert)
        }

        if (!Buffer.isBuffer(cert)) {
            throw 'cert must be a string or Buffer'
        }

        for (let i in derList) {
            if (typeof derList[i] == 'string') {
                derList[i] = Buffer.from(derList[i])
            }

            if (!Buffer.isBuffer(derList[i])) {
                throw 'derList must be an array of buffers or strings'
            }
        }

        this.pkcs12 = wolfcrypt.nodejsPKCS12Create(pass, pass.length, key,
            key.length, cert, cert.length, derList, nidKey, nidCert, iter,
            macIter)

        if (this.pkcs12 == null) {
            throw 'failed to wc_PKCS12_create'
        }
    }

    Parse(pass) {
        if (this.pkcs12 == null) {
            throw 'PKCS12 not allocated'
        }

        if (typeof pass == 'string') {
            pass = Buffer.from(pass)
        }

        if (!Buffer.isBuffer(pass)) {
            throw 'pass must be a string or Buffer'
        }

        let derList = []

        let out = wolfcrypt.nodejsPKCS12Parse(this.pkcs12, pass, derList)

        if (!out.key || !out.cert) {
            throw `failed to nodejsPKCS12Parse`
        }

        return {key: out.key, cert: out.cert, derList: derList}
    }

    DerToInternal(der) {
        if (this.pkcs12 == null) {
            throw 'PKCS12 not allocated'
        }

        if (typeof der == 'string') {
            pass = Buffer.from(der)
        }

        if (!Buffer.isBuffer(der)) {
            throw 'der must be a string or Buffer'
        }

        let ret = wolfcrypt.wc_d2i_PKCS12(der, der.length, this.pkcs12)

        if (ret != 0) {
            throw `failed to wc_d2i_PKCS12 ${ret}`
        }
    }

    InternalToDer() {
        if (this.pkcs12 == null) {
            throw 'PKCS12 not allocated'
        }

        let der = wolfcrypt.nodejsPKCS12InternalToDer(this.pkcs12)

        if (der == null) {
            throw `failed to nodejsPKCS12InternalToDer`
        }

        return der;
    }

    /**
     * Frees the data allocated by the PKCS12 structure
     *
     * @throws {Error} If PKCS12 structure is not allocated.
     */
    free() {
        if ( this.pkcs12 == null )
        {
            throw 'Pkcs12 not allocated'
        }

        wolfcrypt.wc_PKCS12_free(this.pkcs12)

        this.pkcs12 = null
    }
}

exports.WolfSSL_PKCS12 = WolfSSL_PKCS12
