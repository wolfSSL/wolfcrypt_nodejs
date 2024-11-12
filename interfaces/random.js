/* random.js
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

class WolfSSLRandom
{
    /**
     * Creates a new ecc_key structure by calling sizeof_ecc_key and wc_ecc_init
     *
     * @remarks free must be called to free the ecc key data
     */
    constructor()
    {
        this.rng = Buffer.alloc(wolfcrypt.sizeof_WC_RNG())

        let ret = wolfcrypt.wc_InitRng(this.rng)

        if ( ret != 0 ) {
            throw `Failed to wc_InitRng ${ ret }`
        }
    }

    GenerateBlock(size)
    {
       let block = Buffer.alloc(size) 

       let ret = wolfcrypt.wc_RNG_GenerateBlock(this.rng, block, size)

       if (ret != 0) {
            throw 'RNG not allocated'
       }

       return block
    }

    /**
     * Frees the data allocated by the WC_RNG struct
     *
     * @throws {Error} If WC_RNG is not allocated.
     *
     * @throws {Error} If wc_FreeRng fails.
     */
    free()
    {
        if ( this.rng == null ) {
            throw 'RNG not allocated'
        }

        let ret = wolfcrypt.wc_FreeRng(this.rng)
        this.rng = null

        if (ret != 0) {
            throw `Failed to wc_FreeRng ${ ret }`
        }
    }
}

exports.WolfSSLRandom = WolfSSLRandom
