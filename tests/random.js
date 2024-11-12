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
const { WolfSSLRandom } = require( '../interfaces/random' )

const rng_tests =
{
    generateBlock: async function()
    {
        let rng = new WolfSSLRandom()
        let rngOne = rng.GenerateBlock(256)
        let rngTwo = rng.GenerateBlock(256)
        rng.free()

        if (rngOne.equals(rngTwo)) {
            console.log('FAIL RNG generateBlock')
        }
        else {
            let i;
            for (i = 0; i < rngOne.length; i++) {
                if (rngOne[i] != 0) {
                    break
                }
            }
            if (i >= rngOne.length) {
                console.log('FAIL RNG generateBlock')
            }
            else {
                console.log('PASS RNG generateBlock')
            }
        }
    }
}

module.exports = rng_tests
