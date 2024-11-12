/* hmac.js
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
const fs = require( 'fs' )
const { WolfSSLHmac, WolfSSLHmacStream } = require( '../interfaces/hmac' )
const wolfcrypt = require( '../build/Release/wolfcrypt' )

const key = Buffer.from('12345678901234567890123456789012')
const expectedLonger = '12345678901234567'
const expectedLongerDigest = 'db6ff3fef0c61ef0d43d7020f6de2bb570a2dbf78921bb185242971b9c8e8d85afb6cbfc31a2a1de3b538da6b784e7424e84e3d8973bcf57798b3e3b67d6b45e'
const messageDigest = 'be5ceaacc5e837f04c6a3b9969724ec71063c92d91300f4bc7ae7b49db7bfc594106ddde3be902d1e452de76f020b60b82ebcbb7a8a4a3906cccab5849e34719'

const hmac_tests =
{
  hmac: function()
  {
    let hmac = new WolfSSLHmac( 'SHA3_512', key )
    hmac.update( expectedLonger )
    const actualDigest = hmac.finalize().toString( 'hex' )

    if ( actualDigest == expectedLongerDigest )
    {
      console.log( 'PASS hmac hmac' )
    }
    else
    {
      console.log( 'FAIL hmac hmac', actualDigest, expectedLongerDigest )
    }
  },

  hmacStream: async function()
  {
    await new Promise( (res, rej) => {
      let parts = []
      let hmacStream = new WolfSSLHmacStream( 'SHA3_512', key )

      hmacStream.on( 'data', function( chunk ) {
        parts.push( chunk )
      } )

      hmacStream.on( 'end', function() {
        const actualDigest = Buffer.concat( parts ).toString( 'hex' )

        if ( actualDigest == expectedLongerDigest )
        {
          console.log( 'PASS hmac hmacStream' )
        }
        else
        {
          console.log( 'FAIL hmac hmacStream', actualDigest, expectedLongerDigest )
        }

        res()
      } )

      hmacStream.write( expectedLonger )
      hmacStream.end()
    } )
  },

  hmacPipe: async function()
  {
    await new Promise( (res, rej) => {
      let parts = []
      let readStream = fs.createReadStream( 'message.txt' )
      let hmacStream = new WolfSSLHmacStream( 'SHA3_512', key )

      hmacStream.on( 'data', function( chunk ) {
        parts.push( chunk )
      } )

      hmacStream.on( 'end', function() {
        const actualDigest = Buffer.concat( parts ).toString( 'hex' )

        if ( actualDigest == messageDigest )
        {
          console.log( 'PASS hmac hmacPipe' )
        }
        else
        {
          console.log( 'FAIL hmac hmacPipe', actualDigest, messageDigest )
        }

        res()
      } )

      readStream.pipe( hmacStream )
    } )
  },
}

module.exports = hmac_tests
