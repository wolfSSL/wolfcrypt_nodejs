/* sha.js
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
const { WolfSSLSha } = require( '../interfaces/sha' )

const message = 'Hello WolfSSL!'
const expectedShaHex = 'ba9b3d5bba54898cd9e957b169635a89abcce309'
const expectedSha224Hex = 'f342a6cb55bfa290428c7fe88db88f46c2bc17702eb13ad937cd3fbe'
const expectedSha256Hex = '972bced2e3b1a0600abcb5b911f8e7b22cf52bdcd7581119eeafdac11b6737b8'
const expectedSha384Hex = '987e43441ebae9bbc1f07ff4675425ae3f590f55569e0d9df3f94d43f976802831dd9ec2bf33e2e6f7b0d9e23f0d6af0'
const expectedSha512Hex = '5330a918b9e4cc3541dc1f68d8ebf7dbb826845fc44c8e932574e875ad0f5220052e0bfcf25c9fcc53ec7f18e5b89e18f8c670c99667667a4089a06363af1b8e'
const expectedSha512_224Hex = 'efeb498901763679ce3efc00c42e8cc645ac78181b476e74b7f91bb0'
const expectedSha512_256Hex = 'abed0959d48ef4966d1132613a4228771804164d82a3d2d1c4faa9d60bcd5ebc'

const sha_tests =
{
  sha: function()
  {
    let sha = new WolfSSLSha( 'SHA' )

    sha.update( message )

    const digestHex = sha.finalize().toString( 'hex' )

    if ( digestHex == expectedShaHex )
    {
      console.log( 'PASS sha sha' )
    }
    else
    {
      console.log( 'FAIL sha sha', digestHex, expectedShaHex )
    }
  },

  sha224: function()
  {
    let sha = new WolfSSLSha( 'SHA224' )

    sha.update( message )

    const digestHex = sha.finalize().toString( 'hex' )

    if ( digestHex == expectedSha224Hex )
    {
      console.log( 'PASS sha sha224' )
    }
    else
    {
      console.log( 'FAIL sha sha224', digestHex, expectedSha224Hex )
    }
  },

  sha256: function()
  {
    let sha = new WolfSSLSha( 'SHA256' )

    sha.update( message )

    const digestHex = sha.finalize().toString( 'hex' )

    if ( digestHex == expectedSha256Hex )
    {
      console.log( 'PASS sha sha256' )
    }
    else
    {
      console.log( 'FAIL sha sha256', digestHex, expectedSha256Hex )
    }
  },

  sha384: function()
  {
    let sha = new WolfSSLSha( 'SHA384' )

    sha.update( message )

    const digestHex = sha.finalize().toString( 'hex' )

    if ( digestHex == expectedSha384Hex )
    {
      console.log( 'PASS sha sha384' )
    }
    else
    {
      console.log( 'FAIL sha sha384', digestHex, expectedSha384Hex )
    }
  },

  sha512: function()
  {
    let sha = new WolfSSLSha( 'SHA512' )

    sha.update( message )

    const digestHex = sha.finalize().toString( 'hex' )

    if ( digestHex == expectedSha512Hex )
    {
      console.log( 'PASS sha sha512' )
    }
    else
    {
      console.log( 'FAIL sha sha512', digestHex, expectedSha512Hex )
    }
  },

  sha512_224: function()
  {
    if (process.env.WOLFCRYPT_FIPS) {
      console.log('SKIP SHA512_224 for FIPS')
      return
    }

    let sha = new WolfSSLSha( 'SHA512_224' )

    sha.update( message )

    const digestHex = sha.finalize().toString( 'hex' )

    if ( digestHex == expectedSha512_224Hex )
    {
      console.log( 'PASS sha sha512_224' )
    }
    else
    {
      console.log( 'FAIL sha sha512_224', digestHex, expectedSha512_224Hex )
    }
  },

  sha512_256: function()
  {
    if (process.env.WOLFCRYPT_FIPS) {
      console.log('SKIP SHA512_256 for FIPS')
      return
    }

    let sha = new WolfSSLSha( 'SHA512_256' )

    sha.update( message )

    const digestHex = sha.finalize().toString( 'hex' )

    if ( digestHex == expectedSha512_256Hex )
    {
      console.log( 'PASS sha sha512_256' )
    }
    else
    {
      console.log( 'FAIL sha sha512_256', digestHex, expectedSha512_256Hex )
    }
  },
}

module.exports = sha_tests
