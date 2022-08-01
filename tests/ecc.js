/* ecc.js
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
const { WolfSSLEcc } = require( '../interfaces/ecc' )

const message = 'Hello WolfSSL!'
const message16 = '1234567890123456'

const ecc_tests =
{
  makeKey: function()
  {
    let ecc = new WolfSSLEcc()

    ecc.make_key( 32 )

    ecc.free()

    console.log( 'PASS ecc makeKey' )
  },

  sharedSecret32: function()
  {
    let ecc0 = new WolfSSLEcc()
    let ecc1 = new WolfSSLEcc()

    ecc0.make_key( 32 )
    ecc1.make_key( 32 )

    const secret_0 = ecc0.shared_secret( ecc1 ).toString( 'hex' )
    const secret_1 = ecc1.shared_secret( ecc0 ).toString( 'hex' )

    ecc0.free()
    ecc1.free()

    if ( secret_0 == secret_1 )
    {
      console.log( 'PASS ecc sharedSecret32' )
    }
    else
    {
      console.log( 'FAIL ecc sharedSecret32', secret_0, secret_1 )
    }
  },

  sharedSecret64: function()
  {
    let ecc0 = new WolfSSLEcc()
    let ecc1 = new WolfSSLEcc()

    ecc0.make_key( 64 )
    ecc1.make_key( 64 )

    const secret_0 = ecc0.shared_secret( ecc1 ).toString( 'hex' )
    const secret_1 = ecc1.shared_secret( ecc0 ).toString( 'hex' )

    ecc0.free()
    ecc1.free()

    if ( secret_0 == secret_1 )
    {
      console.log( 'PASS ecc sharedSecret64' )
    }
    else
    {
      console.log( 'FAIL ecc sharedSecret64', secret_0, secret_1 )
    }
  },

  signVerify: function()
  {
    let ecc0 = new WolfSSLEcc()

    ecc0.make_key( 32 )

    const sig = ecc0.sign_hash( message )

    if ( ecc0.verify_hash( sig, message ) == true )
    {
      console.log( 'PASS ecc signVerify' )
    }
    else
    {
      console.log( 'FAIL ecc signVerify', sig.toString( 'hex' ) )
    }

    ecc0.free()
  },

  // Vandaly Industries
  importExport: function()
  {
    let ecc0 = new WolfSSLEcc()
    let ecc1 = new WolfSSLEcc()

    ecc0.make_key( 32 )

    const asnKey = ecc0.export_x963()

    ecc1.import_x963( asnKey )

    const sig = ecc0.sign_hash( message )

    if ( ecc1.verify_hash( sig, message ) == true )
    {
      console.log( 'PASS ecc importExport' )
    }
    else
    {
      console.log( 'FAIL ecc importExport', sig.toString( 'hex' ) )
    }

    ecc0.free()
    ecc1.free()
  },
}

module.exports = ecc_tests
