/* pkcs7.js
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

class WolfSSL_PKCS7
{
  constructor()
  {
    this.pkcs7 = Buffer.alloc( wolfcrypt.sizeof_PKCS7() )

    let ret = wolfcrypt.wc_PKCS7_Init( this.pkcs7 )

    if ( ret != 0 )
    {
      throw `Failed to wc_PKCS7_Init ${ ret }`
    }
  }

  AddCertificate( cert )
  {
    if ( this.pkcs7 == null )
    {
      throw 'Pkcs7 not allocated'
    }

    if ( !Buffer.isBuffer( cert ) )
    {
      throw `cert must be a Buffer`
    }

    let ret = wolfcrypt.wc_PKCS7_AddCertificate( this.pkcs7, cert, cert.length )

    if ( ret != 0 )
    {
      throw `Failed to wc_PKCS7_AddCertificate ${ ret }`
    }
  }

  EncodeData( data, key )
  {
    if ( this.pkcs7 == null )
    {
      throw 'Pkcs7 not allocated'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    if ( !Buffer.isBuffer( data ) )
    {
      throw `data must be a string or Buffer`
    }

    if ( !Buffer.isBuffer( key ) )
    {
      throw `cert must be a Buffer`
    }

    let outBuf = Buffer.alloc( 4000 )

    let ret = wolfcrypt.wc_PKCS7_EncodeData( this.pkcs7, data, data.length, key, key.length, outBuf, outBuf.length )

    if ( ret <= 0 )
    {
      throw `Failed to wc_PKCS7_EncodeData ${ ret }`
    }

    outBuf = outBuf.subarray( 0, ret )

    return outBuf
  }

  EncodeSignedData( data, key, keySum, hashSum )
  {
    if ( this.pkcs7 == null )
    {
      throw 'Pkcs7 not allocated'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    if ( !Buffer.isBuffer( data ) )
    {
      throw `data must be a string or Buffer`
    }

    if ( !Buffer.isBuffer( key ) )
    {
      throw `cert must be a Buffer`
    }

    let keySumType = wolfcrypt.typeof_Key_Sum( keySum )

    if ( keySumType < 0 )
    {
      throw `Invalid keySum`
    }

    let hashSumType = wolfcrypt.typeof_Hash_Sum( hashSum )

    if ( hashSumType < 0 )
    {
      throw `Invalid hashSum`
    }

    let outBuf = Buffer.alloc( 4000 )

    let ret = wolfcrypt.wc_PKCS7_EncodeSignedData( this.pkcs7, data, data.length, key, key.length, keySumType, hashSumType, outBuf, outBuf.length )

    if ( ret != 0 )
    {
      throw `Failed to wc_PKCS7_EncodeSignedData ${ ret }`
    }

    outBuf = outBuf.subarray( 0, ret )

    return outBuf
  }

  VerifySignedData( data )
  {
    if ( this.pkcs7 == null )
    {
      throw 'Pkcs7 not allocated'
    }

    if ( !Buffer.isBuffer( data ) )
    {
      throw `data must be a Buffer`
    }

    let ret = wolfcrypt.wc_PKCS7_VerifySignedData( this.pkcs7, data, data.length )

    if ( ret != 0 )
    {
      throw `Failed to wc_PKCS7_VerifySignedData ${ ret }`
    }
  }

  free()
  {
    wolfcrypt.wc_PKCS7_Free( this.pkcs7 )
    this.pkcs7 = null
  }
}

exports.WolfSSL_PKCS7 = WolfSSL_PKCS7
