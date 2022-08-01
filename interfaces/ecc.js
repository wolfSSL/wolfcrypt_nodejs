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
const wolfcrypt = require( '../build/Release/wolfcrypt' )

class WolfSSLEcc
{
  constructor()
  {
    this.ecc = Buffer.alloc( wolfcrypt.sizeof_ecc_key() )
    this.size = -1

    let ret = wolfcrypt.wc_ecc_init( this.ecc )

    if ( ret != 0 )
    {
      throw `Failed to wc_ecc_init ${ ret }`
    }
  }

  make_key( size )
  {
    if ( this.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    let ret = wolfcrypt.wc_ecc_make_key( size, this.ecc )

    if ( ret != 0 )
    {
      throw `Failed to wc_ecc_make_key ${ ret }`
    }

    this.size = size
  }

  export_x963()
  {
    if ( this.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    let asnBuf = Buffer.alloc( 2048 )

    let ret = wolfcrypt.wc_ecc_export_x963( this.ecc, asnBuf, asnBuf.length )

    if ( ret <= 0 )
    {
      throw `Failed to wc_ecc_export_x963 ${ ret }`
    }

    asnBuf = asnBuf.subarray( 0, ret )

    return asnBuf
  }

  import_x963( asnBuf )
  {
    if ( this.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    if ( typeof asnBuf == 'string' )
    {
      asnBuf = Buffer.from( asnBuf )
    }

    let ret = wolfcrypt.wc_ecc_import_x963( asnBuf, asnBuf.length, this.ecc )

    if ( ret != 0 )
    {
      throw `Failed to wc_ecc_export_x963 ${ ret }`
    }
  }

  set_curve( keySize, curveId )
  {
    if ( this.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    let ret = wolfcrypt.wc_ecc_set_curve( this.ecc, keySize, curveId )

    if ( ret != 0 )
    {
      throw `Failed to wc_ecc_set_curve ${ ret }`
    }
  }

  shared_secret( pubEcc )
  {
    if ( this.ecc == null || pubEcc.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    let secret = Buffer.alloc( this.size )

    let ret = wolfcrypt.wc_ecc_shared_secret( this.ecc, pubEcc.ecc, secret, this.size )

    if ( ret != this.size )
    {
      throw `Failed to wc_ecc_shared_secret ${ ret }`
    }

    return secret
  }

  sign_hash( data )
  {
    if ( this.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    const sigSize = wolfcrypt.wc_ecc_sig_size( this.ecc )

    if ( sigSize <= 0 )
    {
      throw `Failed to wc_ecc_sig_size ${ ret }`
    }

    let sig = Buffer.alloc( sigSize )

    let ret = wolfcrypt.wc_ecc_sign_hash( data, data.length, sig, sig.length, this.ecc )

    if ( ret <= 0 )
    {
      throw `Failed to wc_ecc_sign_hash ${ ret }`
    }

    sig = sig.subarray( 0, ret )

    return sig;
  }

  verify_hash( sig, hash )
  {
    if ( this.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    if ( typeof sig == 'string' )
    {
      sig = Buffer.from( sig )
    }

    if ( typeof hash == 'string' )
    {
      hash = Buffer.from( hash )
    }

    let ret = wolfcrypt.wc_ecc_verify_hash( sig, sig.length, hash, hash.length, this.ecc )

    if ( ret < 0 )
    {
      throw `Failed to wc_ecc_verify_hash ${ ret }`
    }

    if ( ret == 1 )
    {
      return true
    }

    return false
  }

  ecc_encrypt( pubEcc, data )
  {
    if ( this.ecc == null || pubEcc.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    let cipherText = Buffer.alloc( this.size * 2 + 1 + data.length + 32 )

    console.log( cipherText.length )

    let ret = wolfcrypt.wc_ecc_encrypt( this.ecc, pubEcc.ecc, data, data.length, cipherText, cipherText.length )

    if ( ret <= 0 )
    {
      throw `Failed to wc_ecc_encrypt ${ ret }`
    }

    console.log( ret )

    cipherText = cipherText.subarray( 0, ret )

    return cipherText;
  }

  ecc_decrypt( pubEcc, cipherText )
  {
    if ( this.ecc == null || pubEcc.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    if ( typeof cipherText == 'string' )
    {
      cipherText = Buffer.from( cipherText )
    }

    let data = Buffer.alloc( cipherText.length )

    let ret = wolfcrypt.wc_ecc_decrypt( this.ecc, pubEcc.ecc, cipherText, cipherText.length, data, data.length )

    if ( ret <= 0 )
    {
      throw `Failed to wc_ecc_decrypt ${ ret }`
    }

    data = data.subarray( 0, ret )

    return cipherText;
  }

  free()
  {
    if ( this.ecc == null )
    {
      throw 'Ecc not allocated'
    }

    let ret = wolfcrypt.wc_ecc_free( this.ecc )
    this.ecc = null

    if ( ret != 0 )
    {
      throw `Failed to wc_ecc_free ${ ret }`
    }
  }
}

exports.WolfSSLEcc = WolfSSLEcc
