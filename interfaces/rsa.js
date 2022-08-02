/* rsa.js
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
const wolfcrypt = require( '../build/Release/wolfcrypt' );

class WolfSSLRsa
{
  constructor()
  {
    this.rsa = Buffer.alloc( wolfcrypt.sizeof_RsaKey() )
    wolfcrypt.wc_InitRsaKey( this.rsa )
  }

  MakeRsaKey( size, e )
  {
    let ret = wolfcrypt.wc_MakeRsaKey( this.rsa, size, e )

    if ( ret != 0 )
    {
      throw `Failed to wc_MakeRsaKey ${ ret }`
    }
  }

  KeyToDer()
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    let derBuf = Buffer.alloc( wolfcrypt.RsaPrivateDerSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaKeyToDer( this.rsa, derBuf, derBuf.length )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaKeyToDer ${ ret }`
    }

    return derBuf
  }

  KeyToPublicDer()
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    let derBuf = Buffer.alloc( wolfcrypt.RsaPublicDerSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaKeyToPublicDer( this.rsa, derBuf, derBuf.length )

    if ( ret < 0 )
    {
      throw `Failed to wc_RsaKeyToPublicDer ${ ret }`
    }

    return derBuf
  }

  PrivateKeyDecode( derBuf )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( !Buffer.isBuffer( derBuf ) )
    {
      throw 'Private key der must be Buffer'
    }

    let ret = wolfcrypt.wc_RsaPrivateKeyDecode( derBuf, this.rsa, derBuf.length )

    if ( ret != 0 )
    {
      throw `Failed to wc_RsaPrivateKeyDecode ${ ret }`
    }
  }

  PublicKeyDecode( derBuf )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( !Buffer.isBuffer( derBuf ) )
    {
      throw 'Public key der must be Buffer'
    }

    let ret = wolfcrypt.wc_RsaPublicKeyDecode( derBuf, this.rsa, derBuf.length )

    if ( ret != 0 )
    {
      throw `Failed to wc_RsaPublicKeyDecode ${ ret }`
    }
  }

  PublicEncrypt( data )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    let ciphertext = Buffer.alloc( wolfcrypt.wc_RsaEncryptSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaPublicEncrypt( data, data.length, ciphertext, ciphertext.length, this.rsa )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaPublicEncrypt ${ ret }`
    }

    ciphertext = ciphertext.subarray( 0, ret )

    return ciphertext
  }

  PrivateDecrypt( ciphertext )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( !Buffer.isBuffer( ciphertext ) )
    {
      throw `ciphertext must be a Buffer`
    }

    let data = Buffer.alloc( wolfcrypt.wc_RsaEncryptSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaPrivateDecrypt( ciphertext, ciphertext.length, data, data.length, this.rsa )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaPrivateDecrypt ${ ret }`
    }

    data = data.subarray( 0, ret )

    return data
  }

  SSL_Sign( data )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    let sig = Buffer.alloc( wolfcrypt.wc_RsaEncryptSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaSSL_Sign( data, data.length, sig, sig.length, this.rsa )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaSSL_Sign ${ ret }`
    }

    return sig
  }

  SSL_Verify( sig, data )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    if ( !Buffer.isBuffer( sig ) )
    {
      throw `signature must be a Buffer`
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    let validLength = wolfcrypt.wc_RsaSSL_Verify( sig, sig.length, data, data.length, this.rsa )

    if ( validLength < 0 )
    {
      throw `Failed to wc_RsaSSL_Verify ${ validLength }`
    }

    if ( validLength == data.length )
    {
      return true
    }

    return false
  }

  free()
  {
    wolfcrypt.wc_FreeRsaKey( this.rsa )
    this.rsa = null
  }
}

exports.WolfSSLRsa = WolfSSLRsa
