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
  /**
   * Creates a new RsaKey by calling sizeof_RsaKey and wc_InitRsaKey
   *
   * @remarks free must be called to free the rsa key data
   */
  constructor()
  {
    this.rsa = Buffer.alloc( wolfcrypt.sizeof_RsaKey() )
    wolfcrypt.wc_InitRsaKey( this.rsa )
  }

  /**
   * Makes a new rsa key and fills the rsa struct with the key data
   *
   * @param size The size of the rsa key.
   *
   * @param e The exponent parameter to use for key generation.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If wc_MakeRsaKey fails.
   */
  MakeRsaKey( size, e )
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    let ret = wolfcrypt.wc_MakeRsaKey( this.rsa, size, e )

    if ( ret != 0 )
    {
      throw `Failed to wc_MakeRsaKey ${ ret }`
    }
  }

  /**
   * Exports the private key in Der format
   *
   * @returns The Der private key as a data Buffer.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If wc_RsaKeyToDer fails.
   */
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

  /**
   * Exports the public key in Der format
   *
   * @returns The Der public key as a data Buffer.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If wc_RsaKeyToPublicDer fails.
   */
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

  /**
   * Imports the private key from Der Buffer
   *
   * @param derBuf The private key Der.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If derBuf is not a Buffer.
   *
   * @throws {Error} If wc_RsaPrivateKeyDecode fails.
   */
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

  /**
   * Imports the public key from Der Buffer
   *
   * @param derBuf The public key Der.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If derBuf is not a Buffer.
   *
   * @throws {Error} If wc_RsaPublicKeyDecode fails.
   */
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

  /**
   * Encrypts the provided data using the public key
   *
   * @param data The data to encrypt.
   *
   * @returns The encrypted message as a data Buffer.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If data is not a string or Buffer.
   *
   * @throws {Error} If wc_RsaPublicEncrypt fails.
   */
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

    if ( !Buffer.isBuffer( data ) )
    {
      throw 'Data must be string or Buffer'
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

  /**
   * Decrypts the provided ciphertext using the private key
   *
   * @param ciphertext The ciphertext to decrypt.
   *
   * @returns The plaintext message as a data Buffer.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If ciphertext is not a Buffer.
   *
   * @throws {Error} If wc_RsaPrivateDecrypt fails.
   */
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

  /**
   * Generates a signature of the provided data using the private key
   *
   * @param data The data to sign.
   *
   * @returns The signature as a data Buffer.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If data is not a string or Buffer.
   *
   * @throws {Error} If wc_RsaSSL_Sign fails.
   */
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

    if ( !Buffer.isBuffer( data ) )
    {
      throw 'data must be a string or Buffer'
    }

    let sig = Buffer.alloc( wolfcrypt.wc_RsaEncryptSize( this.rsa ) )

    let ret = wolfcrypt.wc_RsaSSL_Sign( data, data.length, sig, sig.length, this.rsa )

    if ( ret <= 0 )
    {
      throw `Failed to wc_RsaSSL_Sign ${ ret }`
    }

    return sig
  }

  /**
   * Verifies a signature of the provided data using the public key
   *
   * @param sig The signature to verify.
   *
   * @param data The data used to generate the signature.
   *
   * @returns true if the signature is valid, false otherwise.
   *
   * @throws {Error} If the rsa key is not allocated.
   *
   * @throws {Error} If sig is not a Buffer.
   *
   * @throws {Error} If data is not a string or Buffer.
   *
   * @throws {Error} If wc_RsaSSL_Verify fails.
   */
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

    if ( !Buffer.isBuffer( data ) )
    {
      throw 'data must be a string or Buffer'
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

  /**
   * Frees the data allocated by the rsa key
   *
   * @throws {Error} If rsa key is not allocated.
   *
   * @throws {Error} If wc_FreeRsaKey fails.
   */
  free()
  {
    if ( this.rsa == null )
    {
      throw 'Invalid rsa key'
    }

    let ret = wolfcrypt.wc_FreeRsaKey( this.rsa )

    if ( ret != 0 )
    {
      throw `Failed to wc_FreeRsaKey ${ ret }`
    }

    this.rsa = null
  }
}

exports.WolfSSLRsa = WolfSSLRsa
