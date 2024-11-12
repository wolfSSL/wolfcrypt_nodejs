/* evp.js
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
const wolfcrypt = require( '../build/Release/wolfcrypt' );
const stream = require( 'stream' );

class WolfSSLEVP
{
  /**
   * Creates a new evp cipher by calling EVP_CIPHER_CTX_new
   *
   * @remarks finalize or free must be called to free the cipher
   */
  constructor()
  {
    this.totalInputLength = 0
    this.evp = wolfcrypt.EVP_CIPHER_CTX_new()
  }

  /**
   * Updates the internal state with data for cipher.
   *
   * @param data The data that will be added to the cipher.
   *
   * @returns The result data if possible.
   *
   * @throws {Error} If the cipher update fails.
   *
   * @remarks This function can be called multiple times.
   */
  update( data )
  {
    if ( this.evp == null )
    {
      throw 'Cipher is not allocated'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    this.totalInputLength += data.length

    let outBuffer = Buffer.alloc( this.totalInputLength )

    let ret = wolfcrypt.EVP_CipherUpdate( this.evp, outBuffer, data, data.length )

    if ( ret < 0 )
    {
      throw 'Failed to update cipher'
    }

    if ( ret > 0 )
    {
      this.totalInputLength -= ret;

      return outBuffer.subarray( 0, ret )
    }

    return Buffer.alloc( 0 )
  }

  /**
   * Finalize the encryption/decryption process.
   *
   * @returns The last block of data.
   *
   * @throws {Error} If the EVP_CipherFinal fails.
   *
   * @remarks This function should be called once to finalize the
   * encryption/decryption process.
   */
  finalize()
  {
    if ( this.evp == null )
    {
      throw 'Cipher is not allocated'
    }

    if ( this.totalInputLength % 16 != 0 )
    {
      this.totalInputLength += ( 16 - this.totalInputLength % 16 )
    }

    let outBuffer = Buffer.alloc( this.totalInputLength )
    this.totalInputLength = 0;

    let ret = wolfcrypt.EVP_CipherFinal( this.evp, outBuffer )

    this.free()

    if ( ret < 0 )
    {
      throw 'Failed to finalize cipher'
    }

    if ( ret > 0 )
    {
      return outBuffer.subarray( 0, ret )
    }

    return Buffer.alloc( 0 )
  }

  /**
   * Frees the evp ctx
   *
   * @throws {Error} If the evp pointer is set to null
   *
   * @throws {Error} If the evp pointer is set to null
   *
   * @remarks This function should be called if the caller
   * no longer wants to use the cipher, update and finalize
   * will throw errors if free has been called
   */
  free()
  {
    if ( this.evp == null )
    {
      throw 'Cipher is not allocated'
    }

    wolfcrypt.EVP_CIPHER_CTX_free( this.evp )
    this.evp = null
  }
}

class WolfSSLEncryptor extends WolfSSLEVP
{
  /**
   * Initializes the evp cipher for encryption by calling EVP_CipherInit
   *
   * @param cipher the cipher to be used
   * @param key aes key
   * @param iv aes initialization vector
   */
  constructor( cipher, key, iv )
  {
    super()
    wolfcrypt.EVP_CipherInit( this.evp, cipher, key, iv, 1 )
  }
}

exports.WolfSSLEncryptor = WolfSSLEncryptor

class WolfSSLDecryptor extends WolfSSLEVP
{
  /**
   * Initializes the evp cipher for decryption by calling EVP_CipherInit
   *
   * @param cipher the cipher to be used
   * @param key aes key
   * @param iv aes initialization vector
   */
  constructor( cipher, key, iv )
  {
    super()
    wolfcrypt.EVP_CipherInit( this.evp, cipher, key, iv, 0 )
  }
}

exports.WolfSSLDecryptor = WolfSSLDecryptor

class WolfSSLEVPStream extends stream.Transform
{
  constructor()
  {
    super()
  }

  /**
   * Transforms input data by encrypting or decrypting it with cipher.update
   *
   * @param chunk the data to be encrypted
   * @param enc encoding of the chunk
   * @param cb the callback function that handles
   * the next task of the stream
   */
  _transform( chunk, enc, cb )
  {
    let buffer = Buffer.isBuffer( chunk ) ? chunk: new Buffer( chunk, enc )

    let ret_buffer = this.cipher.update( chunk )

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }

  /**
   * Called when the end of input is reached, call cipher.finalize
   * to finish the encryption
   *
   * @param cb the callback function that handles
   * the next task of the stream
   */
  _flush( cb )
  {
    let ret_buffer = this.cipher.finalize()

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }
}

class WolfSSLEncryptionStream extends WolfSSLEVPStream
{
  /**
   * Creates a new encryptor and sets it to cipher, can then be used
   * by the generic stream methods
   *
   * @param cipher the cipher to be used
   * @param key aes key
   * @param iv aes initialization vector
   */
  constructor( cipher, key, iv )
  {
    super()
    this.cipher = new WolfSSLEncryptor( cipher, key, iv )
  }
}

exports.WolfSSLEncryptionStream = WolfSSLEncryptionStream

class WolfSSLDecryptionStream extends WolfSSLEVPStream
{
  /**
   * Creates a new encryptor and sets it to cipher, can then be used
   * by the generic stream methods
   *
   * @param cipher the cipher to be used
   * @param key aes key
   * @param iv aes initialization vector
   */
  constructor( cipher, key, iv )
  {
    super()
    this.cipher = new WolfSSLDecryptor( cipher, key, iv )
  }
}

exports.WolfSSLDecryptionStream = WolfSSLDecryptionStream
