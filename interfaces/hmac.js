/* hmac.js
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
const stream = require( 'stream' );

class WolfSSLHmac
{
  /**
   * Creates a new hmac by calling wc_HmacSetKey
   *
   * @param type the hashing algorithm to use
   * @param key hmac key
   *
   * @remarks finalize or free must be called to free the cipher
   */
  constructor( type, key )
  {
    this.hmac = Buffer.alloc( wolfcrypt.sizeof_Hmac() )

    this.hashType = wolfcrypt.typeof_Hmac( type )

    if ( this.hashType == -1 )
    {
      throw `Hashing algorithm ${ type } not recognized`
    }

    this.digestLength = wolfcrypt.Hmac_digest_length( this.hashType )

    wolfcrypt.wc_HmacSetKey( this.hmac, this.hashType, key, key.length )
  }

  /**
   * Adds to the hash with data
   *
   * @param data The data that will be added to the hash.
   *
   * @remarks This function can be called multiple times.
   */
  update( data )
  {
    if ( this.hmac == null )
    {
      throw 'Hmac is not allocated'
    }

    if ( typeof data == 'string' )
    {
      data = Buffer.from( data )
    }

    let ret = wolfcrypt.wc_HmacUpdate( this.hmac, data, data.length )

    if ( ret != 0 )
    {
      throw 'Failed to update hash'
    }
  }

  /**
   * Computes the digest of the hash data
   *
   * @param data The data that will be added to the hash.
   *
   * @returns The digest of the hash data
   *
   * @remarks This function can only be called once
   */
  finalize()
  {
    if ( this.hmac == null )
    {
      throw 'Hmac is not allocated'
    }

    let outBuffer = Buffer.alloc( this.digestLength )

    let ret = wolfcrypt.wc_HmacFinal( this.hmac, outBuffer )

    this.free()

    if ( ret != 0 )
    {
      throw 'Failed to finalize digest'
    }

    return outBuffer
  }

  /**
   * Frees the hmac by calling wc_HmacFree
   *
   * @throws {Error} If the hmac pointer is set to null
   *
   * @remarks This function should be called if the caller
   * no longer wants to use the hmac, update and finalize
   * will throw errors if free has been called
   */
  free()
  {
    if ( this.hmac != null )
    {
      wolfcrypt.wc_HmacFree( this.hmac )
      this.hmac = null
    }
    else
    {
      throw 'Hmac is not allocated'
    }
  }
}

exports.WolfSSLHmac = WolfSSLHmac

class WolfSSLHmacStream extends stream.Transform
{
  /**
   * Creates a new Hmac stream
   *
   * @param type   The hashing algorithm to use
   * @param key    The key to use
   *
   * @throws {Error} If hashing algorithm is not available or unknown.
   * @throws {Error} If the creation of the Hmac object failed.
   */
  constructor( type, key )
  {
    super()
    this.hmac = new WolfSSLHmac( type, key )
  }

  /**
   * Transforms input data by hashing it with hmac.update
   *
   * @param chunk the data to be hashed
   * @param enc encoding of the chunk
   * @param cb the callback function that handles
   * the next task of the stream
   */
  _transform( chunk, enc, cb )
  {
    let buffer = Buffer.isBuffer( chunk ) ? chunk: new Buffer( chunk, enc )

    this.hmac.update( chunk )

    cb()
  }

  /**
   * Called when the end of input is reached, call hmac.finalize
   * to finish the hashing and compute the digest
   *
   * @param cb the callback function that handles
   * the next task of the stream
   */
  _flush( cb )
  {
    let ret_buffer = this.hmac.finalize()

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }
}

exports.WolfSSLHmacStream = WolfSSLHmacStream
