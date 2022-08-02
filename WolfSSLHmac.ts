/* WolfSSLHmac.ts
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
const wolfcrypt = require( './build/Release/wolfcrypt' );
const stream = require( 'stream' );

export class WolfSSLHmac
{
  // actually holds a pointer but nodejs has no pointer type
  private hmac: Buffer = null
  private hashType: number = -1
  private digestLength: number = -1

  public constructor( type: string, key: Buffer )
  {
    this.hmac = Buffer.alloc( wolfcrypt.sizeof_Hmac() )
    this.hashType = wolfcrypt.typeof_Hmac( type )
    this.digestLength = wolfcrypt.Hmac_digest_length( this.hashType )

    wolfcrypt.wc_HmacSetKey( this.hmac, this.hashType, key, key.length )
  }

  /**
   * Updates the internal state with data for hash.
   *
   * @param data The data that will be added to the hash.
   *
   * @throws {Error} If the hash fails.
   *
   * @remarks This function should be called multiple times.
   */
  public update(data: Buffer)
  {
    if ( this.hmac == null )
    {
      throw 'Hmac is not allocated'
    }

    let ret = wolfcrypt.wc_HmacUpdate( this.hmac, data, data.length )

    if ( ret != 0 )
    {
      throw 'Failed to update hash'
    }
  }

  /**
   * Finalize the hmac process.
   *
   * @returns The digest of the hashed data.
   *
   * @throws {Error} If the digest fails.
   *
   * @remarks This function should be called once to finalize the hmac
   * process.
   */
  public finalize(): Buffer
  {
    if ( this.hmac == null )
    {
      throw 'Hmac is not allocated'
    }

    let outBuffer = Buffer.alloc( this.digestLength )

    let ret = wolfcrypt.wc_HmacFinal( this.hmac, outBuffer )

    wolfcrypt.wc_HmacFree( this.hmac )
    this.hmac = null

    if ( ret != 0 )
    {
      throw 'Failed to finalize digest'
    }

    return outBuffer
  }

  public free()
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

  /**
   * Enables the FIPS mode.
   */
  /*
  private enableFips(): void {
    if (!wolfssl.isFipsEnabled() && !wolfssl.enableFips()) {
      logger.logWarning('FIPS mode not available.');
    }
  }
  */
}

export class WolfSSLHmacStream extends stream.Transform
{
  private hmac: WolfSSLHmac

  /**
   * Initializes a new instance of the WolfSSLEncryptionStream class.
   *
   * @param cipher The cipher name to use.
   * @param key    The decryption key to use.
   * @param iv     The initialization vector.
   *
   * @throws {Error} If cipher is not available or unknown.
   * @throws {Error} If the creation of the Decryption object failed.
   */
  public constructor( type: string, key: Buffer )
  {
    super()
    this.hmac = new WolfSSLHmac( type, key )
  }

  public _transform( chunk: Buffer, enc: BufferEncoding, cb: Function )
  {
    let buffer = Buffer.isBuffer( chunk ) ? chunk: new Buffer( chunk, enc )

    this.hmac.update( chunk )

    cb()
  }

  public _flush( cb: Function )
  {
    let ret_buffer = this.hmac.finalize()

    if ( ret_buffer.length > 0 )
    {
      this.push( ret_buffer )
    }

    cb()
  }
}
