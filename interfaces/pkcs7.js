/* pkcs7.js
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
const wolfcrypt = require( '../build/Release/wolfcrypt' )

class WolfSSL_PKCS7
{
  /**
   * Creates a new PKCS7 structure by calling sizeof_PKCS7 and wc_PKCS7_Init
   *
   * @remarks free must be called to free the ecc PKCS7 data
   */
  constructor()
  {
    this.pkcs7 = Buffer.alloc( wolfcrypt.sizeof_PKCS7() )

    let ret = wolfcrypt.wc_PKCS7_Init( this.pkcs7 )

    if ( ret != 0 )
    {
      throw `Failed to wc_PKCS7_Init ${ ret }`
    }
  }

  /**
   * Adds a certificate to the PKCS7 structure
   *
   * @param cert The cert to add.
   *
   * @throws {Error} If the PKCS7 structure is not allocated.
   *
   * @throws {Error} If the cert is not a Buffer.
   *
   * @throws {Error} If wc_PKCS7_AddCertificate fails.
   */
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

  /**
   * Encodes the provided data using the provided key
   *
   * @param data The data to encode.
   *
   * @param key The key to use, as a Buffer.
   *
   * @returns The encoded data Buffer.
   *
   * @throws {Error} If the PKCS7 structure is not allocated.
   *
   * @throws {Error} If the data is not a string or Buffer.
   *
   * @throws {Error} If the key is not a Buffer.
   *
   * @throws {Error} If wc_PKCS7_EncodeData fails.
   */
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

  /**
   * Encodes and signs the provided data using the provided key, keySum and hashSum
   *
   * @param data The data to encode and sign.
   *
   * @param key The key to use, as a Buffer.
   *
   * @param keySum The key algorithm to use, RSA, ECDSA, ED25519, etc.
   *
   * @param keySum The hash algorithm to use, MD5, SHA, SHAKE256, etc.
   *
   * @returns The signed data Buffer.
   *
   * @throws {Error} If the PKCS7 structure is not allocated.
   *
   * @throws {Error} If the data is not a string or Buffer.
   *
   * @throws {Error} If the key is not a Buffer.
   *
   * @throws {Error} If keySum or hashSum are invalid.
   *
   * @throws {Error} If wc_PKCS7_EncodeSignedData fails.
   */
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

    if ( ret <= 0 )
    {
      throw `Failed to wc_PKCS7_EncodeSignedData ${ ret }`
    }

    outBuf = outBuf.subarray( 0, ret )

    return outBuf
  }

  /**
   * Verifies a signed data Buffer and loads it into the PKCS7 struct
   *
   * @param data The signed data to verify.
   *
   * @throws {Error} If the PKCS7 structure is not allocated.
   *
   * @throws {Error} If the data is not a Buffer.
   *
   * @throws {Error} If wc_PKCS7_VerifySignedData fails.
   */
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

  /**
   * Retreives an attribute from the PKCS7 structure by its oid
   *
   * @param oid The oid of the desired attribute.
   *
   * @returns The attribute value as a Buffer.
   *
   * @throws {Error} If the PKCS7 structure is not allocated.
   *
   * @throws {Error} If the oid is not a string or Buffer.
   *
   * @throws {Error} If wc_PKCS7_GetAttributeValue fails.
   */
  GetAttributeValue( oid )
  {
    if ( this.pkcs7 == null )
    {
      throw 'Pkcs7 not allocated'
    }

    if ( typeof oid == 'string' )
    {
      oid = Buffer.from( oid )
    }

    if ( !Buffer.isBuffer( oid ) )
    {
      throw `oid must be a Buffer or string`
    }

    let outBuf = Buffer.alloc( wolfcrypt.sizeof_wc_PKCS7_GetAttributeValue( this.pkcs7, oid, oid.length ) )

    let ret = wolfcrypt.wc_PKCS7_GetAttributeValue(  this.pkcs7, oid, oid.length, outBuf, outBuf.length )

    if ( ret <= 0 )
    {
      throw `Failed to wc_PKCS7_GetAttributeValue ${ ret }`
    }

    return outBuf
  }

  /**
   * Retreives the SID from the PKCS7 structure
   *
   * @returns The SID value as a Buffer.
   *
   * @throws {Error} If the PKCS7 structure is not allocated.
   *
   * @throws {Error} If wc_PKCS7_GetSignerSID fails.
   */
  GetSignerSID()
  {
    if ( this.pkcs7 == null )
    {
      throw 'Pkcs7 not allocated'
    }

    let outBuf = Buffer.alloc( wolfcrypt.sizeof_wc_PKCS7_GetSignerSID( this.pkcs7 ) )

    let ret = wolfcrypt.wc_PKCS7_GetSignerSID( this.pkcs7, outBuf, outBuf.length )

    if ( ret <= 0 )
    {
      throw `Failed to wc_PKCS7_GetSignerSID ${ ret }`
    }

    return outBuf
  }

  /**
   * Frees the data allocated by the PKCS7 structure
   *
   * @throws {Error} If PKCS7 structure is not allocated.
   *
   * @throws {Error} If wc_ecc_free fails.
   */
  free()
  {
    if ( this.pkcs7 == null )
    {
      throw 'Pkcs7 not allocated'
    }

    wolfcrypt.wc_PKCS7_Free( this.pkcs7 )

    this.pkcs7 = null
  }
}

exports.WolfSSL_PKCS7 = WolfSSL_PKCS7
