/* pbkdf2.js
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

/**
 * Generates a new key using the key derivation function
 *
 * @param password The password to use.
 *
 * @param salt The salt to use.
 *
 * @param iterations The number of iterations to use for derivation.
 *
 * @param keyLen The length of the key to be derived.
 *
 * @param hash_type The hashing algorithm to be used for derivation.
 *
 * @returns true if the signature matches, false otherwise.
 *
 * @throws {Error} If passowrd or salt are not buffers.
 *
 * @throws {Error} If hash_type is not a known hashing algorithm.
 *
 * @throws {Error} If wc_PBKDF2 fails.
 */
const WolfSSL_PBKDF2 = function( password, salt, iterations, keyLen, hash_type )
{
  if ( !Buffer.isBuffer( password ) )
  {
    throw 'password must be Buffer'
  }

  if ( !Buffer.isBuffer( salt ) )
  {
    throw 'salt must be Buffer'
  }

  let type = wolfcrypt.typeof_Hmac( hash_type )

  if ( type < 0 )
  {
    throw 'Invalid hash_type'
  }

  let key = Buffer.alloc( keyLen )

  let ret = wolfcrypt.wc_PBKDF2( key, password, password.length, salt, salt.length, iterations, keyLen, type )

  if ( ret != 0 )
  {
    throw `Failed to wc_PBKDF2 ${ ret }`
  }

  return key
}

exports.WolfSSL_PBKDF2 = WolfSSL_PBKDF2
