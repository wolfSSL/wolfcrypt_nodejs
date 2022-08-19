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

const { WolfSSL_PBKDF2 } = require( '../interfaces/pbkdf2' )

const pbkdf2_tests = 
{
  pbkdf2: function()
  {
    const password = Buffer.from( 'super secret password' )
    const salt = Buffer.from( 'super secret salt' )

    const key1 = WolfSSL_PBKDF2( password, salt, 2048, 64, 'SHA512' )
    const key2 = WolfSSL_PBKDF2( password, salt, 2048, 64, 'SHA512' )

    if ( key1.toString( 'hex' ) == key2.toString( 'hex' ) )
    {
      console.log( 'PASS pbkdf2' );
    }
    else
    {
      console.log( 'FAIL pbkdf2', key1.toString( 'hex' ), key2.toString( 'hex' ) );
    }
  }
}

module.exports = pbkdf2_tests
