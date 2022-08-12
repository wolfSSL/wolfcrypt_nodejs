/* app.js
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
const evp_tests = require( './tests/evp' );
const hmac_tests = require( './tests/hmac' );
const rsa_tests = require( './tests/rsa' );
const sha_tests = require( './tests/sha' );
const ecc_tests = require( './tests/ecc' );
const pbkdf2_tests = require( './tests/pbkdf2' );
const pkcs7_tests = require( './tests/pkcs7' );

(async function() {
  for ( const key of Object.keys( evp_tests ) )
  {
    await evp_tests[key]()
  }

  for ( const key of Object.keys( hmac_tests ) )
  {
    await hmac_tests[key]()
  }

  for ( const key of Object.keys( rsa_tests ) )
  {
    await rsa_tests[key]()
  }

  for ( const key of Object.keys( sha_tests ) )
  {
    await sha_tests[key]()
  }

  for ( const key of Object.keys( ecc_tests ) )
  {
    await ecc_tests[key]()
  }

  for ( const key of Object.keys( pbkdf2_tests ) )
  {
    await pbkdf2_tests[key]()
  }

  for ( const key of Object.keys( pkcs7_tests ) )
  {
    await pkcs7_tests[key]()
  }
})()
