/* pkcs7.js
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
const { WolfSSL_PKCS7 } = require( '../interfaces/pkcs7' )
const fs = require( 'fs' )

const message = 'Hello WolfSSL!'

const pkcs7_tests =
{
  pkcs7_addCertificate: function()
  {
    const cert = fs.readFileSync( './client-cert.der' )

    let pkcs7 = new WolfSSL_PKCS7()
    pkcs7.AddCertificate( cert )

    pkcs7.free()

    console.log( 'PASS pkcs7 addCertificate' )
  },

  pkcs7_encodeData: function()
  {
    const cert = fs.readFileSync( './client-cert.der' )
    const key = fs.readFileSync( './client-key.der' )

    let pkcs7 = new WolfSSL_PKCS7()
    pkcs7.AddCertificate( cert )

    const encoded = pkcs7.EncodeData( message, key )

    pkcs7.free()

    console.log( 'PASS pkcs7 encodeData' )
  },

  pkcs7_signVerify: function()
  {
    const cert = fs.readFileSync( './client-cert.der' )
    const key = fs.readFileSync( './client-key.der' )

    let pkcs7 = new WolfSSL_PKCS7()
    pkcs7.AddCertificate( cert )

    const encoded = pkcs7.EncodeSignedData( message, key, 'RSA', 'SHA' )

    pkcs7.free()

    pkcs7 = new WolfSSL_PKCS7()

    pkcs7.VerifySignedData( encoded )

    console.log( 'PASS pkcs7 signVerify' )
  },

  pkcs7_getAttribute: function()
  {
    const cert = fs.readFileSync( './client-cert.der' )
    const key = fs.readFileSync( './client-key.der' )

    let pkcs7 = new WolfSSL_PKCS7()
    pkcs7.AddCertificate( cert )

    const encoded = pkcs7.EncodeSignedData( message, key, 'RSA', 'SHA' )

    pkcs7.free()

    pkcs7 = new WolfSSL_PKCS7()

    pkcs7.VerifySignedData( encoded )

    // oid identifier for data
    const data = pkcs7.GetAttributeValue( Buffer.from( '2a864886f70d010904', 'hex' ) )

    console.log( 'PASS pkcs7 getAttribute' )
  },

  pkcs7_getSid: function()
  {
    const cert = fs.readFileSync( './client-cert.der' )
    const key = fs.readFileSync( './client-key.der' )

    let pkcs7 = new WolfSSL_PKCS7()
    pkcs7.AddCertificate( cert )

    const encoded = pkcs7.EncodeSignedData( message, key, 'RSA', 'SHA' )

    pkcs7.free()

    pkcs7 = new WolfSSL_PKCS7()

    pkcs7.VerifySignedData( encoded )

    // oid identifier for data
    const data = pkcs7.GetSignerSID()

    console.log( 'PASS pkcs7 getSid' )
  },
}

module.exports = pkcs7_tests
