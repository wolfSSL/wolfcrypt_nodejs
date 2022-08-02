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
const { WolfSSLRsa } = require( '../interfaces/rsa' )

const privateDerHex = '308204a40201000282010100b9588e111d0172e016b37b757498e9658332ff21aae11b3bced29c6854d80e2dc32aa89e0ca46dd57b9fad6e0c36ad7d7c2450be6ca3eb17516c3f540a19a39db46d38f30da0fb4aea1d32565d2a73541d934b2660a70e6651e5927ddcd4e827c0c00185182c3be4cbde284fadaab40970195f871e04852ec75da785aba4142864a4a767ee84cc65d85f5c11be7ea83968ab822d7c06060f1de720a88389967cb87c3a5792c5ad1c907b58fa8ca2c365c46e5c0fdbfb337771301bbcbd8ee504311283bb003470ddb6aa64407aab7d8eb2722b08c3164a8a0c1b398c94078099a7fb20011402cb271c246c892d0b79f0b17ec8401dfe762371ae01d68034998b0203010001028201000b7c26497f2fa0cbabfc7131050998a4d6ad694bcfc7e5251e9ac4605ea988af634198733abb51a701e3121f1898a6c578d4d34009815ac6f61fac08ec1b4c9d3019f8866f18c3998fca415d42a6a7c0d59853f6cbd46e3afee627deaeb96ead4fef55e8c667af4a6d2b95f9e1fc0aedeec953b70eb01f04980c009e72d556fe52c3b3251d5b54e5613ff63dbe7809f91a742852d886503fd96b380e9a968ee6a1ca3e029032631f42fbbfe6b476b7f711a2574a5bca876e8e5ccd8ea502432c35fce8ae331ca68cf144726bfc3cdc7f8eff79a9983d11b171e28840975a04a78fe9dab25d5b99d58ca72977f07d608713ed28174691c74257c954389e1199d102818100e0fb51869f7793ce2c7f405175d4bef807f87e44d43ec1a911dbc7516614cb249ee901e2c910ea8f74fa83fba756e053cd85f7138162d262fafd7462ea82cab1bc4a363fc2c594b2d10e96d72c993cbbdffd96753b2d1b33c5fc7563c7f034cf30e216bf4e51b8a4abeeed7b05cb9646b0e6f6c61b564ab2d9e0508ffaff0e3302818100d2e64cb02b8861f6c99bae355d6ac8168c2df466ade212a69e9adba701e5eafa413bfcd579e6fb4ee1b232d4e391541ca4adf65f318048cdff58ec59997fb44bb36f7065e20953765d9c12fa9147ba0538c3d76492c6542ea6314a7ca9e2b8af62c5e9a926f6671911ebdc07ea456f84a7a1764ba2a547dcd3d643e822193f4902818100aba35009127399917b25019ea3f45054cd4fe894fe0f7a934f8a8a3f314fbfc30a70dcfd7543b08f0d41699b7d88abcf834626befcc0b59cc9babf260f9f04a01ff3c5fb52ce85a8fe10d1470b4144b2582a10b513165060693537218e9154d8948487b21f3ffd4bb3d7add9630c74732dd6a68170ad9e835ff0dfc55849693d02818100cfc3e79aca582242505d1923237395c878b2b10a12951bd09f816990be92f5893288d94ca939ff2bb7b6a8d307995d2696a97684532cd10c7758f00658ecf0fe7eb7f31fbbad7a56aa639e62d08abbdc770e9ffc49882ed8820b1f196ef796ffd92ba64468c8e7ca4fd86ebc3173d427f8485d54a7d771d33fb1ded629f97b590281800f314729ce79f742cf15f0ab03ab8dee4f49d4c917b8b187ea8bc005436a9e6d6f07c49118f7743adbbaaf14707c642e101368c27a27d55ef1f01bb3a9a36c8ed1dcab08172ff7b74ade213bf327b73936b3915f8979646fcfea5a879c372104b5345898a89b3214edb1c435ec6bdf96d1875a3457f2e0f790d0b5a6cd153a08'
const publicDerHex = '30820122300d06092a864886f70d01010105000382010f003082010a0282010100b9588e111d0172e016b37b757498e9658332ff21aae11b3bced29c6854d80e2dc32aa89e0ca46dd57b9fad6e0c36ad7d7c2450be6ca3eb17516c3f540a19a39db46d38f30da0fb4aea1d32565d2a73541d934b2660a70e6651e5927ddcd4e827c0c00185182c3be4cbde284fadaab40970195f871e04852ec75da785aba4142864a4a767ee84cc65d85f5c11be7ea83968ab822d7c06060f1de720a88389967cb87c3a5792c5ad1c907b58fa8ca2c365c46e5c0fdbfb337771301bbcbd8ee504311283bb003470ddb6aa64407aab7d8eb2722b08c3164a8a0c1b398c94078099a7fb20011402cb271c246c892d0b79f0b17ec8401dfe762371ae01d68034998b0203010001'
const rsaSigHex = '2f5f5b8410d11daa48f6474fda9a58cec4ab2c2c627300d3518671f1dc128ecdc30440ce105f77403506869427d30fd8a32ba15fb9656b8a13bb7abd6bcf63e4eb946c2a139506684a10b5a5e5644d140ca8cd7fb12edf027650500cadebb74ea6c857bdb7b47a5a39917763039fd5ed849554017cc69034910746f4a924815ab94d1d099774170b7b126b4d91f2e811a9eebe651cff3db494bdf4501cf4c08ebecccd66c7b40f49e9fec881d2cf672ef7ebd9e5ce515c7fe88ac7c9733755a82220ddd294130a682f0b40d5dd2855ea2607ab6b51c8187e1f3aad0b4defd30316cb9ae6270d8caf2977753c9272180c7f68242b4c74e741a48f5ffa01c5c36c'
const message = '\ntesttesttest\n'

const rsa_tests =
{
  keyToDer: function()
  {
    let rsa = new WolfSSLRsa()

    rsa.MakeRsaKey( 2048, 65537 )

    const derHex = rsa.KeyToDer().toString( 'hex' )

    rsa.free()

    console.log( 'PASS rsa keyToDer' )
  },

  keyToPublicDer: function()
  {
    let rsa = new WolfSSLRsa()

    rsa.PrivateKeyDecode( Buffer.from( privateDerHex, 'hex' ) )

    const derHex = rsa.KeyToPublicDer().toString( 'hex' )

    rsa.free()

    console.log( 'PASS rsa keyToPublicDer' )
  },

  privateKeyDecode: function()
  {
    let rsa = new WolfSSLRsa()

    rsa.PrivateKeyDecode( Buffer.from( privateDerHex, 'hex' ) )

    const sigHex = rsa.SSL_Sign( message ).toString( 'hex' )

    rsa.free()

    if ( sigHex == rsaSigHex )
    {
      console.log( 'PASS rsa privateKeyDecode' )
    }
    else
    {
      console.log( 'FAIL rsa privateKeyDecode' )
    }
  },

  publicKeyDecode: function()
  {
    let rsa = new WolfSSLRsa()

    rsa.PublicKeyDecode( Buffer.from( publicDerHex, 'hex' ) )

    if ( rsa.SSL_Verify( Buffer.from( rsaSigHex, 'hex' ), message ) )
    {
      console.log( 'PASS rsa publicKeyDecode' )
    }
    else
    {
      console.log( 'FAIL rsa publicKeyDecode' )
    }

    rsa.free()
  },

  encryptDecrypt: function()
  {
    let rsa = new WolfSSLRsa()

    rsa.PrivateKeyDecode( Buffer.from( privateDerHex, 'hex' ) )

    const ciphertext = rsa.PublicEncrypt( message )
    const plaintext = rsa.PrivateDecrypt( ciphertext ).toString()

    rsa.free()

    if ( plaintext == message )
    {
      console.log( 'PASS rsa encryptDecrypt' )
    }
    else
    {
      console.log( 'FAIL rsa encryptDecrypt' )
    }
  },

  signVerify: function()
  {
    let rsa = new WolfSSLRsa()

    rsa.PrivateKeyDecode( Buffer.from( privateDerHex, 'hex' ) )

    const sig = rsa.SSL_Sign( message )

    if ( rsa.SSL_Verify( sig, message ) )
    {
      console.log( 'PASS rsa signVerify' )
    }
    else
    {
      console.log( 'FAIL rsa signVerify' )
    }

    rsa.free()
  }
}

module.exports = rsa_tests
