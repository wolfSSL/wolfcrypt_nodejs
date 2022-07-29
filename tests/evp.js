const fs = require( 'fs' )
const { WolfSSLEncryptor, WolfSSLDecryptor, WolfSSLEncryptionStream, WolfSSLDecryptionStream } = require( '../interfaces/evp' )
const wolfcrypt = require( '../build/Release/wolfcrypt' )

const key = Buffer.from('12345678901234567890123456789012')
const iv = Buffer.from('1234567890123456')
const expected = 'test'
const expectedCiphertext = '24d31b1e41fc8c40e521531d67c72c20'
// 17 bytes to test padding
const expectedLonger = '12345678901234567'
const expectedMessage = 'Hello WolfSSL!\n'

const evp_tests =
{
  encrypt: function()
  {
    let encrypt = new WolfSSLEncryptor( 'AES-256-CBC', key, iv )

    const actual = Buffer.concat([
      encrypt.update( expected ),
      encrypt.finalize()
    ]).toString( 'hex' )

    if ( actual == expectedCiphertext )
    {
      console.log( 'PASS evp encrypt' )
    }
    else
    {
      console.log( 'FAIL evp encrypt', actual, expectedCiphertext )
    }
  },

  decrypt: function()
  {
    let decrypt = new WolfSSLDecryptor( 'AES-256-CBC', key, iv )

    const actual = Buffer.concat([
      decrypt.update( Buffer.from( expectedCiphertext, 'hex' ) ),
      decrypt.finalize()
    ]).toString()

    if ( actual == expected )
    {
      console.log( 'PASS evp decrypt' )
    }
    else
    {
      console.log( 'FAIL evp decrypt', actual, expected )
    }
  },

  encryptDecryptOdd: function()
  {
    let parts = []
    let encrypt = new WolfSSLEncryptor( 'AES-256-CBC', key, iv )
    let decrypt = new WolfSSLDecryptor( 'AES-256-CBC', key, iv )

    for ( let i = 0; i < expectedLonger.length; i++ )
    {
      parts.push( encrypt.update( expectedLonger[i] ) )
    }

    parts.push( encrypt.finalize() )

    const actualCiphertext = Buffer.concat( parts )

    parts = []

    for ( let i = 0; i < actualCiphertext.length; i++ )
    {
      parts.push( decrypt.update( actualCiphertext.subarray( i, i + 1 ) ) )
    }

    parts.push( decrypt.finalize() )

    const actualPlaintext = Buffer.concat( parts ).toString()

    if ( actualPlaintext == expectedLonger )
    {
      console.log( 'PASS evp encrypt_decrypt_odd' )
    }
    else
    {
      console.log( 'FAIL evp encrypt_decrypt_odd', actualPlaintext, expectedLonger )
    }
  },

  encryptionStream: async function()
  {
    await new Promise( (res, rej) => {
      let parts = []
      let encryptStream = new WolfSSLEncryptionStream( 'AES-256-CBC', key, iv )

      encryptStream.on( 'data', function( chunk ) {
        parts.push( chunk )
      } )

      encryptStream.on( 'end', function() {
        const actual = Buffer.concat( parts ).toString( 'hex' )

        if ( actual == expectedCiphertext )
        {
          console.log( 'PASS evp encryptionStream' )
        }
        else
        {
          console.log( 'FAIL evp encryptionStream', actual, expectedCiphertext )
        }

        res()
      } )

      for ( i = 0; i < expected.length; i++ )
      {
        encryptStream.write( expected[i] )
      }

      encryptStream.end()
    } )
  },

  decryptionStream: async function()
  {
    await new Promise( (res, rej) => {
      let parts = []
      let decryptStream = new WolfSSLDecryptionStream( 'AES-256-CBC', key, iv )

      decryptStream.on( 'data', function( chunk ) {
        parts.push( chunk )
      } )

      decryptStream.on( 'end', function() {
        const actual = Buffer.concat( parts ).toString()

        if ( actual == expected )
        {
          console.log( 'PASS evp decryptionStream' )
        }
        else
        {
          console.log( 'FAIL evp decryptionStream', actual, expected )
        }

        res()
      } )

      decryptStream.write( Buffer.from( expectedCiphertext, 'hex' ) )

      decryptStream.end()
    } )
  },

  encryptDecryptPipes: async function()
  {
    await new Promise( (res, rej) => {
      let parts = []
      let readStream = fs.createReadStream( 'message.txt' )
      let encryptStream = new WolfSSLEncryptionStream( 'AES-256-CBC', key, iv )
      let decryptStream = new WolfSSLDecryptionStream( 'AES-256-CBC', key, iv )

      decryptStream.on( 'data', function( chunk ) {
        parts.push( chunk )
      } )

      decryptStream.on( 'end', function() {
        const actual = Buffer.concat( parts ).toString()

        if ( actual == expectedMessage )
        {
          console.log( 'PASS evp encryptDecryptPipes' )
        }
        else
        {
          console.log( 'FAIL evp encryptDecryptPipes', actual, expectedMessage )
        }

        res()
      } )

      // in this case we pipe to decrypt which defeats the purpose, but it could pipe to any stream such as a file
      readStream.pipe( encryptStream ).pipe( decryptStream )
    } )
  },
}

module.exports = evp_tests
