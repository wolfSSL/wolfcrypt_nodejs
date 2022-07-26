//const wolfcrypt = require('./build/Release/wolfcrypt');
const { WolfSSLDecryptor } = require( './WolfSSLDecryptor.ts' )

/*
let aes = Buffer.alloc( 1152 )
let key = Buffer.from( '12345678901234567890123456789012' )
let iv = Buffer.from( '1234567890123456' )
let plainText = Buffer.from( 'testtesttesttest' )
let cipherText = Buffer.alloc( 16 )
let plainAgain = Buffer.alloc( 16 )
let length = 16

let ret = wolfcrypt.MakeAes( aes, key, iv )

if ( ret == 0 )
  ret = wolfcrypt.Encrypt( aes, cipherText, plainText, length )

if ( ret == 0 )
  ret = wolfcrypt.Decrypt( aes, plainAgain, cipherText, length )

console.log( plainText.toString() )
console.log( cipherText.toString( 'hex' ) )
console.log( plainAgain.toString() )
*/
/*
let length = 0
let finalOutput = []
const key = Buffer.from('12345678901234567890123456789012')
const iv = Buffer.from('1234567890123456');

console.log( wolfcrypt.GetDecryptionSize() )

let decryption = Buffer.alloc( wolfcrypt.GetDecryptionSize() )
wolfcrypt.NewDecryption( decryption, 'AES-256-CBC', key, iv )

let outBuf = Buffer.alloc( 8 )
length = wolfcrypt.UpdateCipher( decryption, outBuf, Buffer.from('24d31b1e41fc8c40', 'hex'), 8 )
console.log( length )

if ( length > 0 )
{
  finalOutput.push( outBuf )
}

outBuf = Buffer.alloc( 8 )
length = wolfcrypt.UpdateCipher( decryption, outBuf, Buffer.from('e521531d67c72c20', 'hex'), 8 )
console.log( length )

if ( length > 0 )
{
  finalOutput.push( outBuf )
}

outBuf = Buffer.alloc( 16 )
length = wolfcrypt.FinalizeCipher( decryption, outBuf )
console.log( length )

if ( length > 0 )
{
  finalOutput.push( outBuf )
}

console.log( Buffer.concat( finalOutput ).toString() )
*/

const key = Buffer.from('12345678901234567890123456789012');
const iv = Buffer.from('1234567890123456');
const decrypt = new WolfSSLDecryptor('AES-256-CBC', key, iv);
const expected = 'test';

const actual = Buffer.concat([
  decrypt.update(Buffer.from('24d31b1e41fc8c40', 'hex')),
  decrypt.update(Buffer.from('e521531d67c72c20', 'hex')),
  decrypt.finalize()
]);

console.log( actual.toString() )
