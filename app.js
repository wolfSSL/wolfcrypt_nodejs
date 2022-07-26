const wolfcrypt = require('./build/Release/wolfcrypt');

let aes = Buffer.alloc( 300 )
let key = Buffer.from( '12345678901234567890123456789012' )
let iv = Buffer.from( '1234567890123456' )
let plainText = Buffer.from( 'testtesttesttest' )
let cipherText = Buffer.alloc( 16 )
let plainAgain = Buffer.alloc( 16 )

let ret = wolfcrypt.MakeAes( aes, key, iv )

if ( ret == 0 )
{
  ret = wolfcrypt.Encrypt( aes, cipherText, plainText, 16 )
}

if ( ret == 0 )
{
  ret = wolfcrypt.Decrypt( aes, plainAgain, cipherText, 16 )
}

console.log( plainText.toString() );
console.log( cipherText.toString( 'hex' ) );
console.log( plainAgain.toString() );
