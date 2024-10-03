# wolfCrypt Node.JS support

## Description

This Node.js module exposes various wolfCrypt native C functions to Node.js using the Napi library. It makes wolfCrypt functions for ECC, EVP, HMAC, PBKDF2, PKCS7, RSA and SHA available within Nodejs and also provides interface classes that streamline a lot of the tedious actions required when using these functions.

### Native C Functions

The native C functions can be called by importing wolfCrypt from this package:

```
const { wolfcrypt } = require( 'wolfcrypt' )
const message = Buffer.from( 'Hello wolfSSL!' )

// allocate the rsa key
let rsaKey = Buffer.alloc( wolfcrypt.sizeof_RsaKey() )
// init the rsa key
let ret = wolfcrypt.wc_InitRsaKey( rsaKey )
// make a new key
if ( ret == 0 )
  ret = wolfcrypt.wc_MakeRsaKey( rsaKey, 2048, 65537 )
// sign a message
let signature = Buffer.alloc( wolfcrypt.wc_RsaEncryptSize( rsaKey ) )
if ( ret == 0 )
  ret = wolfcrypt.wc_RsaSSL_Sign( message, message.length, signature, signature.length, rsaKey )
// check the signature
if ( ret == signature.length )
  ret = wolfcrypt.wc_RsaSSL_Verify( signature, signature.length, message, message.length, rsaKey )

console.log( ret == message.length )

// free the struct data
ret = wolfcrypt.wc_FreeRsaKey( rsaKey )
```

`ret` will be the return value of the C function. It is important to note that wolfcrypt structures are not managed by the garbage collector and as in the above example the relevant function call must be made to free the memory used by wolfCrypt, in this case `wc_FreeRsaKey`. All of the available C functions can be found in `addon/wolfcrypt/main.cpp`.

### Interface Classes

Alternatively if you find using the native C functions within Node.js to be clunky, interface Classes have been provided to make using wolfCrypt more convenient in Node.js:

```
const { WolfSSLRsa } = require( 'wolfcrypt' )
const message = 'Hello wolfSSL!'

let rsa = new WolfSSLRsa()

try
{
  // make a new key
  rsa.MakeRsaKey( 2048, 65537 )
  // sign a message
  const signature = rsa.SSL_Sign( message )
  // check the signature
  let valid = rsa.SSL_Verify( signature, message )

  console.log( valid )

  // free the struct data
  rsa.free()
}
catch ( e )
{
  console.log( e )
}
```

Instead of needing to check the return value of the C functions, the class will do that for you and throw an error with the wolfSSL error code if anything fails. The free function must still be called to cleanup the internal structure data. The interface classes and their methods can be found in the interfaces folder.

### Streams

The EVP and HMAC interfaces include stream classes that allow them to process data from stream buffers, which is convenient when working with files or http streams:

```
const fs = require( 'fs' )
const { WolfSSLHmacStream } = require( 'wolfcrypt' )

let parts = []
const key = Buffer.from( '12345678901234567890123456789012' )
// create a read stream from the file message.txt
let readStream = fs.createReadStream( 'message.txt' )
let hmacStream = new WolfSSLHmacStream( 'SHA3_512', key )

// collect all the data that come from the hmac stream
hmacStream.on( 'data', function( chunk ) {
  parts.push( chunk )
} )

// called when the end of file has been hashed
hmacStream.on( 'end', function() {
  const fileDigest = Buffer.concat( parts ).toString( 'hex' )

  console.log( fileDigest )
} )

// send the output of the file stream to the hmacStream
readStream.pipe( hmacStream )
```

In the above example we take the contents of `message.txt` and compute the hmac using the provided key and `SHA3_512` as the hashing algorithm.

### Async Support

The RSA and ECC key make functions support async workers and can be called using either a promise or a callback function:

```
const { WolfSSLEcc } = require( 'wolfcrypt' );

( async () => {
  let ecc0 = new WolfSSLEcc()
  let ecc1 = new WolfSSLEcc()

  // make both keys concurrently
  await Promise.all([ ecc0.make_key_promise( 64 ), ecc1.make_key_promise( 64 ) ])

  const secret_0 = ecc0.shared_secret( ecc1 ).toString( 'hex' )
  const secret_1 = ecc1.shared_secret( ecc0 ).toString( 'hex' )

  ecc0.free()
  ecc1.free()

  console.log( secret_0 == secret_1 )
} )()
```

This example uses the `make_key_promise` to make both keys concurrently, but requires promises. The same example using callbacks would look like:

```
const { WolfSSLEcc } = require( 'wolfcrypt' );

let ecc0 = new WolfSSLEcc()
let ecc1 = new WolfSSLEcc()
let readyKeys = 0;

const cb = ( err, ret ) => {
  if ( err || ret != 0 )
  {
    console.log( 'Failed to make key' )
  }
  else
  {
    readyKeys++;

    if ( readyKeys == 2 )
    {
      const secret_0 = ecc0.shared_secret( ecc1 ).toString( 'hex' )
      const secret_1 = ecc1.shared_secret( ecc0 ).toString( 'hex' )

      ecc0.free()
      ecc1.free()

      console.log( secret_0 == secret_1 )
    }
  }
}

// make both keys concurrently
ecc0.make_key_cb( 64, cb )
ecc1.make_key_cb( 64, cb )
```

More examples of how to use the functions in this library can be found in the tests directory

## Building wolfSSL

WolfSSL must be installed on your machine, this package dynamically links it

```
./configure --enable-all
make
sudo make install
```

To link wolfCrypt you need to run `export LD_LIBRARY_PATH=/usr/local/lib` or wherever you have your wolfssl installed:

Verify the .so (shared object) path and version in `binding.gyp`:

```
        'libraries': [
          "/usr/local/lib/libwolfssl.so"
        ],
```

## Package Installation

### Install using npm

```
npm i wolfcrypt
```

Then to import it in your application code

```
const { wolfcrypt, WolfSSLEncryptionStream } = require( 'wolfcrypt' )
...
```

### Install latest main without npm package

```
git clone https://github.com/wolfSSL/wolfcrypt_nodejs
cd wolfcrypt_nodejs
npm i
```

Then copy the directory into your project's `node_modules` folder

```
cp -R wolfcrypt_nodejs my_project/node_modules
```

And import it using the folder name

```
const { wolfcrypt, WolfSSLEncryptionStream } = require( 'wolfcrypt_nodejs' )
...
```

## Tests Output

```
$ npm run test
PASS ecc makeKey
PASS ecc sharedSecret32
PASS ecc sharedSecret64
PASS ecc signVerify
PASS ecc importExportx963
PASS ecc importExportDer
PASS evp encrypt
PASS evp decrypt
PASS evp encrypt_decrypt_odd
PASS evp encryptionStream
PASS evp decryptionStream
PASS evp encryptDecryptPipes
PASS hmac hmac
PASS hmac hmacStream
PASS hmac hmacPipe
PASS pbkdf2
PASS pkcs7 addCertificate
PASS pkcs7 encodeData
PASS pkcs7 signVerify
PASS pkcs7 getAttribute
PASS pkcs7 getSid
PASS rsa keyToDer
PASS rsa keyToPublicDer
PASS rsa privateKeyDecode
PASS rsa publicKeyDecode
PASS rsa encryptDecrypt
PASS rsa signVerify
PASS sha sha
PASS sha sha224
PASS sha sha256
PASS sha sha384
PASS sha sha512
PASS sha sha512_224
PASS sha sha512_256
```
