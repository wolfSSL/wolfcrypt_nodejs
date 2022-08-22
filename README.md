# wolfCrypt Node.JS support

Wrappers for various wolfCrypt functions.

## Building wolfSSL

```
./configure --enable-all
make
sudo make install
```

To link wolfcrypt you need to run `export LD_LIBRARY_PATH=/usr/local/lib` or wherever you have your wolfssl installed:

Verify the .so (shared object) path and version in `binding.gyp`:

```
        'libraries': [
          "/usr/local/lib/libwolfssl.so.34"
        ],
```

## Package Installation

Use npm to install the package:

```
npm i wolfcrypt
```

Then require it in your application code

```
const { wolfcrypt, WolfSSLEncryptionStream } = require( 'wolfcrypt' )
```

Examples of how to use this library can be found in the tests directory

### Installing latest main without upstream package

```
npm i
npm run build
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
