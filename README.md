# wolfCrypt Node.JS support

Wrappers for wolfCrypt ciphers.

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

Use npm to install and build:

```
npm i
npm run build
node app.js
```

## Example Output

```
$ node app.js
PASS evp encrypt
PASS evp decrypt
PASS evp encrypt_decrypt_odd
PASS evp encryptionStream
PASS evp decryptionStream
PASS evp encryptDecryptPipes
PASS hmac hmac
PASS hmac hmacStream
PASS hmac hmacPipe
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
PASS ecc makeKey
PASS ecc sharedSecret32
PASS ecc sharedSecret64
PASS ecc signVerify
PASS ecc importExportx963
PASS ecc importExportDer
PASS pbkdf2
```
