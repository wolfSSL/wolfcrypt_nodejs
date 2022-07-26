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
npm run tsrun
```

## Example Output

```
$ npm run tsrun
> wolfcrypt_binding@1.0.0 tsrun /home/davidgarske/GitHub/wolfcrypt_nodejs
> npx tsc main.ts && node main.js

PASS
```
