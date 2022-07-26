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
