{
    "targets": [{
        "target_name": "wolfcrypt",
        "cflags!": [ "-fno-exceptions" ],
        "cflags_cc!": [ "-fno-exceptions" ],
        "sources": [
            "addon/wolfcrypt/main.cpp",
            "addon/wolfcrypt/evp.cpp",
            "addon/wolfcrypt/hmac.cpp",
            "addon/wolfcrypt/rsa.cpp",
            "addon/wolfcrypt/sha.cpp",
            "addon/wolfcrypt/ecc.cpp",
            "addon/wolfcrypt/pbkdf2.cpp",
            "addon/wolfcrypt/pkcs7.cpp"
        ],
        'include_dirs': [
            "<!@(node -p \"require('node-addon-api').include\")"
        ],
        'libraries': [
            "/usr/local/lib/libwolfssl.so"
        ],
        'dependencies': [
            "<!(node -p \"require('node-addon-api').gyp\")",
        ],
        'defines': [ 'NAPI_DISABLE_C_EXCEPTIONS' ],
        'msvs_settings': {
            'VCCLCompilerTool': {
                'ExceptionHandling': '1',    
                'AdditionalOptions': ['/EHsc']
            }
        }
    }]
}
