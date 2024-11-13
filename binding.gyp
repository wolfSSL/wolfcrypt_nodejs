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
            "addon/wolfcrypt/pkcs7.cpp",
            "addon/wolfcrypt/pkcs12.cpp",
            "addon/wolfcrypt/random.cpp"
        ],
        "include_dirs": [
            "<!@(node -p \"require('node-addon-api').include\")"
        ],
        "libraries": [],
        "dependencies": [
            "<!(node -p \"require('node-addon-api').gyp\")"
        ],
        "defines": [ "NAPI_DISABLE_C_EXCEPTIONS" ],
        "conditions": [
            ['OS=="linux"', {
                "libraries": [
                    "/usr/local/lib/libwolfssl.so"
                ]
            }],
            ['OS=="win"', {
                "defines": [ "WOLFSSL_USER_SETTINGS" ],
                "libraries": [
                    "<!(powershell -command \"if ($env:WOLFSSL_LIB_PATH) { echo $env:WOLFSSL_LIB_PATH } else { echo 'C:/workspace/wolfssl/DLL Release/x64' }\")/wolfssl.lib",
                    "ws2_32.lib",
                    "crypt32.lib",
                    "advapi32.lib",
                    "user32.lib",
                    "kernel32.lib"
                ],
                "include_dirs": [
                    "<!(powershell -command \"if ($env:WOLFSSL_INCLUDE_PATH) { echo $env:WOLFSSL_INCLUDE_PATH } else { echo 'C:/workspace/wolfssl' }\")",
                    "<!(powershell -command \"if ($env:WOLFSSL_USER_SETTINGS_PATH) { echo $env:WOLFSSL_USER_SETTINGS_PATH } else { echo 'C:/workspace/wolfssl/IDE/WIN' }\")"
                ]
            }],

        ],
        'defines': ['NAPI_DISABLE_C_EXCEPTIONS'],
        'msvs_settings': {
            'VCCLCompilerTool': {
                'ExceptionHandling': '1',
                'AdditionalOptions': ['/EHsc']
            }
        }
    }]
}
