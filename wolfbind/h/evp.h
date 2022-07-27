#include <napi.h>
#include <stdio.h>
#include <cstring>
#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/evp.h>

Napi::Value bind_EVP_CIPHER_CTX_new(const Napi::CallbackInfo& info);
Napi::Number bind_EVP_CipherInit(const Napi::CallbackInfo& info);
Napi::Number bind_EVP_CipherUpdate(const Napi::CallbackInfo& info);
Napi::Number bind_EVP_CipherFinal(const Napi::CallbackInfo& info);
void bind_EVP_CIPHER_CTX_free(const Napi::CallbackInfo& info);
