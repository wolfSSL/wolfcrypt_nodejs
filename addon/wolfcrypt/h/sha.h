#include <napi.h>
#include "wolfssl/options.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/openssl/sha.h>

Napi::Number Sha_digest_length(const Napi::CallbackInfo& info);

Napi::Number sizeof_WOLFSSL_SHA_CTX(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA_Update(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA_Final(const Napi::CallbackInfo& info);

Napi::Number sizeof_WOLFSSL_SHA224_CTX(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA224_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA224_Update(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA224_Final(const Napi::CallbackInfo& info);

Napi::Number sizeof_WOLFSSL_SHA256_CTX(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA256_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA256_Update(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA256_Final(const Napi::CallbackInfo& info);

Napi::Number sizeof_WOLFSSL_SHA384_CTX(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA384_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA384_Update(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA384_Final(const Napi::CallbackInfo& info);

Napi::Number sizeof_WOLFSSL_SHA512_CTX(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_Update(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_Final(const Napi::CallbackInfo& info);

Napi::Number sizeof_WOLFSSL_SHA512_224_CTX(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_224_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_224_Update(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_224_Final(const Napi::CallbackInfo& info);

Napi::Number sizeof_WOLFSSL_SHA512_256_CTX(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_256_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_256_Update(const Napi::CallbackInfo& info);
Napi::Number bind_wolfSSL_SHA512_256_Final(const Napi::CallbackInfo& info);
