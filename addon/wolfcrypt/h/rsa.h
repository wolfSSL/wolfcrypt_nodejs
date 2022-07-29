#include <napi.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>

Napi::Number sizeof_RsaKey(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaEncryptSize(const Napi::CallbackInfo& info);
Napi::Number bind_wc_InitRsaKey(const Napi::CallbackInfo& info);
Napi::Number bind_wc_MakeRsaKey(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaKeyToDer(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPrivateKeyDecode(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPublicKeyDecode(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPublicEncrypt(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPrivateDecrypt(const Napi::CallbackInfo& info);
Napi::Number bind_wc_FreeRsaKey(const Napi::CallbackInfo& info);
