#include <napi.h>
#include "wolfssl/options.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>

Napi::Number sizeof_Hmac(const Napi::CallbackInfo& info);
Napi::Number typeof_Hmac(const Napi::CallbackInfo& info);
Napi::Number Hmac_digest_length(const Napi::CallbackInfo& info);
Napi::Number bind_wc_HmacSetKey(const Napi::CallbackInfo& info);
Napi::Number bind_wc_HmacUpdate(const Napi::CallbackInfo& info);
Napi::Number bind_wc_HmacFinal(const Napi::CallbackInfo& info);
void bind_wc_HmacFree(const Napi::CallbackInfo& info);
