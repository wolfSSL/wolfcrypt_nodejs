#include "./h/hmac.h"

Napi::Number sizeof_EVP_CIPHER_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( Hmac ) );
}

Napi::Number bind_wc_HmacSetKey(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );
  int type = info[1].As<Napi::Number>().Int32Value();
  uint8_t* key = info[2].As<Napi::Uint8Array>().Data();
  uint32_t keySz = info[3].As<Napi::Number>().Uint32Value();

  ret = wc_HmacSetKey( hmac, type, key, keySz );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_HmacUpdate(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* in = info[1].As<Napi::Uint8Array>().Data();
  int inSz = info[2].As<Napi::Number>().Int32Value();

  ret = wc_HmacUpdate( hmac, in, inSz );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_HmacFinal(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = info[1].As<Napi::Uint8Array>().Data();

  ret = wc_HmacFinal( hmac, out );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_HmacFree(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_HmacFree( hmac );

  return Napi::Number::New( env, ret );
}
