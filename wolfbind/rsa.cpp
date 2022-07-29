#include "./h/rsa.h"

Napi::Number sizeof_RsaKey(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( RsaKey ) );
}

Napi::Number bind_wc_RsaEncryptSize(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_RsaEncryptSize( rsa );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_InitRsaKey(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_InitRsaKey( rsa, NULL );

  rsa->rng = (WC_RNG*)XMALLOC( sizeof( WC_RNG ), rsa->heap, DYNAMIC_TYPE_RNG );

  wc_InitRng( rsa->rng );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_MakeRsaKey(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );
  int size = info[1].As<Napi::Number>().Int32Value();
  long e = info[2].As<Napi::Number>().Int64Value();

  ret = wc_MakeRsaKey( rsa, size, e, rsa->rng );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaKeyToDer(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = info[1].As<Napi::Uint8Array>().Data();
  int outSz = info[2].As<Napi::Number>().Int32Value();

  ret = wc_RsaKeyToDer( rsa, out, outSz );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaPrivateKeyDecode(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* in = info[0].As<Napi::Uint8Array>().Data();
  RsaKey* rsa = (RsaKey*)( info[1].As<Napi::Uint8Array>().Data() );
  int inSz = info[2].As<Napi::Number>().Int32Value();
  unsigned int idx = 0;

  ret = wc_RsaPrivateKeyDecode( in, &idx, rsa, inSz );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaPublicKeyDecode(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* in = info[0].As<Napi::Uint8Array>().Data();
  RsaKey* rsa = (RsaKey*)( info[1].As<Napi::Uint8Array>().Data() );
  int inSz = info[2].As<Napi::Number>().Int32Value();
  unsigned int idx = 0;

  ret = wc_RsaPublicKeyDecode( in, &idx, rsa, inSz );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaPublicEncrypt(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* in = info[0].As<Napi::Uint8Array>().Data();
  int inLen = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = info[2].As<Napi::Uint8Array>().Data();
  int outLen = info[3].As<Napi::Number>().Int32Value();
  RsaKey* rsa = (RsaKey*)( info[4].As<Napi::Uint8Array>().Data() );

  ret = wc_RsaPublicEncrypt( in, inLen, out, outLen, rsa, rsa->rng );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaPrivateDecrypt(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* in = info[0].As<Napi::Uint8Array>().Data();
  int inLen = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = info[2].As<Napi::Uint8Array>().Data();
  int outLen = info[3].As<Napi::Number>().Int32Value();
  RsaKey* rsa = (RsaKey*)( info[4].As<Napi::Uint8Array>().Data() );

  ret = wc_RsaPrivateDecrypt( in, inLen, out, outLen, rsa );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_FreeRsaKey(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );

  wc_FreeRng( rsa->rng );
  ret = wc_FreeRsaKey( rsa );

  return Napi::Number::New( env, ret );
}
