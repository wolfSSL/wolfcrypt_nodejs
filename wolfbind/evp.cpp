#include "./h/evp.h"

Napi::Number sizeof_EVP_CIPHER_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( EVP_CIPHER_CTX ) );
}

Napi::Value bind_EVP_CIPHER_CTX_new(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  EVP_CIPHER_CTX* evp = EVP_CIPHER_CTX_new();
  Napi::External<EVP_CIPHER_CTX> evp_ext = Napi::External<EVP_CIPHER_CTX>::New( env, evp );

  return evp_ext;
}

Napi::Number bind_EVP_CipherInit(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  EVP_CIPHER_CTX* evp = info[0].As<Napi::External<EVP_CIPHER_CTX>>().Data();
  std::string type = info[1].As<Napi::String>().Utf8Value();
  uint8_t* key = info[2].As<Napi::Uint8Array>().Data();
  uint8_t* iv = info[3].As<Napi::Uint8Array>().Data();
  int enc = info[4].As<Napi::Number>().Int32Value();

  ret = EVP_CipherInit( evp, type.c_str(), key, iv, enc );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_EVP_CipherUpdate(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  EVP_CIPHER_CTX* evp = info[0].As<Napi::External<EVP_CIPHER_CTX>>().Data();
  uint8_t* out_buf = info[1].As<Napi::Uint8Array>().Data();
  int out_len;
  uint8_t* in_buf = info[2].As<Napi::Uint8Array>().Data();
  int in_len = info[3].As<Napi::Number>().Int32Value();

  ret = EVP_CipherUpdate( evp, out_buf, &out_len, in_buf, in_len );

  if ( ret != WOLFSSL_SUCCESS )
    out_len = -1;

  return Napi::Number::New( env, out_len );
}

Napi::Number bind_EVP_CipherFinal(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  EVP_CIPHER_CTX* evp = info[0].As<Napi::External<EVP_CIPHER_CTX>>().Data();
  uint8_t* out_buf = info[1].As<Napi::Uint8Array>().Data();
  int out_len;

  ret = EVP_CipherFinal( evp, out_buf, &out_len );

  if ( ret != WOLFSSL_SUCCESS )
    out_len = -1;

  return Napi::Number::New( env, out_len );
}

void bind_EVP_CIPHER_CTX_free(const Napi::CallbackInfo& info)
{
  EVP_CIPHER_CTX* evp = info[0].As<Napi::External<EVP_CIPHER_CTX>>().Data();

  EVP_CIPHER_CTX_free( evp );
}
