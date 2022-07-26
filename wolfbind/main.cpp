#include <napi.h>
#include <stdio.h>
#include <cstring>
#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/openssl/evp.h>

using namespace Napi;

typedef struct WrappedKey
{
  Aes aes[1];
  uint8_t key[32];
  uint8_t iv[16];
} WrappedKey;

Napi::Number sizeof_EVP_CIPHER_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( EVP_CIPHER_CTX ) );
}

Napi::Number bind_EVP_CipherInit(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  EVP_CIPHER_CTX* evp = (EVP_CIPHER_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
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
  EVP_CIPHER_CTX* evp = (EVP_CIPHER_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
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
  EVP_CIPHER_CTX* evp = (EVP_CIPHER_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out_buf = info[1].As<Napi::Uint8Array>().Data();
  int out_len;

  ret = EVP_CipherFinal( evp, out_buf, &out_len );

  if ( ret != WOLFSSL_SUCCESS )
    out_len = -1;

  return Napi::Number::New( env, out_len );
}

Napi::Number MakeAes(const Napi::CallbackInfo& info)
{
  int ret = 0;
  Napi::Env env = info.Env();
  WrappedKey* key = (WrappedKey*)( info[0].As<Napi::Uint8Array>().Data() );

  memcpy( key->key, ( info[1].As<Napi::Uint8Array>().Data() ), 32 );
  memcpy( key->iv, ( info[2].As<Napi::Uint8Array>().Data() ), 16 );

  //ret = wc_AesInit( key->aes, NULL, INVALID_DEVID );

  return Napi::Number::New( env, ret );
}

Napi::Number Encrypt(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WrappedKey* key = (WrappedKey*)(info[0].As<Napi::Uint8Array>().Data());
  uint8_t* out = info[1].As<Napi::Uint8Array>().Data();
  uint8_t* in = info[2].As<Napi::Uint8Array>().Data();
  int length = info[3].As<Napi::Number>().Int32Value();

  ret = wc_AesSetKey( key->aes, key->key, AES_256_KEY_SIZE, key->iv, AES_ENCRYPTION );

  if ( ret == 0 )
  {
    ret = wc_AesCbcEncrypt( key->aes, out, in, length );

    //wc_AesFree( key->aes );
  }


  return Napi::Number::New( env, ret );
}

Napi::Number Decrypt(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WrappedKey* key = (WrappedKey*)(info[0].As<Napi::Uint8Array>().Data());
  uint8_t* out = info[1].As<Napi::Uint8Array>().Data();
  uint8_t* in = info[2].As<Napi::Uint8Array>().Data();
  int length = info[3].As<Napi::Number>().Int32Value();

  ret = wc_AesSetKey( key->aes, key->key, AES_256_KEY_SIZE, key->iv, AES_DECRYPTION );

  if ( ret == 0 )
  {
    ret = wc_AesCbcDecrypt( key->aes, out, in, length );

    //wc_AesFree( key->aes );
  }

  return Napi::Number::New( env, ret );
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
  exports.Set(Napi::String::New(env, "MakeAes"), Napi::Function::New(env, MakeAes));
  exports.Set(Napi::String::New(env, "Encrypt"), Napi::Function::New(env, Encrypt));
  exports.Set(Napi::String::New(env, "Decrypt"), Napi::Function::New(env, Decrypt));

  exports.Set(Napi::String::New(env, "sizeof_EVP_CIPHER_CTX"), Napi::Function::New(env, sizeof_EVP_CIPHER_CTX));
  exports.Set(Napi::String::New(env, "EVP_CipherInit"), Napi::Function::New(env, bind_EVP_CipherInit));
  exports.Set(Napi::String::New(env, "EVP_CipherUpdate"), Napi::Function::New(env, bind_EVP_CipherUpdate));
  exports.Set(Napi::String::New(env, "EVP_CipherFinal"), Napi::Function::New(env, bind_EVP_CipherFinal));

  return exports;
}

NODE_API_MODULE( addon, Init )
