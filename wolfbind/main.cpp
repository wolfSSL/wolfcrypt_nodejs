#include <napi.h>
#include <stdio.h>
#include <cstring>
#include "./h/evp.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>

using namespace Napi;

typedef struct WrappedKey
{
  Aes aes[1];
  uint8_t key[32];
  uint8_t iv[16];
} WrappedKey;

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

  exports.Set(Napi::String::New(env, "EVP_CIPHER_CTX_new"), Napi::Function::New(env, bind_EVP_CIPHER_CTX_new));
  exports.Set(Napi::String::New(env, "EVP_CipherInit"), Napi::Function::New(env, bind_EVP_CipherInit));
  exports.Set(Napi::String::New(env, "EVP_CipherUpdate"), Napi::Function::New(env, bind_EVP_CipherUpdate));
  exports.Set(Napi::String::New(env, "EVP_CipherFinal"), Napi::Function::New(env, bind_EVP_CipherFinal));
  exports.Set(Napi::String::New(env, "EVP_CIPHER_CTX_free"), Napi::Function::New(env, bind_EVP_CIPHER_CTX_free));

  return exports;
}

NODE_API_MODULE( addon, Init )
