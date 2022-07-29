#include <napi.h>
#include <stdio.h>
#include <cstring>
#include "./h/evp.h"
#include "./h/hmac.h"
#include "./h/rsa.h"
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

  exports.Set(Napi::String::New(env, "sizeof_Hmac"), Napi::Function::New(env, sizeof_Hmac));
  exports.Set(Napi::String::New(env, "typeof_Hmac"), Napi::Function::New(env, typeof_Hmac));
  exports.Set(Napi::String::New(env, "Hmac_digest_length"), Napi::Function::New(env, Hmac_digest_length));
  exports.Set(Napi::String::New(env, "wc_HmacSetKey"), Napi::Function::New(env, bind_wc_HmacSetKey));
  exports.Set(Napi::String::New(env, "wc_HmacUpdate"), Napi::Function::New(env, bind_wc_HmacUpdate));
  exports.Set(Napi::String::New(env, "wc_HmacFinal"), Napi::Function::New(env, bind_wc_HmacFinal));
  exports.Set(Napi::String::New(env, "wc_HmacFree"), Napi::Function::New(env, bind_wc_HmacFree));

  exports.Set(Napi::String::New(env, "sizeof_RsaKey"), Napi::Function::New(env, sizeof_RsaKey));
  exports.Set(Napi::String::New(env, "wc_RsaEncryptSize"), Napi::Function::New(env, bind_wc_RsaEncryptSize));
  exports.Set(Napi::String::New(env, "wc_InitRsaKey"), Napi::Function::New(env, bind_wc_InitRsaKey));
  exports.Set(Napi::String::New(env, "wc_MakeRsaKey"), Napi::Function::New(env, bind_wc_MakeRsaKey));
  exports.Set(Napi::String::New(env, "wc_RsaKeyToDer"), Napi::Function::New(env, bind_wc_RsaKeyToDer));
  exports.Set(Napi::String::New(env, "wc_RsaPrivateKeyDecode"), Napi::Function::New(env, bind_wc_RsaPrivateKeyDecode));
  exports.Set(Napi::String::New(env, "wc_RsaPublicKeyDecode"), Napi::Function::New(env, bind_wc_RsaPublicKeyDecode));
  exports.Set(Napi::String::New(env, "wc_RsaPublicEncrypt"), Napi::Function::New(env, bind_wc_RsaPublicEncrypt));
  exports.Set(Napi::String::New(env, "wc_RsaPrivateDecrypt"), Napi::Function::New(env, bind_wc_RsaPrivateDecrypt));
  exports.Set(Napi::String::New(env, "wc_FreeRsaKey"), Napi::Function::New(env, bind_wc_FreeRsaKey));

  return exports;
}

NODE_API_MODULE( addon, Init )
