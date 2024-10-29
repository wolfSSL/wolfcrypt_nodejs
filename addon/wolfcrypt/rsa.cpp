/* rsa.cpp
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#ifndef WOLFSSL_USER_SETTINGS
#include "wolfssl/options.h"
#else
#include "../user_settings.h"
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
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
#ifdef WC_RSA_BLINDING
  rsa->rng = wc_rng_new( NULL, 0, NULL );
#endif

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_MakeRsaKey(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );
#ifdef WC_RSA_BLINDING
  WC_RNG* rng = rsa->rng;
#else
  WC_RNG* rng = wc_rng_new( NULL, 0, NULL );
#endif
  int size = info[1].As<Napi::Number>().Int32Value();
  long e = info[2].As<Napi::Number>().Int64Value();

  ret = wc_MakeRsaKey( rsa, size, e, rng );

#ifndef WC_RSA_BLINDING
  wc_rng_free( rng );
#endif

  return Napi::Number::New( env, ret );
}

class wc_MakeRsaKeyAsyncWorker : public Napi::AsyncWorker
{
  public:
    wc_MakeRsaKeyAsyncWorker( Napi::Function& callback, RsaKey* rsa, int size, long e )
      : Napi::AsyncWorker( callback ), rsa( rsa ), size( size ), e( e )
    {
    }

    ~wc_MakeRsaKeyAsyncWorker() {}

    void Execute() override
    {
#ifdef WC_RSA_BLINDING
      WC_RNG* rng = rsa->rng;
#else
      WC_RNG* rng = wc_rng_new( NULL, 0, NULL );
#endif

      ret = wc_MakeRsaKey( rsa, size, e, rng );

#ifndef WC_RSA_BLINDING
      wc_rng_free( rng );
#endif
    }

    void OnOK() override
    {
      Napi::HandleScope scope(Env());
      Callback().Call({Env().Undefined(), Napi::Number::New(Env(), ret)});
    }
  private:
    RsaKey* rsa;
    int size;
    long e;
    int ret;
};

// uses the above async worker to make the key, callback will be called
// when the key has completed
Napi::Value wc_MakeRsaKey_async(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );
  int size = info[1].As<Napi::Number>().Int32Value();
  long e = info[2].As<Napi::Number>().Int64Value();
  Napi::Function callback = info[3].As<Napi::Function>();

  wc_MakeRsaKeyAsyncWorker* key_worker = new wc_MakeRsaKeyAsyncWorker( callback, rsa, size, e );
  key_worker->Queue();

  return env.Undefined();
}

Napi::Number RsaPrivateDerSize(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_RsaKeyToDer( rsa, NULL, 0 );

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

Napi::Number RsaPublicDerSize(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_RsaKeyToPublicDer( rsa, NULL, 0 );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaKeyToPublicDer(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = info[1].As<Napi::Uint8Array>().Data();
  int outSz = info[2].As<Napi::Number>().Int32Value();

  ret = wc_RsaKeyToPublicDer( rsa, out, outSz );

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
  int in_len = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = info[2].As<Napi::Uint8Array>().Data();
  int out_len = info[3].As<Napi::Number>().Int32Value();
  RsaKey* rsa = (RsaKey*)( info[4].As<Napi::Uint8Array>().Data() );
#ifdef WC_RSA_BLINDING
  WC_RNG* rng = rsa->rng;
#else
  WC_RNG* rng = wc_rng_new( NULL, 0, NULL );
#endif

  ret = wc_RsaPublicEncrypt( in, in_len, out, out_len, rsa, rng );

#ifndef WC_RSA_BLINDING
  wc_rng_free( rng );
#endif

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaPrivateDecrypt(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* in = info[0].As<Napi::Uint8Array>().Data();
  int in_len = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = info[2].As<Napi::Uint8Array>().Data();
  int out_len = info[3].As<Napi::Number>().Int32Value();
  RsaKey* rsa = (RsaKey*)( info[4].As<Napi::Uint8Array>().Data() );

  ret = wc_RsaPrivateDecrypt( in, in_len, out, out_len, rsa );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaSSL_Sign(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* in = info[0].As<Napi::Uint8Array>().Data();
  int in_len = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = info[2].As<Napi::Uint8Array>().Data();
  int out_len = info[3].As<Napi::Number>().Int32Value();
  RsaKey* rsa = (RsaKey*)( info[4].As<Napi::Uint8Array>().Data() );
#ifdef WC_RSA_BLINDING
  WC_RNG* rng = rsa->rng;
#else
  WC_RNG* rng = wc_rng_new( NULL, 0, NULL );
#endif

  ret = wc_RsaSSL_Sign( in, in_len, out, out_len, rsa, rng );

#ifndef WC_RSA_BLINDING
  wc_rng_free( rng );
#endif

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_RsaSSL_Verify(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* in = info[0].As<Napi::Uint8Array>().Data();
  int in_len = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = info[2].As<Napi::Uint8Array>().Data();
  int out_len = info[3].As<Napi::Number>().Int32Value();
  RsaKey* rsa = (RsaKey*)( info[4].As<Napi::Uint8Array>().Data() );

  ret = wc_RsaSSL_Verify( in, in_len, out, out_len, rsa );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_FreeRsaKey(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  RsaKey* rsa = (RsaKey*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_FreeRsaKey( rsa );

  return Napi::Number::New( env, ret );
}
