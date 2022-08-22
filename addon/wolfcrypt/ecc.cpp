/* ecc.cpp
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
#include "./h/ecc.h"

Napi::Number sizeof_ecc_key(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( ecc_key ) );
}

Napi::Number sizeof_ecc_point(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( ecc_point ) );
}

Napi::Number bind_wc_ecc_size(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_ecc_size( ecc );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_ecc_init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_ecc_init( ecc );

  ecc->rng = wc_rng_new( NULL, 0, NULL );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_ecc_make_key(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  int key_size = info[0].As<Napi::Number>().Int32Value();
  ecc_key* ecc = (ecc_key*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wc_ecc_make_key( ecc->rng, key_size, ecc );

  return Napi::Number::New( env, ret );
}

class wc_ecc_make_keyAsyncWorker : public Napi::AsyncWorker
{
  public:
    wc_ecc_make_keyAsyncWorker( Napi::Function& callback, ecc_key* ecc, int key_size )
      : Napi::AsyncWorker( callback ), ecc( ecc ), key_size( key_size )
    {
    }

    ~wc_ecc_make_keyAsyncWorker() {}

    void Execute() override
    {
      ret = wc_ecc_make_key( ecc->rng, key_size, ecc );
    }

    void OnOK() override
    {
      Napi::HandleScope scope(Env());
      Callback().Call({Env().Undefined(), Napi::Number::New(Env(), ret)});
    }
  private:
    ecc_key* ecc;
    int key_size;
    int ret;
};

// uses the above async worker to make the key, callback will be called
// when the key has completed
Napi::Value wc_ecc_make_key_async(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int key_size = info[0].As<Napi::Number>().Int32Value();
  ecc_key* ecc = (ecc_key*)( info[1].As<Napi::Uint8Array>().Data() );
  Napi::Function callback = info[2].As<Napi::Function>();

  wc_ecc_make_keyAsyncWorker* key_worker = new wc_ecc_make_keyAsyncWorker( callback, ecc, key_size );
  key_worker->Queue();

  return env.Undefined();
}

Napi::Number sizeof_ecc_x963(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );
  unsigned int out_len;

  wc_ecc_export_x963( ecc, NULL, &out_len );

  return Napi::Number::New( env, out_len );
}

Napi::Number bind_wc_ecc_export_x963(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = (uint8_t*)( info[1].As<Napi::Uint8Array>().Data() );
  unsigned int out_len = info[2].As<Napi::Number>().Int32Value();

  ret = wc_ecc_export_x963( ecc, out, &out_len );

  if ( ret < 0 )
  {
    out_len = ret;
  }

  return Napi::Number::New( env, (int)out_len );
}

Napi::Number bind_wc_ecc_import_x963(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  uint8_t* in = (uint8_t*)( info[0].As<Napi::Uint8Array>().Data() );
  unsigned int in_len = info[1].As<Napi::Number>().Int32Value();
  ecc_key* ecc = (ecc_key*)( info[2].As<Napi::Uint8Array>().Data() );

  ret = wc_ecc_import_x963( in, in_len, ecc );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_EccKeyDerSize(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );
  int pub = info[1].As<Napi::Number>().Int32Value();

  ret = wc_EccKeyDerSize( ecc, pub );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_EccPublicKeyDerSize(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_EccPublicKeyDerSize( ecc, 1 );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_EccPublicKeyToDer(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = (uint8_t*)( info[1].As<Napi::Uint8Array>().Data() );
  unsigned int out_len = info[2].As<Napi::Number>().Int32Value();

  /* 1=export with ASN.1/DER header (which includes curve info) */
  ret = wc_EccPublicKeyToDer( ecc, out, out_len, 1 );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_EccPublicKeyDecode(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  uint8_t* in = (uint8_t*)( info[0].As<Napi::Uint8Array>().Data() );
  ecc_key* ecc = (ecc_key*)( info[1].As<Napi::Uint8Array>().Data() );
  unsigned int in_len = info[2].As<Napi::Number>().Int32Value();
  unsigned int idx = 0;

  ret = wc_EccPublicKeyDecode( in, &idx, ecc, in_len );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_EccPrivateKeyToDer(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = (uint8_t*)( info[1].As<Napi::Uint8Array>().Data() );
  unsigned int out_len = info[2].As<Napi::Number>().Int32Value();

  ret = wc_EccPrivateKeyToDer( ecc, out, out_len );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_EccPrivateKeyDecode(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  uint8_t* in = (uint8_t*)( info[0].As<Napi::Uint8Array>().Data() );
  ecc_key* ecc = (ecc_key*)( info[1].As<Napi::Uint8Array>().Data() );
  unsigned int in_len = info[2].As<Napi::Number>().Int32Value();
  unsigned int idx = 0;

  ret = wc_EccPrivateKeyDecode( in, &idx, ecc, in_len );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_ecc_set_curve(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );
  int key_size = info[1].As<Napi::Number>().Int32Value();
  int curve_id = info[2].As<Napi::Number>().Int32Value();

  ret = wc_ecc_set_curve( ecc, key_size, curve_id );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_ecc_shared_secret(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* private_key = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );
  ecc_key* public_key = (ecc_key*)( info[1].As<Napi::Uint8Array>().Data() );
  uint8_t* out = info[2].As<Napi::Uint8Array>().Data();
  unsigned int out_len = info[3].As<Napi::Number>().Uint32Value();

  ret = wc_ecc_shared_secret( private_key, public_key, out, &out_len );

  if ( ret < 0 )
  {
    out_len = ret;
  }

  return Napi::Number::New( env, (int)out_len );
}

Napi::Number bind_wc_ecc_sig_size(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_ecc_sig_size( ecc );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_ecc_sign_hash(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  uint8_t* in = (uint8_t*)( info[0].As<Napi::Uint8Array>().Data() );
  int in_len = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = (uint8_t*)( info[2].As<Napi::Uint8Array>().Data() );
  unsigned int out_len = info[3].As<Napi::Number>().Int32Value();
  ecc_key* ecc = (ecc_key*)( info[4].As<Napi::Uint8Array>().Data() );

  ret = wc_ecc_sign_hash( in, in_len, out, &out_len, ecc->rng, ecc );

  if ( ret < 0 )
  {
    out_len = ret;
  }

  return Napi::Number::New( env, (int)out_len );
}

Napi::Number bind_wc_ecc_verify_hash(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  uint8_t* sig = (uint8_t*)( info[0].As<Napi::Uint8Array>().Data() );
  int sig_len = info[1].As<Napi::Number>().Int32Value();
  uint8_t* hash = (uint8_t*)( info[2].As<Napi::Uint8Array>().Data() );
  int hash_len = info[3].As<Napi::Number>().Int32Value();
  ecc_key* ecc = (ecc_key*)( info[4].As<Napi::Uint8Array>().Data() );
  int res;

  ret = wc_ecc_verify_hash( sig, sig_len, hash, hash_len, &res, ecc );
  if ( ret < 0 )
  {
    res = ret;
  }

  return Napi::Number::New( env, res );
}

Napi::Number bind_wc_ecc_free(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  ecc_key* ecc = (ecc_key*)( info[0].As<Napi::Uint8Array>().Data() );

  if ( ecc->rng != NULL )
  {
    wc_rng_free( ecc->rng );
  }

  ret = wc_ecc_free( ecc );

  return Napi::Number::New( env, ret );
}
