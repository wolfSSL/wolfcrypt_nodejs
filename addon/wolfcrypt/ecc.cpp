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

  ecc->rng = NULL;
  ret = wc_ecc_init( ecc );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_ecc_make_key(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  int key_size = info[0].As<Napi::Number>().Int32Value();
  ecc_key* ecc = (ecc_key*)( info[1].As<Napi::Uint8Array>().Data() );

  ecc->rng = wc_rng_new( NULL, 0, NULL );

  ret = wc_ecc_make_key( ecc->rng, key_size, ecc );

  return Napi::Number::New( env, ret );
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
  WC_RNG rng;
  uint8_t* in = (uint8_t*)( info[0].As<Napi::Uint8Array>().Data() );
  int in_len = info[1].As<Napi::Number>().Int32Value();
  uint8_t* out = (uint8_t*)( info[2].As<Napi::Uint8Array>().Data() );
  unsigned int out_len = info[3].As<Napi::Number>().Int32Value();
  ecc_key* ecc = (ecc_key*)( info[4].As<Napi::Uint8Array>().Data() );

  wc_InitRng( &rng );

  ret = wc_ecc_sign_hash( in, in_len, out, &out_len, &rng, ecc );

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
