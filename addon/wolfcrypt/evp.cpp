/* evp.cpp
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
#include "./h/evp.h"

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
