/* sha.cpp
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
#include "./h/sha.h"

Napi::Number Sha_digest_length(const Napi::CallbackInfo& info)
{
  int length = -1;
  Napi::Env env = info.Env();
  std::string type = info[0].As<Napi::String>().Utf8Value();

  if ( strcmp( type.c_str(), "SHA" ) == 0 )
  {
    length = WC_SHA_DIGEST_SIZE;
  }
  else if ( strcmp( type.c_str(), "SHA224" ) == 0 )
  {
    length = WC_SHA224_DIGEST_SIZE;
  }
  else if ( strcmp( type.c_str(), "SHA256" ) == 0 )
  {
    length = WC_SHA256_DIGEST_SIZE;
  }
  else if ( strcmp( type.c_str(), "SHA384" ) == 0 )
  {
      length = WC_SHA384_DIGEST_SIZE;
  }
  else if ( strcmp( type.c_str(), "SHA512" ) == 0 )
  {
    length = WC_SHA512_DIGEST_SIZE;
  }
  else if ( strcmp( type.c_str(), "SHA512_224" ) == 0 )
  {
    length = WC_SHA512_224_DIGEST_SIZE;
  }
  else if ( strcmp( type.c_str(), "SHA512_256" ) == 0 )
  {
    length = WC_SHA512_256_DIGEST_SIZE;
  }

  return Napi::Number::New( env, length );
}

Napi::Number sizeof_WOLFSSL_SHA_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( WOLFSSL_SHA_CTX ) );
}

Napi::Number bind_wolfSSL_SHA_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA_CTX* sha = (WOLFSSL_SHA_CTX*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA_Init( sha );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA_Update(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA_CTX* sha = (WOLFSSL_SHA_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* input = info[1].As<Napi::Uint8Array>().Data();
  unsigned long size = info[2].As<Napi::Number>().Int64Value();

  ret = wolfSSL_SHA_Update( sha, input, size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA_Final(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* output = info[0].As<Napi::Uint8Array>().Data();
  WOLFSSL_SHA_CTX* sha = (WOLFSSL_SHA_CTX*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA_Final( output, sha );

  return Napi::Number::New( env, ret );
}

Napi::Number sizeof_WOLFSSL_SHA224_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( WOLFSSL_SHA224_CTX ) );
}

Napi::Number bind_wolfSSL_SHA224_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA224_CTX* sha = (WOLFSSL_SHA224_CTX*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA224_Init( sha );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA224_Update(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA224_CTX* sha = (WOLFSSL_SHA224_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* input = info[1].As<Napi::Uint8Array>().Data();
  unsigned long size = info[2].As<Napi::Number>().Int64Value();

  ret = wolfSSL_SHA224_Update( sha, input, size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA224_Final(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* output = info[0].As<Napi::Uint8Array>().Data();
  WOLFSSL_SHA224_CTX* sha = (WOLFSSL_SHA224_CTX*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA224_Final( output, sha );

  return Napi::Number::New( env, ret );
}

Napi::Number sizeof_WOLFSSL_SHA256_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( WOLFSSL_SHA256_CTX ) );
}

Napi::Number bind_wolfSSL_SHA256_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA256_CTX* sha = (WOLFSSL_SHA256_CTX*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA256_Init( sha );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA256_Update(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA256_CTX* sha = (WOLFSSL_SHA256_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* input = info[1].As<Napi::Uint8Array>().Data();
  unsigned long size = info[2].As<Napi::Number>().Int64Value();

  ret = wolfSSL_SHA256_Update( sha, input, size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA256_Final(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* output = info[0].As<Napi::Uint8Array>().Data();
  WOLFSSL_SHA256_CTX* sha = (WOLFSSL_SHA256_CTX*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA256_Final( output, sha );

  return Napi::Number::New( env, ret );
}

Napi::Number sizeof_WOLFSSL_SHA384_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( WOLFSSL_SHA384_CTX ) );
}

Napi::Number bind_wolfSSL_SHA384_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA384_CTX* sha = (WOLFSSL_SHA384_CTX*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA384_Init( sha );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA384_Update(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA384_CTX* sha = (WOLFSSL_SHA384_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* input = info[1].As<Napi::Uint8Array>().Data();
  unsigned long size = info[2].As<Napi::Number>().Int64Value();

  ret = wolfSSL_SHA384_Update( sha, input, size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA384_Final(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* output = info[0].As<Napi::Uint8Array>().Data();
  WOLFSSL_SHA384_CTX* sha = (WOLFSSL_SHA384_CTX*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA384_Final( output, sha );

  return Napi::Number::New( env, ret );
}

Napi::Number sizeof_WOLFSSL_SHA512_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( WOLFSSL_SHA512_CTX ) );
}

Napi::Number bind_wolfSSL_SHA512_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA512_CTX* sha = (WOLFSSL_SHA512_CTX*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA512_Init( sha );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA512_Update(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA512_CTX* sha = (WOLFSSL_SHA512_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* input = info[1].As<Napi::Uint8Array>().Data();
  unsigned long size = info[2].As<Napi::Number>().Int64Value();

  ret = wolfSSL_SHA512_Update( sha, input, size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA512_Final(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* output = info[0].As<Napi::Uint8Array>().Data();
  WOLFSSL_SHA512_CTX* sha = (WOLFSSL_SHA512_CTX*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA512_Final( output, sha );

  return Napi::Number::New( env, ret );
}

Napi::Number sizeof_WOLFSSL_SHA512_224_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( WOLFSSL_SHA512_224_CTX ) );
}

Napi::Number bind_wolfSSL_SHA512_224_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA512_224_CTX* sha = (WOLFSSL_SHA512_224_CTX*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA512_224_Init( sha );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA512_224_Update(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA512_224_CTX* sha = (WOLFSSL_SHA512_224_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* input = info[1].As<Napi::Uint8Array>().Data();
  unsigned long size = info[2].As<Napi::Number>().Int64Value();

  ret = wolfSSL_SHA512_224_Update( sha, input, size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA512_224_Final(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* output = info[0].As<Napi::Uint8Array>().Data();
  WOLFSSL_SHA512_224_CTX* sha = (WOLFSSL_SHA512_224_CTX*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA512_224_Final( output, sha );

  return Napi::Number::New( env, ret );
}

Napi::Number sizeof_WOLFSSL_SHA512_256_CTX(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( WOLFSSL_SHA512_256_CTX ) );
}

Napi::Number bind_wolfSSL_SHA512_256_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA512_256_CTX* sha = (WOLFSSL_SHA512_256_CTX*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA512_256_Init( sha );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA512_256_Update(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WOLFSSL_SHA512_256_CTX* sha = (WOLFSSL_SHA512_256_CTX*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* input = info[1].As<Napi::Uint8Array>().Data();
  unsigned long size = info[2].As<Napi::Number>().Int64Value();

  ret = wolfSSL_SHA512_256_Update( sha, input, size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wolfSSL_SHA512_256_Final(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  uint8_t* output = info[0].As<Napi::Uint8Array>().Data();
  WOLFSSL_SHA512_256_CTX* sha = (WOLFSSL_SHA512_256_CTX*)( info[1].As<Napi::Uint8Array>().Data() );

  ret = wolfSSL_SHA512_256_Final( output, sha );

  return Napi::Number::New( env, ret );
}
