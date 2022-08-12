/* pkcs7.cpp
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
#include "./h/pkcs7.h"

Napi::Number sizeof_PKCS7(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( PKCS7 ) );
}

Napi::Number typeof_Key_Sum(const Napi::CallbackInfo& info)
{
  int ret = -1;
  Napi::Env env = info.Env();
  std::string type = info[0].As<Napi::String>().Utf8Value();

  if ( strcmp( type.c_str(), "DSA" ) == 0 )
  {
    ret = DSAk;
  }
  else if ( strcmp( type.c_str(), "RSA" ) == 0 )
  {
    ret = RSAk;
  }
  else if ( strcmp( type.c_str(), "ECDSA" ) == 0 )
  {
    ret = ECDSAk;
  }
  else if ( strcmp( type.c_str(), "ED25519" ) == 0 )
  {
    ret = ED25519k;
  }
  else if ( strcmp( type.c_str(), "X25519" ) == 0 )
  {
    ret = X25519k;
  }
  else if ( strcmp( type.c_str(), "ED448" ) == 0 )
  {
    ret = ED448k;
  }
  else if ( strcmp( type.c_str(), "X448" ) == 0 )
  {
    ret = X448k;
  }
  else if ( strcmp( type.c_str(), "DH" ) == 0 )
  {
    ret = DHk;
  }

  return Napi::Number::New( env, ret );
}

Napi::Number typeof_Hash_Sum(const Napi::CallbackInfo& info)
{
  int ret = -1;
  Napi::Env env = info.Env();
  std::string type = info[0].As<Napi::String>().Utf8Value();

  if ( strcmp( type.c_str(), "MD2" ) == 0 )
  {
    ret = MD2h;
  }
  else if ( strcmp( type.c_str(), "MD5" ) == 0 )
  {
    ret = MD5h;
  }
  else if ( strcmp( type.c_str(), "SHA" ) == 0 )
  {
    ret = SHAh;
  }
  else if ( strcmp( type.c_str(), "SHA224" ) == 0 )
  {
    ret = SHA224h;
  }
  else if ( strcmp( type.c_str(), "SHA256" ) == 0 )
  {
    ret = SHA256h;
  }
  else if ( strcmp( type.c_str(), "SHA384" ) == 0 )
  {
    ret = SHA384h;
  }
  else if ( strcmp( type.c_str(), "SHA512" ) == 0 )
  {
    ret = SHA512h;
  }
  else if ( strcmp( type.c_str(), "SHA512_224" ) == 0 )
  {
    ret = SHA512_224h;
  }
  else if ( strcmp( type.c_str(), "SHA512_256" ) == 0 )
  {
    ret = SHA512_256h;
  }
  else if ( strcmp( type.c_str(), "SHA3_224" ) == 0 )
  {
    ret = SHA3_224h;
  }
  else if ( strcmp( type.c_str(), "SHA3_256" ) == 0 )
  {
    ret = SHA3_256h;
  }
  else if ( strcmp( type.c_str(), "SHA3_384" ) == 0 )
  {
    ret = SHA3_384h;
  }
  else if ( strcmp( type.c_str(), "SHA3_512" ) == 0 )
  {
    ret = SHA3_512h;
  }
  else if ( strcmp( type.c_str(), "SHAKE128" ) == 0 )
  {
    ret = SHAKE128h;
  }
  else if ( strcmp( type.c_str(), "SHAKE256" ) == 0 )
  {
    ret = SHAKE256h;
  }

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_PKCS7_Init(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );

  ret = wc_PKCS7_Init( pkcs7, NULL, INVALID_DEVID );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_PKCS7_InitWithCert(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* cert = info[1].As<Napi::Uint8Array>().Data();
  int cert_size = info[2].As<Napi::Number>().Int32Value();

  ret = wc_PKCS7_InitWithCert( pkcs7, cert, cert_size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_PKCS7_AddCertificate(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* cert = info[1].As<Napi::Uint8Array>().Data();
  int cert_size = info[2].As<Napi::Number>().Int32Value();

  ret = wc_PKCS7_AddCertificate( pkcs7, cert, cert_size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_PKCS7_EncodeData(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* data = info[1].As<Napi::Uint8Array>().Data();
  int data_size = info[2].As<Napi::Number>().Int32Value();
  uint8_t* key = info[3].As<Napi::Uint8Array>().Data();
  int key_size = info[4].As<Napi::Number>().Int32Value();
  uint8_t* output = info[5].As<Napi::Uint8Array>().Data();
  int output_size = info[6].As<Napi::Number>().Int32Value();

  pkcs7->content = data;
  pkcs7->contentSz = data_size;
  pkcs7->privateKey = key;
  pkcs7->privateKeySz = key_size;

  ret = wc_PKCS7_EncodeData( pkcs7, output, output_size );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_PKCS7_EncodeSignedData(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  WC_RNG rng;
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* data = info[1].As<Napi::Uint8Array>().Data();
  int data_size = info[2].As<Napi::Number>().Int32Value();
  uint8_t* key = info[3].As<Napi::Uint8Array>().Data();
  int key_size = info[4].As<Napi::Number>().Int32Value();
  int key_sum = info[5].As<Napi::Number>().Int32Value();
  int hash_sum = info[6].As<Napi::Number>().Int32Value();
  uint8_t* output = info[7].As<Napi::Uint8Array>().Data();
  int output_size = info[8].As<Napi::Number>().Int32Value();

  wc_InitRng( &rng );

  ret = wc_PKCS7_SetSignerIdentifierType( pkcs7, CMS_SKID );

  if ( ret != 0 )
  {
    return Napi::Number::New( env, ret );
  }

  pkcs7->content = data;
  pkcs7->contentSz = data_size;
  pkcs7->privateKey = key;
  pkcs7->privateKeySz = key_size;
  pkcs7->encryptOID = key_sum;
  pkcs7->publicKeyOID = key_sum;
  pkcs7->hashOID = hash_sum;
  pkcs7->rng = &rng;

  ret = wc_PKCS7_EncodeSignedData( pkcs7, output, output_size );

  wc_FreeRng( &rng );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_PKCS7_VerifySignedData(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* in = info[1].As<Napi::Uint8Array>().Data();
  int in_size = info[2].As<Napi::Number>().Int32Value();

  ret = wc_PKCS7_VerifySignedData( pkcs7, in, in_size );

  return Napi::Number::New( env, ret );
}

Napi::Number sizeof_wc_PKCS7_GetAttributeValue(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* oid = info[1].As<Napi::Uint8Array>().Data();
  unsigned int oid_size = info[2].As<Napi::Number>().Int32Value();
  unsigned int out_size;

  ret = wc_PKCS7_GetAttributeValue( pkcs7, oid, oid_size, NULL, &out_size );

  if ( ret != LENGTH_ONLY_E )
  {
    return Napi::Number::New( env, ret );
  }

  return Napi::Number::New( env, out_size );
}

Napi::Number bind_wc_PKCS7_GetAttributeValue(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* oid = info[1].As<Napi::Uint8Array>().Data();
  unsigned int oid_size = info[2].As<Napi::Number>().Int32Value();
  uint8_t* out = info[3].As<Napi::Uint8Array>().Data();
  unsigned int out_size = info[4].As<Napi::Number>().Int32Value();

  ret = wc_PKCS7_GetAttributeValue( pkcs7, oid, oid_size, out, &out_size );

  if ( ret < 0 )
  {
    return Napi::Number::New( env, ret );
  }

  return Napi::Number::New( env, out_size );
}

Napi::Number sizeof_wc_PKCS7_GetSignerSID(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  unsigned int out_size;

  ret = wc_PKCS7_GetSignerSID( pkcs7, NULL, &out_size );

  if ( ret != LENGTH_ONLY_E )
  {
    return Napi::Number::New( env, ret );
  }

  return Napi::Number::New( env, out_size );
}

Napi::Number bind_wc_PKCS7_GetSignerSID(const Napi::CallbackInfo& info)
{
  int ret;
  Napi::Env env = info.Env();
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = info[1].As<Napi::Uint8Array>().Data();
  unsigned int out_size = info[2].As<Napi::Number>().Int32Value();

  ret = wc_PKCS7_GetSignerSID( pkcs7, out, &out_size );

  if ( ret < 0 )
  {
    return Napi::Number::New( env, ret );
  }

  return Napi::Number::New( env, out_size );
}

void bind_wc_PKCS7_Free(const Napi::CallbackInfo& info)
{
  PKCS7* pkcs7 = (PKCS7*)( info[0].As<Napi::Uint8Array>().Data() );

  wc_PKCS7_Free( pkcs7 );
}
