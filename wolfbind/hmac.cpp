#include "./h/hmac.h"

Napi::Number sizeof_Hmac(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New( env, sizeof( Hmac ) );
}

Napi::Number typeof_Hmac(const Napi::CallbackInfo& info)
{
  int ret = -1;
  Napi::Env env = info.Env();
  std::string type = info[0].As<Napi::String>().Utf8Value();

  if ( strcmp( type.c_str(), "MD5" ) == 0 )
  {
    ret = WC_MD5;
  }
  else if ( strcmp( type.c_str(), "SHA" ) == 0 )
  {
    ret = WC_SHA;
  }
  else if ( strcmp( type.c_str(), "SHA256" ) == 0 )
  {
    ret = WC_SHA256;
  }
  else if ( strcmp( type.c_str(), "SHA512" ) == 0 )
  {
    ret = WC_SHA512;
  }
  else if ( strcmp( type.c_str(), "SHA512_224" ) == 0 )
  {
    ret = WC_SHA512_224;
  }
  else if ( strcmp( type.c_str(), "SHA512_256" ) == 0 )
  {
    ret = WC_SHA512_256;
  }
  else if ( strcmp( type.c_str(), "SHA384" ) == 0 )
  {
    ret = WC_SHA384;
  }
  else if ( strcmp( type.c_str(), "SHA224" ) == 0 )
  {
    ret = WC_SHA224;
  }
  else if ( strcmp( type.c_str(), "SHA3_224" ) == 0 )
  {
    ret = WC_SHA3_224;
  }
  else if ( strcmp( type.c_str(), "SHA3_256" ) == 0 )
  {
    ret = WC_SHA3_256;
  }
  else if ( strcmp( type.c_str(), "SHA3_384" ) == 0 )
  {
    ret = WC_SHA3_384;
  }
  else if ( strcmp( type.c_str(), "SHA3_512" ) == 0 )
  {
    ret = WC_SHA3_512;
  }

  return Napi::Number::New( env, ret );
}

Napi::Number Hmac_digest_length(const Napi::CallbackInfo& info)
{
  int length;
  Napi::Env env = info.Env();
  int type = info[0].As<Napi::Number>().Int32Value();

  switch ( type )
  {
    case WC_MD5:
      length = WC_MD5_DIGEST_SIZE;

      break;
    case WC_SHA:
      length = WC_SHA_DIGEST_SIZE;

      break;
    case WC_SHA256:
      length = WC_SHA256_DIGEST_SIZE;

      break;
    case WC_SHA512:
      length = WC_SHA512_DIGEST_SIZE;

      break;
    case WC_SHA512_224:
      length = WC_SHA512_224_DIGEST_SIZE;

      break;
    case WC_SHA512_256:
      length = WC_SHA512_256_DIGEST_SIZE;

      break;
    case WC_SHA384:
      length = WC_SHA384_DIGEST_SIZE;

      break;
    case WC_SHA224:
      length = WC_SHA224_DIGEST_SIZE;

      break;
    case WC_SHA3_224:
      length = WC_SHA3_224_DIGEST_SIZE;

      break;
    case WC_SHA3_256:
      length = WC_SHA3_256_DIGEST_SIZE;

      break;
    case WC_SHA3_384:
      length = WC_SHA3_384_DIGEST_SIZE;

      break;
    case WC_SHA3_512:
      length = WC_SHA3_512_DIGEST_SIZE;

      break;
    default:
      length = -1;

      break;
  }

  return Napi::Number::New( env, length );
}

Napi::Number bind_wc_HmacSetKey(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );
  int type = info[1].As<Napi::Number>().Int32Value();
  uint8_t* key = info[2].As<Napi::Uint8Array>().Data();
  uint32_t keySz = info[3].As<Napi::Number>().Uint32Value();

  ret = wc_HmacSetKey( hmac, type, key, keySz );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_HmacUpdate(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* in = info[1].As<Napi::Uint8Array>().Data();
  int inSz = info[2].As<Napi::Number>().Int32Value();

  ret = wc_HmacUpdate( hmac, in, inSz );

  return Napi::Number::New( env, ret );
}

Napi::Number bind_wc_HmacFinal(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );
  uint8_t* out = info[1].As<Napi::Uint8Array>().Data();

  ret = wc_HmacFinal( hmac, out );

  return Napi::Number::New( env, ret );
}

void bind_wc_HmacFree(const Napi::CallbackInfo& info)
{
  Hmac* hmac = (Hmac*)( info[0].As<Napi::Uint8Array>().Data() );

  wc_HmacFree( hmac );
}
