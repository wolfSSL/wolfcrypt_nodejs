/* main.cpp
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
#include <napi.h>
#include <stdio.h>
#include <cstring>
#include "./h/evp.h"
#include "./h/hmac.h"
#include "./h/rsa.h"
#include "./h/sha.h"
#include "./h/ecc.h"

using namespace Napi;

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
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
  exports.Set(Napi::String::New(env, "wc_RsaKeyToPublicDer"), Napi::Function::New(env, bind_wc_RsaKeyToPublicDer));
  exports.Set(Napi::String::New(env, "wc_RsaPrivateKeyDecode"), Napi::Function::New(env, bind_wc_RsaPrivateKeyDecode));
  exports.Set(Napi::String::New(env, "wc_RsaPublicKeyDecode"), Napi::Function::New(env, bind_wc_RsaPublicKeyDecode));
  exports.Set(Napi::String::New(env, "wc_RsaPublicEncrypt"), Napi::Function::New(env, bind_wc_RsaPublicEncrypt));
  exports.Set(Napi::String::New(env, "wc_RsaPrivateDecrypt"), Napi::Function::New(env, bind_wc_RsaPrivateDecrypt));
  exports.Set(Napi::String::New(env, "wc_RsaSSL_Sign"), Napi::Function::New(env, bind_wc_RsaSSL_Sign));
  exports.Set(Napi::String::New(env, "wc_RsaSSL_Verify"), Napi::Function::New(env, bind_wc_RsaSSL_Verify));
  exports.Set(Napi::String::New(env, "wc_FreeRsaKey"), Napi::Function::New(env, bind_wc_FreeRsaKey));

  exports.Set(Napi::String::New(env, "Sha_digest_length"), Napi::Function::New(env, Sha_digest_length));

  exports.Set(Napi::String::New(env, "sizeof_WOLFSSL_SHA_CTX"), Napi::Function::New(env, sizeof_WOLFSSL_SHA_CTX));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA_Init"), Napi::Function::New(env, bind_wolfSSL_SHA_Init));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA_Update"), Napi::Function::New(env, bind_wolfSSL_SHA_Update));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA_Final"), Napi::Function::New(env, bind_wolfSSL_SHA_Final));

  exports.Set(Napi::String::New(env, "sizeof_WOLFSSL_SHA224_CTX"), Napi::Function::New(env, sizeof_WOLFSSL_SHA224_CTX));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA224_Init"), Napi::Function::New(env, bind_wolfSSL_SHA224_Init));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA224_Update"), Napi::Function::New(env, bind_wolfSSL_SHA224_Update));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA224_Final"), Napi::Function::New(env, bind_wolfSSL_SHA224_Final));

  exports.Set(Napi::String::New(env, "sizeof_WOLFSSL_SHA256_CTX"), Napi::Function::New(env, sizeof_WOLFSSL_SHA256_CTX));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA256_Init"), Napi::Function::New(env, bind_wolfSSL_SHA256_Init));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA256_Update"), Napi::Function::New(env, bind_wolfSSL_SHA256_Update));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA256_Final"), Napi::Function::New(env, bind_wolfSSL_SHA256_Final));

  exports.Set(Napi::String::New(env, "sizeof_WOLFSSL_SHA384_CTX"), Napi::Function::New(env, sizeof_WOLFSSL_SHA384_CTX));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA384_Init"), Napi::Function::New(env, bind_wolfSSL_SHA384_Init));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA384_Update"), Napi::Function::New(env, bind_wolfSSL_SHA384_Update));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA384_Final"), Napi::Function::New(env, bind_wolfSSL_SHA384_Final));

  exports.Set(Napi::String::New(env, "sizeof_WOLFSSL_SHA512_CTX"), Napi::Function::New(env, sizeof_WOLFSSL_SHA512_CTX));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_Init"), Napi::Function::New(env, bind_wolfSSL_SHA512_Init));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_Update"), Napi::Function::New(env, bind_wolfSSL_SHA512_Update));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_Final"), Napi::Function::New(env, bind_wolfSSL_SHA512_Final));

  exports.Set(Napi::String::New(env, "sizeof_WOLFSSL_SHA512_224_CTX"), Napi::Function::New(env, sizeof_WOLFSSL_SHA512_224_CTX));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_224_Init"), Napi::Function::New(env, bind_wolfSSL_SHA512_224_Init));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_224_Update"), Napi::Function::New(env, bind_wolfSSL_SHA512_224_Update));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_224_Final"), Napi::Function::New(env, bind_wolfSSL_SHA512_224_Final));

  exports.Set(Napi::String::New(env, "sizeof_WOLFSSL_SHA512_256_CTX"), Napi::Function::New(env, sizeof_WOLFSSL_SHA512_256_CTX));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_256_Init"), Napi::Function::New(env, bind_wolfSSL_SHA512_256_Init));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_256_Update"), Napi::Function::New(env, bind_wolfSSL_SHA512_256_Update));
  exports.Set(Napi::String::New(env, "wolfSSL_SHA512_256_Final"), Napi::Function::New(env, bind_wolfSSL_SHA512_256_Final));

  exports.Set(Napi::String::New(env, "sizeof_ecc_key"), Napi::Function::New(env, sizeof_ecc_key));
  exports.Set(Napi::String::New(env, "sizeof_ecc_point"), Napi::Function::New(env, sizeof_ecc_point));
  exports.Set(Napi::String::New(env, "wc_ecc_init"), Napi::Function::New(env, bind_wc_ecc_init));
  exports.Set(Napi::String::New(env, "wc_ecc_make_key"), Napi::Function::New(env, bind_wc_ecc_make_key));
  exports.Set(Napi::String::New(env, "wc_ecc_export_x963"), Napi::Function::New(env, bind_wc_ecc_export_x963));
  exports.Set(Napi::String::New(env, "wc_ecc_import_x963"), Napi::Function::New(env, bind_wc_ecc_import_x963));
  exports.Set(Napi::String::New(env, "wc_ecc_set_curve"), Napi::Function::New(env, bind_wc_ecc_set_curve));
  exports.Set(Napi::String::New(env, "wc_ecc_shared_secret"), Napi::Function::New(env, bind_wc_ecc_shared_secret));
  exports.Set(Napi::String::New(env, "wc_ecc_sig_size"), Napi::Function::New(env, bind_wc_ecc_sig_size));
  exports.Set(Napi::String::New(env, "wc_ecc_sign_hash"), Napi::Function::New(env, bind_wc_ecc_sign_hash));
  exports.Set(Napi::String::New(env, "wc_ecc_verify_hash"), Napi::Function::New(env, bind_wc_ecc_verify_hash));
  exports.Set(Napi::String::New(env, "wc_ecc_free"), Napi::Function::New(env, bind_wc_ecc_free));

  return exports;
}

NODE_API_MODULE( addon, Init )
