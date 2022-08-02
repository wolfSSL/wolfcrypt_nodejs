/* rsa.h
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
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>

Napi::Number sizeof_RsaKey(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaEncryptSize(const Napi::CallbackInfo& info);
Napi::Number bind_wc_InitRsaKey(const Napi::CallbackInfo& info);
Napi::Number bind_wc_MakeRsaKey(const Napi::CallbackInfo& info);
Napi::Number RsaPrivateDerSize(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaKeyToDer(const Napi::CallbackInfo& info);
Napi::Number RsaPublicDerSize(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaKeyToPublicDer(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPrivateKeyDecode(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPublicKeyDecode(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPublicEncrypt(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaPrivateDecrypt(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaSSL_Sign(const Napi::CallbackInfo& info);
Napi::Number bind_wc_RsaSSL_Verify(const Napi::CallbackInfo& info);
Napi::Number bind_wc_FreeRsaKey(const Napi::CallbackInfo& info);
