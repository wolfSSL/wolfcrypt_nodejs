/* hmac.h
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
#include "wolfssl/options.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/pkcs7.h>

Napi::Number sizeof_PKCS7(const Napi::CallbackInfo& info);
Napi::Number typeof_Key_Sum(const Napi::CallbackInfo& info);
Napi::Number typeof_Hash_Sum(const Napi::CallbackInfo& info);
Napi::Number bind_wc_PKCS7_Init(const Napi::CallbackInfo& info);
Napi::Number bind_wc_PKCS7_InitWithCert(const Napi::CallbackInfo& info);
Napi::Number bind_wc_PKCS7_AddCertificate(const Napi::CallbackInfo& info);
Napi::Number bind_wc_PKCS7_EncodeData(const Napi::CallbackInfo& info);
Napi::Number bind_wc_PKCS7_EncodeSignedData(const Napi::CallbackInfo& info);
Napi::Number bind_wc_PKCS7_VerifySignedData(const Napi::CallbackInfo& info);
void bind_wc_PKCS7_Free(const Napi::CallbackInfo& info);
