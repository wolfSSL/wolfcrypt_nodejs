/* evp.h
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
#ifndef WOLFSSL_USER_SETTINGS
#include "wolfssl/options.h"
#else
#include "../user_settings.h"
#endif
#include <wolfssl/wolfcrypt/types.h>
#include "wolfssl/ssl.h"
#include <wolfssl/openssl/evp.h>

Napi::Value bind_EVP_CIPHER_CTX_new(const Napi::CallbackInfo& info);
Napi::Number bind_EVP_CipherInit(const Napi::CallbackInfo& info);
Napi::Number bind_EVP_CipherUpdate(const Napi::CallbackInfo& info);
Napi::Number bind_EVP_CipherFinal(const Napi::CallbackInfo& info);
void bind_EVP_CIPHER_CTX_free(const Napi::CallbackInfo& info);
