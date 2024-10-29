/* pkcs12.h
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
#ifndef WOLFSSL_USER_SETTINGS
#include "wolfssl/options.h"
#else
#include "../user_settings.h"
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/pkcs12.h>

Napi::Value bind_wc_PKCS12_new(const Napi::CallbackInfo& info);
Napi::Value nodejsPKCS12Create(const Napi::CallbackInfo& info);
Napi::Object nodejsPKCS12Parse(const Napi::CallbackInfo& info);
Napi::Number bind_wc_d2i_PKCS12(const Napi::CallbackInfo& info);
Napi::Buffer<uint8_t> nodejsPKCS12InternalToDer(const Napi::CallbackInfo& info);
void bind_wc_PKCS12_free(const Napi::CallbackInfo& info);
