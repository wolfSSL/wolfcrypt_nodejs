/* hmac.h
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
#include <napi.h>
#ifndef WOLFSSL_USER_SETTINGS
#include "wolfssl/options.h"
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hmac.h>

Napi::Number sizeof_Hmac(const Napi::CallbackInfo& info);
Napi::Number typeof_Hmac(const Napi::CallbackInfo& info);
Napi::Number Hmac_digest_length(const Napi::CallbackInfo& info);
Napi::Number bind_wc_HmacSetKey(const Napi::CallbackInfo& info);
Napi::Number bind_wc_HmacUpdate(const Napi::CallbackInfo& info);
Napi::Number bind_wc_HmacFinal(const Napi::CallbackInfo& info);
void bind_wc_HmacFree(const Napi::CallbackInfo& info);
