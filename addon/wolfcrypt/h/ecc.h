/* ecc.h
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
#include <wolfssl/wolfcrypt/ecc.h>

Napi::Number sizeof_ecc_key(const Napi::CallbackInfo& info);
Napi::Number sizeof_ecc_point(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_init(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_make_key(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_export_x963(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_import_x963(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_set_curve(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_shared_secret(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_sig_size(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_sign_hash(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_verify_hash(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_encrypt(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_decrypt(const Napi::CallbackInfo& info);
Napi::Number bind_wc_ecc_free(const Napi::CallbackInfo& info);
