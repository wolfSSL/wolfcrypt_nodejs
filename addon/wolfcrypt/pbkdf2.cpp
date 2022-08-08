/* pbkdf2.cpp
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
#include "./h/pbkdf2.h"

Napi::Number bind_wc_PBKDF2(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  uint8_t* out = info[0].As<Napi::Uint8Array>().Data();
  uint8_t* passwd = info[1].As<Napi::Uint8Array>().Data();
  int p_len = info[2].As<Napi::Number>().Int32Value();
  uint8_t* salt = info[3].As<Napi::Uint8Array>().Data();
  int s_len = info[4].As<Napi::Number>().Int32Value();
  int iterations = info[5].As<Napi::Number>().Int32Value();
  int k_len = info[6].As<Napi::Number>().Int32Value();
  int type_h = info[7].As<Napi::Number>().Int32Value();

  ret = wc_PBKDF2( out, passwd, p_len, salt, s_len, iterations, k_len, type_h );

  return Napi::Number::New( env, ret );
}
