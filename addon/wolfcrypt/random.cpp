/* random.cpp
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
#include "./h/random.h"

Napi::Number sizeof_WC_RNG(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();

  return Napi::Number::New(env, sizeof(WC_RNG));
}

Napi::Number bind_wc_InitRng(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  WC_RNG* rng = (WC_RNG*)(info[0].As<Napi::Uint8Array>().Data());

  ret = wc_InitRng(rng);

  return Napi::Number::New(env, ret);
}

Napi::Number bind_wc_RNG_GenerateBlock(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  WC_RNG* rng = (WC_RNG*)(info[0].As<Napi::Uint8Array>().Data());
  uint8_t* out = (uint8_t*)(info[1].As<Napi::Uint8Array>().Data());
  word32 outLen = (word32)(info[2].As<Napi::Number>().Int32Value());

  ret = wc_RNG_GenerateBlock(rng, out, outLen);

  return Napi::Number::New(env, ret);
}

Napi::Number bind_wc_FreeRng(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  int ret;
  WC_RNG* rng = (WC_RNG*)(info[0].As<Napi::Uint8Array>().Data());

  ret = wc_FreeRng(rng);

  return Napi::Number::New(env, ret);
}
