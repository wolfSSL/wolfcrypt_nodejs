/* pkcs12.cpp
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
#include "./h/pkcs12.h"

Napi::Value bind_wc_PKCS12_new(const Napi::CallbackInfo& info)
{
  Napi::Env env = info.Env();
  WC_PKCS12* pkcs12 = wc_PKCS12_new();
  Napi::External<WC_PKCS12> pkcs12_ext = Napi::External<WC_PKCS12>::New(env,
      pkcs12);

  return pkcs12_ext;
}

Napi::Value nodejsPKCS12Create(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    uint8_t* pass = info[0].As<Napi::Uint8Array>().Data();
    int passSz = info[1].As<Napi::Number>().Int32Value();
    uint8_t* key = info[2].As<Napi::Uint8Array>().Data();
    int keySz = info[3].As<Napi::Number>().Int32Value();
    uint8_t* cert = info[4].As<Napi::Uint8Array>().Data();
    int certSz = info[5].As<Napi::Number>().Int32Value();
    Napi::Array derList = info[6].As<Napi::Array>();
    int nidKey = info[7].As<Napi::Number>().Int32Value();
    int nidMac = info[8].As<Napi::Number>().Int32Value();
    int iter = info[9].As<Napi::Number>().Int32Value();
    int macIter = info[10].As<Napi::Number>().Int32Value();
    int i;
    WC_PKCS12* pkcs12 = NULL;
    Napi::External<WC_PKCS12> pkcs12_ext;
    WC_DerCertList* root = NULL;
    WC_DerCertList* cur = NULL;

    if (derList.Length() > 0) {
        root = (WC_DerCertList*)XMALLOC(sizeof(WC_DerCertList), NULL,
            DYNAMIC_TYPE_PKCS);
        XMEMSET(root, 0, sizeof(WC_DerCertList));
        cur = root;
    }

    for (i = 0; i < (int)derList.Length(); i++) {
        Napi::Value v = derList[i];

        if (v.IsBuffer()) {
            cur->bufferSz = (word32)v.As<Napi::Buffer<uint8_t>>().Length();
            cur->buffer = (byte*)XMALLOC(cur->bufferSz, NULL,
                DYNAMIC_TYPE_PKCS);
            XMEMCPY(cur->buffer, v.As<Napi::Uint8Array>().Data(),
                cur->bufferSz);
        }

        if (i < (int)derList.Length() - 1) {
            cur->next = (WC_DerCertList*)XMALLOC(sizeof(WC_DerCertList), NULL,
                DYNAMIC_TYPE_PKCS);
            cur = cur->next;
            XMEMSET(cur, 0, sizeof(WC_DerCertList));
        }
    }

    pkcs12 = wc_PKCS12_create((char*)pass, passSz, (char*)"friendlyName", key,
        keySz, cert, certSz, root, nidKey, nidMac, iter, macIter, 0, NULL);

    if (root != NULL) {
        wc_FreeCertList(root, NULL);
    }

    if (pkcs12 != NULL) {
        pkcs12_ext = Napi::External<WC_PKCS12>::New(env, pkcs12);
    }

    return pkcs12_ext;
}

Napi::Object nodejsPKCS12Parse(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    WC_PKCS12* pkcs12 = info[0].As<Napi::External<WC_PKCS12>>().Data();
    uint8_t* pass = info[1].As<Napi::Uint8Array>().Data();
    Napi::Array derList = info[2].As<Napi::Array>();
    Napi::Object out = Napi::Object::New(env);
    Napi::Buffer<uint8_t> key;
    Napi::Buffer<uint8_t> cert;
    int ret;
    int i = 0;
    byte* tmpKey = NULL;
    word32 tmpKeySz;
    byte* tmpCert = NULL;
    word32 tmpCertSz;
    WC_DerCertList* tmpDerList;
    WC_DerCertList* cur;

    ret = wc_PKCS12_parse(pkcs12, (const char*)pass, &tmpKey, &tmpKeySz,
        &tmpCert, &tmpCertSz, &tmpDerList);

    if (ret == 0) {
        key = Napi::Buffer<uint8_t>::Copy(env, tmpKey, tmpKeySz);
        XFREE(tmpKey, NULL, DYNAMIC_TYPE_PUBLIC_KEY);

        cert = Napi::Buffer<uint8_t>::Copy(env, tmpCert, tmpCertSz);
        XFREE(tmpCert, NULL, DYNAMIC_TYPE_PKCS);

        cur = tmpDerList;

        while (cur != NULL) {
            derList[i] = Napi::Buffer<uint8_t>::Copy(env, cur->buffer,
                cur->bufferSz);
            cur = cur->next;
        }

        if (tmpDerList != NULL) {
            wc_FreeCertList(tmpDerList, NULL);
        }

        out.Set("key", key);
        out.Set("cert", cert);
    }

    return out;
}

Napi::Number bind_wc_d2i_PKCS12(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    int ret;
    uint8_t* der = info[0].As<Napi::Uint8Array>().Data();
    int derSz = info[1].As<Napi::Number>().Int32Value();
    WC_PKCS12* pkcs12 = info[2].As<Napi::External<WC_PKCS12>>().Data();

    ret = wc_d2i_PKCS12((const byte*)der, derSz, pkcs12);

    return Napi::Number::New(env, ret);
}

Napi::Buffer<uint8_t> nodejsPKCS12InternalToDer(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();
    WC_PKCS12* pkcs12 = info[0].As<Napi::External<WC_PKCS12>>().Data();
    int ret;
    Napi::Buffer<uint8_t> der;
    byte* tmpDer = NULL;
    int tmpDerSz = 0;

    ret = wc_i2d_PKCS12(pkcs12, &tmpDer, &tmpDerSz);

    if (ret > 0) {
        der = Napi::Buffer<uint8_t>::Copy(env, tmpDer, ret);
        XFREE(tmpDer, NULL, DYNAMIC_TYPE_PKCS);
    }

    return der;
}

void bind_wc_PKCS12_free(const Napi::CallbackInfo& info)
{
    WC_PKCS12* pkcs12 = info[0].As<Napi::External<WC_PKCS12>>().Data();

    wc_PKCS12_free(pkcs12);
}
