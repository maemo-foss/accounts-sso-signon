/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * This file is part of signon
 *
 * Copyright (C) 2008 Nokia Corporation. All rights reserved.
 *
 * Contact: Alexander Akimov <ext-alexander.akimov@nokia.com>
 * Contact: Andrei Laperie <Andrei.Laperie@nokia.com>
 *
 * This software, including documentation, is protected by copyright controlled
 * by Nokia Corporation. All rights are reserved.
 * Copying, including reproducing, storing, adapting or translating, any or all
 * of this material requires the prior written consent of Nokia Corporation.
 * This material also contains confidential information which may not be
 * disclosed to others without the prior written consent of Nokia.
 */

#include <glib.h>
#include <string.h>
#include <openssl/hmac.h>

#include "oauth-util.h"

#define SSO_OAUTHSIGNATURE_TRACE


/**
 * A generic utility class for calculating OAuth signatures.
 *
 */

#define DEFAULT_ALGORITHM "HmacSHA1"

/**
 * Unreserved bytes by OAuth specification.
 */
#define ALPHA "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define DIGIT "0123456789"
#define UNRESERVED_BYTES ALPHA DIGIT "-._~"

/**
 * free all elements from array
 * @param array
 */
void emptyArray(GArray* array)
{
    uint i;
    if(array == NULL)
    {
        return;
    }

    for (i = 0; i < array->len; i++)
    {
        OAuthParameter* p;
        p=&g_array_index (array, OAuthParameter, i);
        if(p->param) {g_free(p->param);p->param=NULL;}
        if(p->value) {g_free(p->value);p->value=NULL;}
    }
    return;
}

/**
 * encode string
 *
 * @param input
 * @return encoded data
 */
gchar* encodeParam(gchar* input)
{
    if (input==NULL)
    {
        return NULL;
    }
    return g_uri_escape_string(input, UNRESERVED_BYTES, FALSE);
}

/**
 * decode string
 * @param input
 * @return decoded string
 */
gchar* decodeParam(gchar* input)
{
    if(input==NULL)
    {
        return NULL;
    }
    return g_uri_unescape_string(input, NULL);
}

/**
 * Normalize url
 * @param url
 * @return normalized url
 */
gchar* normalizeUrl(gchar* url)
{
    //TODO normalizeUrl
    SSOTRACE("not implemented\n");
    if(url==NULL)
    {
        SSOTRACE("NULL\n");
        return NULL;
    }
    /*
    char* urlString = url.getProtocol().toLowerCase() + "://"
                + url.getHost().toLowerCase();

        int port = url.getPort();
        if (port != -1) {
            if (port != url.getDefaultPort()) {
                urlString += ":" + port;
            }
        }

        urlString += url.getPath();
*/
    return g_strdup(url);
}

/**
 * get query part or url
 *
 * @param url
 * @return query part
 */
gchar* getQuery(gchar* url)
{
    //TODO make better implementation
    SSOTRACE("url: %s\n", url);
    if (url == NULL)
    {
        return NULL;
    }

    while( (url[0]!='?')&&(url[0]!='\0') )
    {
        url++;
    }
    if(url[0]=='?')
    {
        return g_strdup(url+1);
    }
    return NULL;
}

/**
 * Signs a string with a secret key.
 *
 * @param signatureBaseString
 *                the string to sign
 * @param secret
 *                the secret to sign the base string with
 * @return signed base string base64 encoded
 */
gchar* createSignature(GString* signatureBaseString,
            GString* secretKey)
{
    HMAC_CTX hmac;
    guint len;
    guchar hmac_value[1024];
    gchar* ret=NULL;

    SSOTRACE("%s\n", DEFAULT_ALGORITHM);

    g_return_val_if_fail (signatureBaseString != NULL, NULL);
    g_return_val_if_fail (secretKey != NULL, NULL);

    SSOTRACE("key: %s\n",secretKey->str);

    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, secretKey->str, secretKey->len, EVP_sha1(), NULL);

    HMAC_Update(&hmac, (guchar*)(signatureBaseString->str),
               signatureBaseString->len);

    HMAC_Final(&hmac, hmac_value, &len);
    HMAC_CTX_cleanup(&hmac);

    ret=g_base64_encode(hmac_value, len);

    return ret;
}

/**
 * compare OAuthParameter parameters first by name, then by value
 * @param a pointer
 * @param b pointer
 * @return comparison value
 */
gint paramCompare( gconstpointer a, gconstpointer b)
{
    int ret;
    g_return_val_if_fail( (a!=NULL) && (b!=NULL), 0);

    // by name
    ret=strcmp(((OAuthParameter*)a)->param, ((OAuthParameter*)b)->param);
    if( ret )
    {
        return ret;
    }
    // by value
    return strcmp(((OAuthParameter*)a)->value, ((OAuthParameter*)b)->value);
}

/**
 * Creates a NAuth signature base string.
 * This method assumes several things to improve speed:
 * 1) URL does not contain any query string, all request parameters are given in "parameters"
 * 2) OAuth header fields have already been parameter encoded.
 * 3) Query parameters have NOT been URLencoded or parameter encoded.
 *
 * @param httpMethod API verb
 * @param url full service URL including host but excluding all query parameters
 * @param authorizationHeaderFields OAuth header fields (except signature), must be parameter encoded!
 * @param parameters request parameters
 * @return return base string
 */

gchar* createSignatureBaseString(gchar* httpMethod,
                                        gchar* url ,
                                        GArray* authorizationHeaderFields,
                                        GArray* parameters )
{
    guint i;
    GArray*  requestParameters;
    OAuthParameter param;
    gchar* query=NULL;
    gchar* httpmethod=NULL;
    gchar* urlString=NULL;
    gchar* paramString=NULL;
    gchar* ret=NULL;
    gchar* urlString2=NULL;
    gchar* paramString2=NULL;



    g_return_val_if_fail(httpMethod != NULL, NULL);
    g_return_val_if_fail(url != NULL, NULL);

    if( (query=getQuery(url))!=NULL )
    {
        g_free(query);
        SSOTRACE("Query string in URL not supported\n");
        return NULL;
    }

    // 1. UPPER-CASE HTTP REQUEST METHOD
    httpmethod=g_ascii_strup(httpMethod,-1);

    // 2. NORMALIZED REQUEST URL
    urlString = normalizeUrl(url);

    // 3. ALPHABETICALLY SORTED REQUEST PARAMETERS
    requestParameters = g_array_new(FALSE, FALSE, sizeof (OAuthParameter));

    // parameter encode parameter names and values
    if (parameters!=NULL)
    {
        for (i = 0; i < parameters->len; i++)
        {
            OAuthParameter* p;
            p=&g_array_index(parameters, OAuthParameter, i);
            param.param=encodeParam(p->param);
            param.value=encodeParam(p->value);
            g_array_append_val(requestParameters, param);
        }
    }
    // Assuming authorization header fields are already pre-encoded
    if (authorizationHeaderFields!=NULL)
    {
        for (i = 0; i < authorizationHeaderFields->len; i++)
        {
            OAuthParameter* p;
            p=&g_array_index(authorizationHeaderFields, OAuthParameter, i);
            param.param=g_strdup(p->param);
            param.value=g_strdup(p->value);
            g_array_append_val(requestParameters, param);
        }
    }
    // sort parameters alphabetically by name (and value)
    g_array_sort(requestParameters, ((GCompareFunc)&paramCompare));

    // put all parameters in one string
    for (i = 0; i < requestParameters->len; i++)
    {
        OAuthParameter* p;
        p=&g_array_index(requestParameters, OAuthParameter, i);
        if (paramString==NULL)
        {
            paramString=g_strconcat(p->param, "=", p->value, NULL);
        }
        else
        {
            gchar* tmp=NULL;
            tmp=g_strconcat(paramString, "&", p->param, "=", p->value, NULL);
            g_free(paramString);
            paramString=tmp; tmp=NULL;
        }
    }

    // free array
    emptyArray(requestParameters);
    g_array_free(requestParameters, TRUE);

    // parameter-encode the 3 parts and separate them by '&'
    urlString2 = encodeParam(urlString);
    paramString2 = encodeParam(paramString);

    ret=g_strconcat(httpmethod, "&", urlString2, "&", paramString2, NULL);

    g_free(paramString2); paramString2=NULL;
    g_free(urlString2); urlString2=NULL;
    g_free(paramString); paramString=NULL;
    g_free(urlString); urlString=NULL;
    g_free(httpmethod); httpmethod=NULL;

    return ret;
}
