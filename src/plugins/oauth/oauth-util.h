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

#ifndef SSO_OAUTHUTIL_H_
#define SSO_OAUTHUTIL_H_


typedef struct {
    char* param;
    char* value;
} OAuthParameter;


void emptyArray(GArray* array);
gchar* encodeParam(gchar* input);
gchar* decodeParam(gchar* input);
gchar* normalizeUrl(gchar* url); 
gchar* getQuery(gchar* url);
gchar* createSignature(GString* signatureBaseString,
            GString* secretKey); 
gchar* createSignatureBaseString(gchar* httpMethod, 
                                         gchar* url , 
                                         GArray* authorizationHeaderFields, 
                                         GArray* parameters );



#endif //SSO_OAUTHUTIL_H_
