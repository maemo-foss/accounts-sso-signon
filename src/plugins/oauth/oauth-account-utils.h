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

#ifndef SSOOAUTHACCOUNT_UTILS_H_
#define SSOOAUTHACCOUNT_UTILS_H_

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>
#include <glib-object.h>

#define REST_PATH "/rest/1.0"

//use gconf for proxy resolution
#define SSO_USE_GCONF

// HTTP GET verb
#define REST_VERB_GET    "GET"
// HTTP POST verb
#define REST_VERB_POST   "POST"
// HTTP PUT verb
#define REST_VERB_PUT    "PUT"
// HTTP DELETE verb
#define REST_VERB_DELETE "DELETE"

G_BEGIN_DECLS

        typedef enum
{
    SSO_ERROR_COMMUNICATION                            = 10,
    SSO_ERROR_NO_CONNECTION                            = 5,
    SSO_ERROR_OPERATION_FAILED                         = 4,
    SSO_ERROR_NOT_AUTHORIZED                           = 3,
    SSO_ERROR_INVALID_USERNAME                         = 2,
    SSO_ERROR_OPERATION_CANCELLED                      = 1,
    SSO_ERROR_NONE                                     = 0,
    SSO_ERROR_GENERAL                                  = -1,
    SSO_ERROR_INVALID_REQUEST_ID                       = -2,
    SSO_ERROR_INVALID_SERVICE_ID                       = -3,
    SSO_ERROR_INVALID_SERVICE_TYPE                     = -4,
    SSO_ERROR_INVALID_CUSTOM_FUNC                      = -5,
    SSO_ERROR_INVALID_PARAMETER                        = -6,
    SSO_ERROR_NOT_INITIALIZED                          = -7

} SignonErrorCode;


gboolean
get_system_http_proxy (gboolean https, gchar **host, guint *port);
gchar* getSystemProxy(void);


size_t writeMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data);
size_t readMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data);
void resetNonce(SsoNokiaAccountPlugin* self);
void resetTimestamp(SsoNokiaAccountPlugin* self);
void resetRequest(SsoNokiaAccountPlugin* self);
gchar* getValidator(GString* resource,  GString* password);
gchar* getDigest(GString* resource,
                        GString* password,
                        gchar* timestamp,
                        gchar* nonce);

gchar* getAuthenticateXmlContent(SsoNokiaAccountPlugin* self,
                                 GString* loginId,
                                 GString* password);

GArray* getAuthParams(SsoNokiaAccountPlugin* self, gchar* restVerb,
                             gchar* fullUrl,
                             GArray* parameters,
                             gboolean addAccessToken);
gchar* getAuthHeader(SsoNokiaAccountPlugin* self, gchar* restVerb,
                            gchar* fullUrl,
                            GArray*  parameters,
                            gboolean addAccessToken);
gchar* getQueryString(GArray* parameters);
gchar* parseResponse(SsoNokiaAccountPlugin* self, gchar* data,gint len);
gint sendRequest(SsoNokiaAccountPlugin* self, gchar* restVerb,
                          gchar* requestUrl,
                          GArray* parameters,
                          gboolean addAccessToken,
                          GError **err);
gchar* authenticateUser(SsoNokiaAccountPlugin* self, gchar* username, gchar* password, GError **err);
gchar* retrieveTokenInfo(SsoNokiaAccountPlugin* self, GError **err);
gchar* deleteToken(SsoNokiaAccountPlugin* self, GError **err);
gchar* refreshToken(SsoNokiaAccountPlugin* self, GError **err);

gchar* getResponse(SsoNokiaAccountPlugin* self);
gboolean setUrl(SsoNokiaAccountPlugin* self, gchar* url);
gboolean setConsumerKey(SsoNokiaAccountPlugin* self, gchar* consumerKey);
gboolean setConsumerSecret(SsoNokiaAccountPlugin* self, gchar* consumerSecret);
gboolean setConsumer(SsoNokiaAccountPlugin* self, gchar* consumerKey, gchar* consumerSecret);
gint errorToInt(gchar* errorCode);

G_END_DECLS

#endif /*SSOOAUTHACCOUNT_UTILS_H_*/
