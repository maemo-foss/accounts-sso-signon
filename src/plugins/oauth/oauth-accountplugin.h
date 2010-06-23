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

#ifndef SSOOAUTHACCOUNTPLUGIN_H_
#define SSOOAUTHACCOUNTPLUGIN_H_

#include <QtCore>

#include "signoncommon.h"
#include "authpluginif.h"

#include <stdio.h>
#include <unistd.h>
#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define SSO_TYPE_NOKIAACCOUNT_PLUGIN             (sso_nokiaaccount_plugin_get_type ())
#define SSO_NOKIAACCOUNT_PLUGIN(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSO_TYPE_NOKIAACCOUNT_PLUGIN, SsoNokiaAccountPlugin))
#define SSO_NOKIAACCOUNT_PLUGIN_CLASS(vtable)    (G_TYPE_CHECK_CLASS_CAST ((vtable), SSO_NOKIAACCOUNT_PLUGIN, SsoNokiaAccountPluginClass))
#define SSO_IS_NOKIAACCOUNT_PLUGIN(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSO_TYPE_NOKIAACCOUNT_PLUGIN))
#define SSO_IS_NOKIAACCOUNT_PLUGIN_CLASS(vtable) (G_TYPE_CHECK_CLASS_TYPE ((vtable), SSO_TYPE_NOKIAACCOUNT_PLUGIN))
#define SSO_NOKIAACCOUNT_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSO_TYPE_NOKIAACCOUNT_PLUGIN, SsoNokiaAccountPluginClass))

typedef struct _SsoNokiaAccountPlugin SsoNokiaAccountPlugin;
typedef struct _SsoNokiaAccountPluginClass SsoNokiaAccountPluginClass;

struct _SsoNokiaAccountPlugin {
    GObject parent;
    gchar* timestamp;
    gchar* nonce;
    gchar* baseUrl;
    gchar* consumerKey;
    gchar* consumerSecret;
    gchar* accessTokenKey;
    gchar* accessTokenSecret;
    gchar* clientIp;
    gchar* clientAgent;
    gchar* response;
    gchar* username;
    gboolean cancelled;
    gchar *proxy;
};

struct _SsoNokiaAccountPluginClass {
        GObjectClass parent;
};

typedef struct PluginResponse {
    GError *err;
    gint response_error;
    GByteArray *response;
} SsoPluginResponse;

typedef struct _SsoAccountData
{
    char* serviceId;
    char* type;
    char* username;
    char* password;
    char* data;
    char* realm;
    int status;
    int timeout;
    GHashTable *fields;
} SsoAccountData;

typedef enum
{
    SSO_NOKIA_ACCOUNT_NOP = 0,
    SSO_NOKIA_ACCOUNT_SET_BEGIN, /* make sure all set are between BEGIN and END */
    SSO_NOKIA_ACCOUNT_SET_SERVER_URL,
    SSO_NOKIA_ACCOUNT_SET_CONSUMER_KEY,
    SSO_NOKIA_ACCOUNT_SET_CONSUMER_SECRET,
    SSO_NOKIA_ACCOUNT_SET_END,
    SSO_NOKIA_GET_TOKEN_INFO,
    SSO_NOKIA_GET_USER_PROFILE,
    SSO_NOKIA_GET_USER_INFO,
    SSO_NOKIA_GET_CONTACTS,
    SSO_NOKIA_GET_MARKETING_CONSENT
} SsoNokiaAccountCustomFunc;



GType sso_nokiaaccount_plugin_get_type (void);
const gchar* sso_nokiaaccount_plugin_name(SsoNokiaAccountPlugin *plugin);
void sso_nokiaaccount_plugin_set_proxy(SsoNokiaAccountPlugin *plugin, const char* proxy);
void sso_plugin_response_free(SsoPluginResponse* response);

G_END_DECLS

#endif /*SSOOAUTHACCOUNTPLUGIN_H_*/
