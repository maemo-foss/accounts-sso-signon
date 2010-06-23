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

#include "authpluginif.h"
#include "oauthplugin.h"
#include "oauthdata.h"

extern "C" {
#include "oauth-accountplugin.c"
#include "oauth-account-utils.c"
#include "oauth-util.c"
}

namespace OAuthPluginNS {

    class OAuthPlugin::Private
{
public:
    Private()
    {
            TRACE();
    }

    ~Private() {
            TRACE();
    }

    SsoNokiaAccountPlugin *m_plugin;
};


    OAuthPlugin::OAuthPlugin(QObject *parent)
    : AuthPluginInterface(parent), d(new Private)
{
    TRACE();
    d->m_plugin=sso_auth_plugin_new();
    TRACE();
}

OAuthPlugin::~OAuthPlugin()
{
    TRACE();
        g_object_unref(d->m_plugin);

    delete d;
    d = 0;
}

    QString OAuthPlugin::type() const
    {
        TRACE();
        return QString("oauth");
    }

    QStringList OAuthPlugin::mechanisms() const
    {
        TRACE();
        //at this point only REST is supported
        QStringList res = QStringList("REST");
        return res;
    }


    void OAuthPlugin::cancel()
    {
       TRACE();
       //this should stop curl
       cancelRequest(d->m_plugin);
    }

    void OAuthPlugin::process(const SignOn::SessionData &inData,
                                              const QString &mechanism)
    {
        TRACE();
        gboolean ret=false;
        SsoAccountData account;
        OAuthData response;
        AuthPluginError error;

        //get input parameters
        OAuthData m_input = inData.data<OAuthData>();

        TRACE() << "mechanism: " << mechanism;

        //check that required parameters are set
        if(!mechanism.isNull() && ! mechanisms().contains(mechanism))
        {
            //unsupported mechanism
            error = PLUGIN_ERROR_MECHANISM_NOT_SUPPORTED;
            emit result(response, error);
            return;
        }

        //TODO all setters should have checking for input validity
        if (! m_input.Proxy().isEmpty())
        sso_nokiaaccount_plugin_set_proxy(d->m_plugin,
                    m_input.Proxy().toAscii().constData());

        ret=setUrl(d->m_plugin,
                   (gchar*)m_input.Server().toAscii().constData());
        if(!ret) {
            error = PLUGIN_ERROR_MISSING_DATA;
            emit result(response, error);
            return;
        }
         ret=setConsumerKey(d->m_plugin,
                   (gchar*)m_input.ConsumerKey().toAscii().constData());
        if(!ret) {
            error = PLUGIN_ERROR_MISSING_DATA;
            emit result(response, error);
            return;
        }
         ret=setConsumerSecret(d->m_plugin,
                   (gchar*)m_input.ConsumerSecret().toAscii().constData());
        if(!ret) {
            error = PLUGIN_ERROR_MISSING_DATA;
            emit result(response, error);
            return;
        }
        account.username=g_strdup((gchar*)m_input.UserName().toAscii().constData());
        account.password=g_strdup((gchar*)m_input.Secret().toAscii().constData());

        //do authentication
        SsoPluginResponse* resp = nokiaaccount_plugin_login(d->m_plugin ,
             &account);

        //TODO better error handling is needed
        if(resp->err!=NULL) {
           error = PLUGIN_ERROR_GENERAL;
           response.setToken(QByteArray((const char*)resp->response->data, resp->response->len));
            emit result(response, error);
            return;
        }
        if(resp->response_error !=SSO_ERROR_NONE)
        {
            response.setError(resp->response_error);
        }
        response.setToken(QByteArray((const char*)resp->response->data, resp->response->len));
        //TODO here response could be parsed and put nicely into NaaiData

       error =  PLUGIN_ERROR_NONE;
       emit result(response, error);
       return;
    }

    SIGNON_DECL_AUTH_PLUGIN(OAuthPlugin)
} //namespace NaaiPluginNS
