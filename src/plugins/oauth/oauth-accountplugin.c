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

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <string.h>

#define SSO_NOKIAACCOUNTPLUGIN_TRACE

#ifdef SSOTRACE
#undef SSOTRACE
#endif
#ifdef SSO_NOKIAACCOUNTPLUGIN_TRACE
        #define SSOTRACE(format...)     qDebug(G_STRLOC ": " format)
    #else
         #define SSOTRACE(...) do {} while (0)
    #endif

#include "oauth-accountplugin.h"
#include "oauth-account-utils.h"
#include "oauth-util.h"


G_DEFINE_TYPE(SsoNokiaAccountPlugin, sso_nokiaaccount_plugin, G_TYPE_OBJECT);

/**
 * Login NokiaAccount
 *
 * @param self
 *         pointer to plugin object
 * @param account
 *         pointer to account structure
 * @return plugin response
 */
static SsoPluginResponse*
nokiaaccount_plugin_login(SsoNokiaAccountPlugin* self,
        SsoAccountData *account)
{
    GError *error=NULL;
    gchar* res=NULL;


    g_return_val_if_fail (SSO_IS_NOKIAACCOUNT_PLUGIN(self), NULL);
    g_return_val_if_fail (account!=NULL, NULL);

    //pthread_testcancel();
    //pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    SsoPluginResponse* response = g_new0(SsoPluginResponse, 1);
    response->response = NULL;
    response->err = NULL;
    response->response_error = SSO_ERROR_NONE;

#ifdef SSO_MAX_RETRIES
    gint tries = 0;
    do {
        g_clear_error(&error);
#endif //SSO_MAX_RETRIES

    //pthread_cleanup_push((cleanupfn_t)sso_plugin_response_free, (gpointer)response);
    //pthread_cleanup_push((cleanupfn_t)g_free, (gpointer)res);
    //pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    res = authenticateUser(SSO_NOKIAACCOUNT_PLUGIN(self),
            account->username, account->password, &error);

    //pthread_testcancel();
    //pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    if (error==NULL && res!=NULL) //no errors during authentication
    {
        if(response->response)
            g_byte_array_free(response->response, TRUE);

        GByteArray *ba = g_byte_array_new();
        g_byte_array_append(ba, (guint8*)res, strlen(res)+1 );
        response->response = ba;
    }
    else
    {
        if(error) {
            response->response_error = error->code;
        }
        else
        {
            response->response_error = SSO_ERROR_GENERAL;
        }
        response->response = NULL;
    }

    response->err = error;

   // pthread_cleanup_pop(1); /* g_free(res); */
    //pthread_cleanup_pop(0); /* response */

#ifdef SSO_MAX_RETRIES
    tries++;
    } while((tries < SSO_MAX_RETRIES)&&
            (response->response_error != SSO_ERROR_NONE)&&
            (response->err == NULL));
#endif //SSO_MAX_RETRIES


    return response;
}

/**
 * Auth NokiaAccount
 *
 * @param self
 *         pointer to plugin object
 * @param account
 *         pointer to account structure
 * @return plugin response
 */
static SsoPluginResponse*
nokiaaccount_plugin_auth(SsoNokiaAccountPlugin* self,
        SsoAccountData *account)
{

    g_return_val_if_fail (SSO_IS_NOKIAACCOUNT_PLUGIN(self), NULL);
    g_return_val_if_fail (account!=NULL, NULL);

  //  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    GByteArray *ba = g_byte_array_new();
    gchar *resp = SSO_NOKIAACCOUNT_PLUGIN(self)->accessTokenKey;

    SsoPluginResponse* response = g_new0(SsoPluginResponse, 1);
    response->err = NULL;
    if(resp) {
    ba = g_byte_array_append(ba, (guint8*)resp, strlen(resp)+1);
    } else {
        ba = g_byte_array_append(ba, (guint8*)"", 1);

    }
    response->response = ba;
    response->response_error = SSO_ERROR_NONE;
    return response;
}

/**
 * Logout NokiaAccount
 *
 * @param self
 *         pointer to plugin object
 * @param account
 *         pointer to account structure
 * @return plugin response
 */
static SsoPluginResponse*
nokiaaccount_plugin_logout(SsoNokiaAccountPlugin* self,
        SsoAccountData /**account*/)
{

    GError *error=NULL;
    gchar* res = NULL;

    g_return_val_if_fail (SSO_IS_NOKIAACCOUNT_PLUGIN(self), NULL);
//    g_return_val_if_fail (account!=NULL, NULL);

    res = deleteToken(SSO_NOKIAACCOUNT_PLUGIN(self),
            &error);

   // pthread_testcancel();
   // pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    SsoPluginResponse* response = g_new0(SsoPluginResponse, 1);
    response->err = error;
    response->response=NULL;

    if(error!=NULL)
    {
        response->response_error = error->code;
    }
    else
    {
        GByteArray *ba = g_byte_array_new();
        gchar resp[] = "";
        ba = g_byte_array_append(ba, (guint8*)resp, strlen(resp)+1);
        response->response = ba;

        response->response_error = SSO_ERROR_NONE;
    }

    g_free(res);
    return response;
}

/**
 * CustomRequest for NokiaAccount
 *
 * @param self
 *         pointer to plugin object
 * @param account
 *         pointer to account structure
 * @param func_id
 *         custom function identifier
 * @param
 *         parameters for custom function
 * @return plugin response
 */
static SsoPluginResponse*
nokiaaccount_plugin_custom_request(SsoNokiaAccountPlugin* self,
        SsoAccountData* /**account */,
                                   gint func_id,
                                      GByteArray *request)
{
    SSOTRACE("nokiaaccount_plugin_custom_request\n");
    gchar* param=NULL;
    gboolean ret=TRUE;
    gchar* resp=NULL;
    GByteArray *ba=NULL;

    g_return_val_if_fail (SSO_IS_NOKIAACCOUNT_PLUGIN(self), NULL);

   // pthread_testcancel();
   // pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    SsoPluginResponse* response = g_new0(SsoPluginResponse, 1);
    response->err = NULL;
    response->response = NULL;
    response->response_error = SSO_ERROR_NONE;


    /* set param check */
    if( (SSO_NOKIA_ACCOUNT_SET_BEGIN < func_id) &&
            (func_id < SSO_NOKIA_ACCOUNT_SET_END) )
    {
        if(request==NULL) {
            SSOTRACE("bad request param\n");
            response->response_error = SSO_ERROR_INVALID_PARAMETER;
            return response;
        }
        param=(gchar*)request->data;
    }

   // pthread_cleanup_push((cleanupfn_t)sso_plugin_response_free, (gpointer)response);
   // pthread_cleanup_push((cleanupfn_t)g_free, (gpointer)resp);

    //pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    SSOTRACE("func: %d\n",func_id);
    switch (func_id) {
    case SSO_NOKIA_ACCOUNT_NOP:

        break;
    case SSO_NOKIA_ACCOUNT_SET_SERVER_URL:
        ret=setUrl(SSO_NOKIAACCOUNT_PLUGIN(self),param);
        break;
    case SSO_NOKIA_ACCOUNT_SET_CONSUMER_KEY:
        ret=setConsumerKey(SSO_NOKIAACCOUNT_PLUGIN(self),param);
        break;
    case SSO_NOKIA_ACCOUNT_SET_CONSUMER_SECRET:
        ret=setConsumerSecret(SSO_NOKIAACCOUNT_PLUGIN(self),param);
        break;
    case SSO_NOKIA_GET_TOKEN_INFO:
        resp=retrieveTokenInfo(SSO_NOKIAACCOUNT_PLUGIN(self),&(response->err));
        break;
    default:
        SSOTRACE("default functionality\n");
        response->response_error = SSO_ERROR_INVALID_CUSTOM_FUNC;
        break;
    }

   // pthread_testcancel();
   // pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    /* handle errors and return values */
    if(ret==FALSE)
    {
        response->response_error = SSO_ERROR_GENERAL;
    }
    /* this is needed for getters only */
    if( (func_id > SSO_NOKIA_ACCOUNT_SET_END) )
    {
        if(resp==NULL)
        {
            response->response_error=SSO_ERROR_NOT_INITIALIZED;
        }
        else
        {
            ba = g_byte_array_new();
            g_byte_array_append(ba, (guint8*)resp, strlen(resp)+1);
            response->response = ba;
//            g_free(resp);
        }
    }
    else
    {
        ba = g_byte_array_new();
        g_byte_array_append(ba, (guint8*)"", 1);
        response->response = ba;

    }


   // pthread_cleanup_pop(1); /* gchar* resp; */
  //  pthread_cleanup_pop(0); /* SsoPluginResponse* response; */
    return response;
}


static void
nokiaaccount_plugin_interface_init (gpointer  /*g_iface*/,
                            gpointer  /*iface_data*/)
{
}

static void sso_nokiaaccount_plugin_init (SsoNokiaAccountPlugin* self);

/*spawn*/
/*Add here a parameter to customize the server*/
/*is REST_PATH needed? */
static void
sso_nokiaaccount_plugin_init (SsoNokiaAccountPlugin* self)
{

    SSOTRACE("sso_nokiaaccount_plugin_init\n");
    self->timestamp=NULL;
    self->nonce=NULL;
    self->baseUrl=NULL;
    self->consumerKey=NULL;
    self->consumerSecret=NULL;
    self->accessTokenKey=NULL;
    self->accessTokenSecret=NULL;
    self->clientIp=NULL;
    self->clientAgent=NULL;
    self->response=NULL;
    self->username=NULL;


    self->proxy = NULL;

    self->cancelled=FALSE;

    //test server address
    //self->baseUrl=g_strconcat("https://nabbi.noklab.com" , REST_PATH, NULL);
    self->baseUrl=g_strconcat("http://term.ie/oauth/example/" , REST_PATH, NULL);
}


static void
sso_nokiaaccount_plugin_finalize(GObject * obj)
{
    SsoNokiaAccountPlugin *self = SSO_NOKIAACCOUNT_PLUGIN(obj);

    g_free(self->timestamp);
    g_free(self->nonce);
    g_free(self->baseUrl);
    g_free(self->consumerKey);
    g_free(self->consumerSecret);
    g_free(self->accessTokenKey);
    g_free(self->accessTokenSecret);
    g_free(self->clientIp);
    g_free(self->clientAgent);
    g_free(self->response);
    g_free(self->username);
    g_free(self->proxy);

    self->timestamp=NULL;
    self->nonce=NULL;
    self->baseUrl=NULL;
    self->consumerKey=NULL;
    self->consumerSecret=NULL;
    self->accessTokenKey=NULL;
    self->accessTokenSecret=NULL;
    self->clientIp=NULL;
    self->clientAgent=NULL;
    self->response=NULL;
    self->username=NULL;
    self->proxy = NULL;

 //  G_OBJECT_CLASS(sso_nokiaaccount_plugin_parent_class)->finalize(obj);

}

static void
sso_nokiaaccount_plugin_class_init (SsoNokiaAccountPluginClass* klass)
{
    GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
    gobject_class->finalize =  sso_nokiaaccount_plugin_finalize;
}


SsoNokiaAccountPlugin* sso_auth_plugin_new()
{
    SSOTRACE("\n");

    GObject* obj = (GObject*) g_object_new(SSO_TYPE_NOKIAACCOUNT_PLUGIN, NULL);
    return SSO_NOKIAACCOUNT_PLUGIN(obj);
}

const gchar* sso_nokiaaccount_plugin_name(SsoNokiaAccountPlugin * /*plugin*/)
{
    return "OAuthAccount";
}

void sso_nokiaaccount_plugin_set_proxy(SsoNokiaAccountPlugin *plugin, const char* proxy)
{
    SSOTRACE("\n");
    if(plugin->proxy) g_free(plugin->proxy);
    plugin->proxy = g_strdup(proxy);
}

void sso_plugin_response_free(SsoPluginResponse* response)
{
    if(!response)
    {
        return;
    }

    g_clear_error(&(response->err));

    if(response->response)
    {
        g_byte_array_free(response->response, TRUE);
        response->response=NULL;
    }

    g_free(response);
}

