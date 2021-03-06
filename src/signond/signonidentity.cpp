/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 *
 * Contact: Aurel Popirtac <ext-aurel.popirtac@nokia.com>
 * Contact: Alberto Mardegan <alberto.mardegan@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <iostream>
#include <QVariantMap>

#include "signond-common.h"
#include "signonidentity.h"
#include "signonui_interface.h"
#include "SignOn/uisessiondata.h"
#include "SignOn/uisessiondata_priv.h"
#include "signoncommon.h"

#include "accesscontrolmanager.h"
#include "signonidentityadaptor.h"

#define SIGNON_RETURN_IF_CAM_UNAVAILABLE(_ret_arg_) do {                          \
        if (!(CredentialsAccessManager::instance()->credentialsSystemOpened())) { \
            replyError(internalServerErrName, \
                       internalServerErrStr + \
                       QLatin1String("Could not access Signon Database.")); \
            return _ret_arg_;           \
        }                               \
    } while(0)

using namespace SignOnCrypto;

namespace SignonDaemonNS {

    const QString internalServerErrName = SIGNOND_INTERNAL_SERVER_ERR_NAME;
    const QString internalServerErrStr = SIGNOND_INTERNAL_SERVER_ERR_STR;

    SignonIdentity::SignonIdentity(quint32 id, int timeout,
                                   SignonDaemon *parent)
            : SignonDisposable(timeout, parent),
              m_pInfo(NULL),
              m_pSignonDaemon(parent),
              m_registered(false)
    {
        m_id = id;

        /*
         * creation of unique name for the given identity
         * */
        static quint32 incr = 0;
        QString objectName = SIGNOND_DAEMON_OBJECTPATH + QLatin1String("/Identity_")
                             + QString::number(incr++, 16);
        setObjectName(objectName);

        m_signonui = new SignonUiAdaptor(
                                        SIGNON_UI_SERVICE,
                                        SIGNON_UI_DAEMON_OBJECTPATH,
                                        SIGNOND_BUS,
                                        this);

        if (!(m_encryptor = new Encryptor))
            qFatal("Cannot allocate memory for encryptor");
    }

    SignonIdentity::~SignonIdentity()
    {
        if (m_registered)
        {
            emit unregistered();
            QDBusConnection connection = SIGNOND_BUS;
            connection.unregisterObject(objectName());
        }

        if (credentialsStored())
            m_pSignonDaemon->m_storedIdentities.remove(m_id);
        else
            m_pSignonDaemon->m_unstoredIdentities.remove(objectName());

        delete m_signonui;
        delete m_encryptor;
    }

    bool SignonIdentity::init()
    {
        QDBusConnection connection = SIGNOND_BUS;

        if (!connection.isConnected()) {
            QDBusError err = connection.lastError();
            TRACE() << "Connection cannot be established:" << err.errorString(err.type()) ;
            return false;
        }

        QDBusConnection::RegisterOptions registerOptions = QDBusConnection::ExportAllContents;

#ifndef SIGNON_DISABLE_ACCESS_CONTROL
        (void)new SignonIdentityAdaptor(this);
        registerOptions = QDBusConnection::ExportAdaptors;
#endif

        if (!connection.registerObject(objectName(), this, registerOptions)) {
            TRACE() << "Object cannot be registered: " << objectName();
            return false;
        }

        return (m_registered = true);
    }

    SignonIdentity *SignonIdentity::createIdentity(quint32 id, SignonDaemon *parent)
    {
        SignonIdentity *identity =
            new SignonIdentity(id, parent->identityTimeout(), parent);

        if (!identity->init()) {
            TRACE() << "The created identity is invalid and will be deleted.\n";
            delete identity;
            return NULL;
        }

        return identity;
    }

    void SignonIdentity::replyError(const QString &name, const QString &msg)
    {
        setDelayedReply(true);
        QDBusMessage errReply = message().createErrorReply(name, msg);
        connection().send(errReply);
    }

    void SignonIdentity::destroy()
    {
        if (m_registered)
        {
            emit unregistered();
            QDBusConnection connection = SIGNOND_BUS;
            connection.unregisterObject(objectName());
            m_registered = false;
        }

        deleteLater();
    }

    SignonIdentityInfo SignonIdentity::queryInfo(bool &ok, bool queryPassword)
    {
        ok = true;

        if (m_pInfo) {
            delete m_pInfo;
            m_pInfo = NULL;
        }

        CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
        m_pInfo = new SignonIdentityInfo(db->credentials(m_id, queryPassword));

        if (db->lastError().isValid()) {
            ok = false;
            delete m_pInfo;
            m_pInfo = NULL;
            return SignonIdentityInfo();
        }
        return *m_pInfo;
    }

    bool SignonIdentity::addReference(const QString &reference)
    {
        TRACE() << "addReference: " << reference;

        SIGNON_RETURN_IF_CAM_UNAVAILABLE(false);

        CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
        if (db == NULL) {
            BLAME() << "NULL database handler object.";
            return false;
        }
        QString aegisIdToken = AccessControlManager::idTokenOfPeer(static_cast<QDBusContext>(*this));
        keepInUse();
        return db->addReference(m_id, aegisIdToken, reference);
    }

    bool SignonIdentity::removeReference(const QString &reference)
    {
        TRACE() << "removeReference: " << reference;

        SIGNON_RETURN_IF_CAM_UNAVAILABLE(false);

        CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
        if (db == NULL) {
            BLAME() << "NULL database handler object.";
            return false;
        }
        QString aegisIdToken = AccessControlManager::idTokenOfPeer(static_cast<QDBusContext>(*this));
        keepInUse();
        return db->removeReference(m_id, aegisIdToken, reference);
    }

    quint32 SignonIdentity::requestCredentialsUpdate(const QString &displayMessage)
    {
        SIGNON_RETURN_IF_CAM_UNAVAILABLE(SIGNOND_NEW_IDENTITY);

        bool ok;
        SignonIdentityInfo info = queryInfo(ok, false);

        if (!ok) {
            BLAME() << "Identity not found.";
            replyError(SIGNOND_IDENTITY_NOT_FOUND_ERR_NAME,
                       SIGNOND_IDENTITY_NOT_FOUND_ERR_STR);
            return SIGNOND_NEW_IDENTITY;
        }
        if (!info.storePassword()) {
            BLAME() << "Password cannot be stored.";
            replyError(SIGNOND_STORE_FAILED_ERR_NAME,
                       SIGNOND_STORE_FAILED_ERR_STR);
            return SIGNOND_NEW_IDENTITY;
        }

        //delay dbus reply, ui interaction might take long time to complete
        setDelayedReply(true);
        m_message = message();

        //create ui request to ask password
        QVariantMap uiRequest;
        uiRequest.insert(SSOUI_KEY_QUERYPASSWORD, true);
        uiRequest.insert(SSOUI_KEY_USERNAME, info.userName());
        uiRequest.insert(SSOUI_KEY_MESSAGE, displayMessage);
        uiRequest.insert(SSOUI_KEY_CAPTION, info.caption());

        TRACE() << "Waiting for reply from signon-ui";
        QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(m_signonui->queryDialog(uiRequest),
                                                this);
        connect(watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this, SLOT(queryUiSlot(QDBusPendingCallWatcher*)));

        setAutoDestruct(false);
        return 0;
    }

    QList<QVariant> SignonIdentity::queryInfo()
    {
        TRACE() << "QUERYING INFO";

        SIGNON_RETURN_IF_CAM_UNAVAILABLE(QList<QVariant>());

        bool ok;
        SignonIdentityInfo info = queryInfo(ok, false);

        if (!ok) {
            TRACE();
            replyError(SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_NAME,
                       SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_STR +
                       QLatin1String("Database querying error occurred."));
            return QList<QVariant>();
        }

        if (info.isNew()) {
            TRACE();
            replyError(SIGNOND_IDENTITY_NOT_FOUND_ERR_NAME,
                       SIGNOND_IDENTITY_NOT_FOUND_ERR_STR);
            return QList<QVariant>();
        }

        keepInUse();
        return info.toVariantList();
    }

    void SignonIdentity::queryUserPassword(const QVariantMap &params) {
        TRACE() << "Waiting for reply from signon-ui";
        QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(
                m_signonui->queryDialog(params), this);
        connect(watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this,
                SLOT(verifyUiSlot(QDBusPendingCallWatcher*)));

        setAutoDestruct(false);
    }

    bool SignonIdentity::verifyUser(const QVariantMap &params)
    {
        SIGNON_RETURN_IF_CAM_UNAVAILABLE(false);

        bool ok;
        SignonIdentityInfo info = queryInfo(ok, true);

        if (!ok) {
            BLAME() << "Identity not found.";
            replyError(SIGNOND_IDENTITY_NOT_FOUND_ERR_NAME,
                       SIGNOND_IDENTITY_NOT_FOUND_ERR_STR);
            return false;
        }
        if (!info.storePassword() || info.password().isEmpty()) {
            BLAME() << "Password is not stored.";
            replyError(SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_NAME,
                       SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_STR);
            return false;
        }

        //delay dbus reply, ui interaction might take long time to complete
        setDelayedReply(true);
        m_message = message();

        //create ui request to ask password
        QVariantMap uiRequest;
        uiRequest.unite(params);
        uiRequest.insert(SSOUI_KEY_QUERYPASSWORD, true);
        uiRequest.insert(SSOUI_KEY_USERNAME, info.userName());
        uiRequest.insert(SSOUI_KEY_CAPTION, info.caption());

        queryUserPassword(uiRequest);
        return false;
    }

    bool SignonIdentity::verifySecret(const QString &secret)
    {
        SIGNON_RETURN_IF_CAM_UNAVAILABLE(false);

        pid_t pidOfPeer = AccessControlManager::pidOfPeer(static_cast<QDBusContext>(*this));
        QString decodedSecret(m_encryptor->decodeString(secret, pidOfPeer));

        if (m_encryptor->status() != Encryptor::Ok) {
            QDBusMessage errReply = message().createErrorReply(SIGNOND_ENCRYPTION_FAILED_ERR_NAME,
                                                               SIGNOND_ENCRYPTION_FAILED_ERR_STR);
            SIGNOND_BUS.send(errReply);
            return false;
        }

        bool ok;
        SignonIdentityInfo info = queryInfo(ok);
        if (!ok) {
            TRACE();
            replyError(SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_NAME,
                       SIGNOND_CREDENTIALS_NOT_AVAILABLE_ERR_STR +
                       QLatin1String("Database querying error occurred."));
            return false;
        }

        CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
        bool ret = db->checkPassword(info.id(), info.userName(), decodedSecret);

        keepInUse();
        return ret;
    }

    void SignonIdentity::remove()
    {
        SIGNON_RETURN_IF_CAM_UNAVAILABLE();

        CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
        if ((db == 0) || !db->removeCredentials(m_id)) {
            TRACE() << "Error occurred while inserting/updating credentials.";
            replyError(SIGNOND_REMOVE_FAILED_ERR_NAME,
                       SIGNOND_REMOVE_FAILED_ERR_STR +
                       QLatin1String("Database error occurred."));
            return;
        }
        emit infoUpdated((int)SignOn::IdentityRemoved);
        keepInUse();
    }

    bool SignonIdentity::signOut()
    {
        TRACE() << "Signout request. Identity ID: " << id();
        /*
           - If the identity is stored (thus registered here)
           signal 'sign out' to all identities subsribed to this object,
           otherwise the only identity subscribed to this is the newly
           created client side identity, which called this method.
           - This is just a safety check, as the client identity - if it is a new one -
           should not inform server side to sign out.
        */
        if (id() != SIGNOND_NEW_IDENTITY) {
            //clear stored sessiondata
            CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
            if ((db == 0) || !db->removeData(m_id)) {
                TRACE() << "clear data failed";
            }

            emit infoUpdated((int)SignOn::IdentitySignedOut);
        }
        keepInUse();
        return true;
    }

    quint32 SignonIdentity::store(const QVariantMap &info)
    {
        keepInUse();
        SIGNON_RETURN_IF_CAM_UNAVAILABLE(SIGNOND_NEW_IDENTITY);

        /*
         * TODO: optimize the interaction with security framework: have 1 less call
         * In order to have this we need to fetch all tokens once, and parse them
         * in 'decodeString' and 'idTokenOfPid' as argument, but not pidOfPeer
         * */

        pid_t pidOfPeer = AccessControlManager::pidOfPeer(static_cast<QDBusContext>(*this));
        QString secret = info.value(SIGNOND_IDENTITY_INFO_SECRET).toString();
        QString decodedSecret(m_encryptor->decodeString(secret, pidOfPeer));

        if (m_encryptor->status() != Encryptor::Ok) {
            replyError(SIGNOND_ENCRYPTION_FAILED_ERR_NAME,
                       SIGNOND_ENCRYPTION_FAILED_ERR_STR);
            return SIGNOND_NEW_IDENTITY;
        }

        QString aegisIdToken = AccessControlManager::idTokenOfPid(pidOfPeer);

        bool storeSecret = info.value(SIGNOND_IDENTITY_INFO_STORESECRET).toBool();
        QVariant container = info.value(SIGNOND_IDENTITY_INFO_AUTHMETHODS);
        QVariantMap methods = qdbus_cast<QVariantMap>(container.value<QDBusArgument>());

        //Add creator to owner list if it has AID
        QStringList ownerList = info.value(SIGNOND_IDENTITY_INFO_OWNER).toStringList();
        if (!aegisIdToken.isNull())
            ownerList.append(aegisIdToken);

        SignonIdentityInfo identityInfo(info);
        identityInfo.setMethods(SignonIdentityInfo::mapVariantToMapList(methods));
        identityInfo.setOwnerList(ownerList);
        identityInfo.setPassword(decodedSecret);

        if (decodedSecret.isEmpty()) storeSecret = false;

        m_id = storeCredentials(identityInfo, storeSecret);

        if (m_id == SIGNOND_NEW_IDENTITY) {
            replyError(SIGNOND_STORE_FAILED_ERR_NAME,
                       SIGNOND_STORE_FAILED_ERR_STR);
        }

        return m_id;
    }

    quint32 SignonIdentity::storeCredentials(const quint32 id,
                                             const QString &userName,
                                             const QString &secret,
                                             const bool storeSecret,
                                             const QMap<QString, QVariant> &methods,
                                             const QString &caption,
                                             const QStringList &realms,
                                             const QStringList &accessControlList,
                                             const int type)
    {
        keepInUse();
        SIGNON_RETURN_IF_CAM_UNAVAILABLE(SIGNOND_NEW_IDENTITY);

        /*
         * TODO: optimize the interaction with security framework: have 1 less call
         * In order to have this we need to fetch all tokens once, and parse them
         * in 'decodeString' and 'idTokenOfPid' as argument, but not pidOfPeer
         * */

        pid_t pidOfPeer = AccessControlManager::pidOfPeer(static_cast<QDBusContext>(*this));
        QString decodedSecret(m_encryptor->decodeString(secret, pidOfPeer));

        if (m_encryptor->status() != Encryptor::Ok) {
            replyError(SIGNOND_ENCRYPTION_FAILED_ERR_NAME,
                       SIGNOND_ENCRYPTION_FAILED_ERR_STR);
            return SIGNOND_NEW_IDENTITY;
        }

        QString aegisIdToken = AccessControlManager::idTokenOfPid(pidOfPeer);

        QStringList accessControlListLocal = accessControlList;

        if (!aegisIdToken.isNull())
            accessControlListLocal.append(aegisIdToken);

        //this method is deprecated, so it will set acl as owner list
        if (m_pInfo == 0) {
            m_pInfo = new SignonIdentityInfo(id, userName, decodedSecret, storeSecret,
                                             caption, methods, realms,
                                             accessControlListLocal, accessControlListLocal,
                                             type);
        } else {
            m_pInfo->setUserName(userName);
            m_pInfo->setPassword(decodedSecret);
            m_pInfo->setMethods(SignonIdentityInfo::mapVariantToMapList(methods));
            m_pInfo->setCaption(caption);
            m_pInfo->setRealms(realms);
            m_pInfo->setAccessControlList(accessControlListLocal);
            m_pInfo->setType(type);
        }

        storeCredentials(*m_pInfo, storeSecret);

        if (m_id == SIGNOND_NEW_IDENTITY) {
            replyError(SIGNOND_STORE_FAILED_ERR_NAME,
                       SIGNOND_STORE_FAILED_ERR_STR);
        }

        return m_id;
    }

    quint32 SignonIdentity::storeCredentials(const SignonIdentityInfo &info, bool storeSecret)
    {
        CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
        if (db == NULL) {
            BLAME() << "NULL database handler object.";
            return SIGNOND_NEW_IDENTITY;
        }

        bool newIdentity = info.isNew();

        if (newIdentity)
            m_id = db->insertCredentials(info, storeSecret);
        else
            db->updateCredentials(info, storeSecret);

        if (db->errorOccurred()) {
            if (newIdentity)
                m_id = SIGNOND_NEW_IDENTITY;

            TRACE() << "Error occurred while inserting/updating credentials.";
        } else {
            m_pSignonDaemon->identityStored(this);

            //If secrets db is not available cache auth. data.
            if (!db->isSecretsDBOpen()) {
                AuthCache *cache = new AuthCache;
                cache->setUsername(info.userName());
                cache->setPassword(info.password());
                AuthCoreCache::instance()->insert(
                    AuthCoreCache::CacheId(m_id, AuthCoreCache::AuthMethod()), cache);
            }
            TRACE() << "FRESH, JUST STORED CREDENTIALS ID:" << m_id;
            emit infoUpdated((int)SignOn::IdentityDataUpdated);

            if (m_pInfo) {
                delete m_pInfo;
                m_pInfo = NULL;
            }

        }
        return m_id;
    }

    void SignonIdentity::queryUiSlot(QDBusPendingCallWatcher *call)
    {
        TRACE();
        setAutoDestruct(true);

        QDBusMessage errReply;
        QDBusPendingReply<QVariantMap> reply;
        if (call != NULL) {
            reply = *call;
            call->deleteLater();
        }
        QVariantMap resultParameters;
        if (!reply.isError() && reply.count()) {
            resultParameters = reply.argumentAt<0>();
        } else {
            errReply = m_message.createErrorReply(SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_NAME,
                    SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_STR);
            SIGNOND_BUS.send(errReply);
            return;
        }

        if (!resultParameters.contains(SSOUI_KEY_ERROR)) {
            //no reply code
            errReply = m_message.createErrorReply(SIGNOND_INTERNAL_SERVER_ERR_NAME,
                    SIGNOND_INTERNAL_SERVER_ERR_STR);
            SIGNOND_BUS.send(errReply);
            return;
        }

        int errorCode = resultParameters.value(SSOUI_KEY_ERROR).toInt();
        TRACE() << "error: " << errorCode;
        if (errorCode != QUERY_ERROR_NONE) {
            if (errorCode == QUERY_ERROR_CANCELED)
                errReply = m_message.createErrorReply(SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_NAME,
                        SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_STR);
            else
                errReply = m_message.createErrorReply(SIGNOND_INTERNAL_SERVER_ERR_NAME,
                        QString(QLatin1String("signon-ui call returned error %1")).arg(errorCode));

            SIGNOND_BUS.send(errReply);
            return;
        }

        if (resultParameters.contains(SSOUI_KEY_PASSWORD)) {
            CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
            if (db == NULL) {
                BLAME() << "NULL database handler object.";
                errReply = m_message.createErrorReply(SIGNOND_STORE_FAILED_ERR_NAME,
                        SIGNOND_STORE_FAILED_ERR_STR);
                SIGNOND_BUS.send(errReply);
                return;
            }

            //store new password
            if (m_pInfo) {
                m_pInfo->setPassword(resultParameters[SSOUI_KEY_PASSWORD].toString());

                quint32 ret = db->updateCredentials(*m_pInfo, true);
                delete m_pInfo;
                m_pInfo = NULL;
                if (ret != SIGNOND_NEW_IDENTITY) {
                    QDBusMessage dbusreply = m_message.createReply();
                    dbusreply << quint32(m_id);
                    SIGNOND_BUS.send(dbusreply);
                    return;
                } else{
                    BLAME() << "Error during update";
                }
            }
        }

        //this should not happen, return error
        errReply = m_message.createErrorReply(SIGNOND_INTERNAL_SERVER_ERR_NAME,
                SIGNOND_INTERNAL_SERVER_ERR_STR);
        SIGNOND_BUS.send(errReply);
        return;
    }

    void SignonIdentity::verifyUiSlot(QDBusPendingCallWatcher *call)
    {
        TRACE();
        setAutoDestruct(true);

        QDBusMessage errReply;
        QDBusPendingReply<QVariantMap> reply;
        if (call != NULL) {
            reply = *call;
            call->deleteLater();
        }
        QVariantMap resultParameters;
        if (!reply.isError() && reply.count()) {
            resultParameters = reply.argumentAt<0>();
        } else {
            errReply = m_message.createErrorReply(SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_NAME,
                    SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_STR);
            SIGNOND_BUS.send(errReply);
            return;
        }

        if (!resultParameters.contains(SSOUI_KEY_ERROR)) {
            //no reply code
            errReply = m_message.createErrorReply(SIGNOND_INTERNAL_SERVER_ERR_NAME,
                    SIGNOND_INTERNAL_SERVER_ERR_STR);
            SIGNOND_BUS.send(errReply);
            return;
        }

        int errorCode = resultParameters.value(SSOUI_KEY_ERROR).toInt();
        TRACE() << "error: " << errorCode;
        if (errorCode != QUERY_ERROR_NONE) {
            if (errorCode == QUERY_ERROR_CANCELED)
                errReply = m_message.createErrorReply(SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_NAME,
                        SIGNOND_IDENTITY_OPERATION_CANCELED_ERR_STR);
            else if (errorCode == QUERY_ERROR_FORGOT_PASSWORD)
                errReply = m_message.createErrorReply(SIGNOND_FORGOT_PASSWORD_ERR_NAME,
                        SIGNOND_FORGOT_PASSWORD_ERR_STR);
            else
                errReply = m_message.createErrorReply(SIGNOND_INTERNAL_SERVER_ERR_NAME,
                        QString(QLatin1String("signon-ui call returned error %1")).arg(errorCode));

            SIGNOND_BUS.send(errReply);
            return;
        }

        if (resultParameters.contains(SSOUI_KEY_PASSWORD)) {
            CredentialsDB *db = CredentialsAccessManager::instance()->credentialsDB();
            if (db == NULL) {
                BLAME() << "NULL database handler object.";
                errReply = m_message.createErrorReply(SIGNOND_STORE_FAILED_ERR_NAME,
                        SIGNOND_STORE_FAILED_ERR_STR);
                SIGNOND_BUS.send(errReply);
                return;
            }

            //compare passwords
            if (m_pInfo) {
                bool ret = m_pInfo->password() == resultParameters[SSOUI_KEY_PASSWORD].toString();

                if (!ret && resultParameters.contains(SSOUI_KEY_CONFIRMCOUNT)) {
                    int count = resultParameters[SSOUI_KEY_CONFIRMCOUNT].toInt();
                    TRACE() << "retry count:" << count;
                    if (count > 0) { //retry
                        resultParameters[SSOUI_KEY_CONFIRMCOUNT] = (count-1);
                        resultParameters[SSOUI_KEY_MESSAGEID] = QUERY_MESSAGE_NOT_AUTHORIZED;
                        queryUserPassword(resultParameters);
                        return;
                    } else {
                        //TODO show error note here if needed
                    }
                }
                delete m_pInfo;
                m_pInfo = NULL;
                QDBusMessage dbusreply = m_message.createReply();
                dbusreply << ret;
                SIGNOND_BUS.send(dbusreply);
                return;
            }
        }
        //this should not happen, return error
        errReply = m_message.createErrorReply(SIGNOND_INTERNAL_SERVER_ERR_NAME,
                SIGNOND_INTERNAL_SERVER_ERR_STR);
        SIGNOND_BUS.send(errReply);
        return;
    }

} //namespace SignonDaemonNS
