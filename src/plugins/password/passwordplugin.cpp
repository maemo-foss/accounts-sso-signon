/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 *
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

#include "passwordplugin.h"
#include "SignOn/signonplugincommon.h"

using namespace SignOn;
static bool isProcessing = false;

namespace PasswordPluginNS {

    PasswordPlugin::PasswordPlugin(QObject *parent)
    : AuthPluginInterface(parent)
    {
        TRACE();
    }

    PasswordPlugin::~PasswordPlugin()
    {
        TRACE();
   }

    QString PasswordPlugin::type() const
    {
        return QLatin1String("password");
    }

    QStringList PasswordPlugin::mechanisms() const
    {
        QStringList res = QStringList(QLatin1String("password"));

        return res;
    }

    void PasswordPlugin::cancel()
    {
        replyError(Error(Error::SessionCanceled));
    }

    /*
     * Password plugin is used for returning password
     * */
    void PasswordPlugin::process(const SignOn::SessionData &inData,
                                const QString &mechanism )
    {
        TRACE();
        Q_UNUSED(mechanism);
        SignOn::SessionData response;

        isProcessing = true;

        if (!inData.UserName().isEmpty())
            response.setUserName(inData.UserName());

        if (!inData.Secret().isEmpty()) {
            response.setSecret(inData.Secret());
            replyResult(response);
            return;
        }

        //we didn't receive password from signond, so ask from user
        SignOn::UiSessionData data = inData.data<UiSessionData>();
        if (inData.UserName().isEmpty())
            data.setQueryUserName(true);
        else
            data.setUserName(inData.UserName());

        data.setQueryPassword(true);

        TRACE() << data.propertyNames();
        emit userActionRequired(data);

        return;
    }

    void PasswordPlugin::userActionFinished(const SignOn::UiSessionData &data)
    {
        TRACE();

        if (data.QueryErrorCode() == QUERY_ERROR_NONE) {
            SignOn::SessionData response;
            response.setUserName(data.UserName());
            response.setSecret(data.Secret());
            replyResult(response);
            return;
        }

        if (data.QueryErrorCode() == QUERY_ERROR_CANCELED)
            replyError(Error::SessionCanceled);
        else
            replyError(Error(Error::UserInteraction,
                       QLatin1String("userActionFinished error: ")
                       + QString::number(data.QueryErrorCode())));

        return;
    }

    void PasswordPlugin::replyError(const Error &err)
    {
        if (isProcessing) {
            TRACE() << "Error Emitted";
            emit error(err);
            isProcessing = false;
        }
    }

    void PasswordPlugin::replyResult(const SessionData &data)
    {
        if (isProcessing) {
            TRACE() << "Result Emitted";
            emit result(data);
            isProcessing = false;
        }
    }

    SIGNON_DECL_AUTH_PLUGIN(PasswordPlugin)
} //namespace PasswordPluginNS
