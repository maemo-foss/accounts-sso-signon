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


#ifndef OAUTHPLUGIN_H_
#define OAUTHPLUGIN_H_

#include <QtCore>

#include "signoncommon.h"
#include "sessiondata.h"
#include "authpluginif.h"

class OAuthPluginTest;
namespace OAuthPluginNS {

/*!
 * @class OAuthPlugin
 * Nokia Account authentication plugin.
 */
class OAuthPlugin : public AuthPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(AuthPluginInterface)
    friend class ::OAuthPluginTest;
public:
    OAuthPlugin(QObject *parent = 0);
    virtual ~OAuthPlugin();
public Q_SLOTS:
    QString type() const;
    QStringList mechanisms() const;
    void cancel();
    void process(const SignOn::SessionData &inData, const QString &mechanism = 0);
private:
    class Private;
    Private *d; // Owned.
};

} //namespace OAuthPluginNS

#endif /* OAUTHLUGIN_H_ */
