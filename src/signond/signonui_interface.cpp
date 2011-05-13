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

#include "signonui_interface.h"

#include "SignOn/uisessiondata_priv.h"

/*
 * Implementation of interface class SignonUiAdaptor
 */

const char queryDialogMethod[] = "queryDialog";
const char refreshDialogMethod[] = "refreshDialog";
const char cancelDialogMethod[] = "cancelDialog";

SignonUiAdaptor::SignonUiAdaptor(const QString &service, const QString &path, const QDBusConnection &connection, QObject *parent)
    : QDBusAbstractInterface(service, path, staticInterfaceName(), connection, parent),
      watcher(0)
{
}

SignonUiAdaptor::~SignonUiAdaptor()
{
}

/*
 * Open a new dialog
 * */
void SignonUiAdaptor::queryDialog(const QVariantMap &parameters)
{
    requestType = Query;
    makeCall(QLatin1String(queryDialogMethod), parameters);
}

/*
 * Update the existing dialog
 * */
void SignonUiAdaptor::refreshDialog(const QVariantMap &parameters)
{
    requestType = Refresh;
    makeCall(QLatin1String(refreshDialogMethod), parameters);
}

/*
 * Cancel a dialog request
 * */
void SignonUiAdaptor::cancelDialog(const QString &requestId)
{
    if (watcher != 0) {
        delete watcher;
        watcher = 0;
    }
    QList<QVariant> argumentList;
    argumentList << requestId;
    callWithArgumentList(QDBus::NoBlock, QLatin1String(cancelDialogMethod), argumentList);
}

bool SignonUiAdaptor::isBusy() const
{
    return (watcher != 0) && !watcher->isFinished();
}

void SignonUiAdaptor::makeCall(const QString &method, const QVariantMap &parameters)
{
    QList<QVariant> argumentList;
    argumentList << parameters;

    QDBusPendingCall call = callWithArgumentListAndBigTimeout(
        method, argumentList);

    if (watcher != 0) delete watcher;

    watcher = new QDBusPendingCallWatcher(call, this);
    connect(watcher,
            SIGNAL(finished(QDBusPendingCallWatcher*)),
            SLOT(callFinished(QDBusPendingCallWatcher*)));
}

QDBusPendingCall SignonUiAdaptor::callWithArgumentListAndBigTimeout(const QString &method,
                                                         const QList<QVariant> &args)
{
    QDBusMessage msg = QDBusMessage::createMethodCall(service(),
                                                      path(),
                                                      interface(),
                                                      method);
    if (!args.isEmpty())
        msg.setArguments(args);
    return connection().asyncCall(msg, SIGNOND_MAX_TIMEOUT);
}
