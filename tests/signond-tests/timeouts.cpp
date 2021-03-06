/*
 * This file is part of signon
 *
 * Copyright (C) 2010 Nokia Corporation.
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

#include "timeouts.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDebug>

#include "signond/signoncommon.h"

using namespace SignOn;

/*
 * test timeout 20 seconds
 * */
#define test_timeout 20000


void TimeoutsTest::initTestCase()
{
    /* Kill any running instances of signond */
    QProcess::execute("pkill -9 signond");

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QLatin1String("SSO_IDENTITY_TIMEOUT"), QLatin1String("5"));
    daemonProcess = new QProcess();
    daemonProcess->setProcessEnvironment(env);
    daemonProcess->start("signond");
    daemonProcess->waitForStarted(10 * 1000);
    /*
     * 1 second is still required as the signon daemon needs time to be started
     * */
    sleep(1);
}

void TimeoutsTest::cleanupTestCase()
{
    daemonProcess->kill();
    daemonProcess->waitForFinished();

    delete daemonProcess;
}

void TimeoutsTest::init()
{
    completed = false;
}

void TimeoutsTest::identityTimeout()
{
    QEventLoop loop;
    QTimer::singleShot(test_timeout, &loop, SLOT(quit()));
    QObject::connect(this, SIGNAL(finished()), &loop, SLOT(quit()));

    QMap<MethodName,MechanismsList> methods;
    methods.insert("dummy", QStringList() << "mech1" << "mech2");
    IdentityInfo info = IdentityInfo(QLatin1String("timeout test"),
                                     QLatin1String("timeout@test"),
                                     methods);
    Identity *identity = Identity::newIdentity(info);
    QVERIFY(identity != NULL);

    QObject::connect(identity,
                     SIGNAL(credentialsStored(const quint32)),
                     this,
                     SLOT(credentialsStored(const quint32)));
    QObject::connect(identity,
                     SIGNAL(error(Identity::IdentityError,const QString&)),
                     this,
                     SLOT(identityError(Identity::IdentityError,const QString&)));

    identity->storeCredentials();

    loop.exec();
    QVERIFY(identity->id() != SSO_NEW_IDENTITY);

    QDBusConnection conn = SIGNOND_BUS;

    QDBusMessage msg = QDBusMessage::createMethodCall(SIGNOND_SERVICE,
                                                      SIGNOND_DAEMON_OBJECTPATH,
                                                      SIGNOND_DAEMON_INTERFACE,
                                                      "registerStoredIdentity");
    QList<QVariant> args;
    args << identity->id();
    msg.setArguments(args);

    QDBusMessage reply = conn.call(msg);
    QVERIFY(reply.type() == QDBusMessage::ReplyMessage);

    QDBusObjectPath objectPath = reply.arguments()[0].value<QDBusObjectPath>();
    QString path = objectPath.path();
    qDebug() << "Got path" << path;
    QVERIFY(!path.isEmpty());

    bool success;

    QTest::qSleep(100);
    success = triggerDisposableCleanup();
    QVERIFY(success);

    /* The identity object must exist now */
    QVERIFY(identityAlive(path));

    QTest::qSleep(6 * 1000);
    success = triggerDisposableCleanup();
    QVERIFY(success);

    /* After SSO_IDENTITY_TIMEOUT seconds, the identity must have been
     * destroyed */
    QVERIFY(!identityAlive(path));
}

void TimeoutsTest::identityRegisterTwice()
{
    QEventLoop loop;
    QTimer::singleShot(test_timeout, &loop, SLOT(quit()));
    QObject::connect(this, SIGNAL(finished()), &loop, SLOT(quit()));

    QMap<MethodName,MechanismsList> methods;
    methods.insert("dummy", QStringList() << "mech1" << "mech2");
    IdentityInfo info = IdentityInfo(QLatin1String("timeout test"),
                                     QLatin1String("timeout@test"),
                                     methods);
    Identity *identity = Identity::newIdentity(info);
    QVERIFY(identity != NULL);

    QObject::connect(identity,
                     SIGNAL(credentialsStored(const quint32)),
                     this,
                     SLOT(credentialsStored(const quint32)));
    QObject::connect(identity,
                     SIGNAL(error(Identity::IdentityError,const QString&)),
                     this,
                     SLOT(identityError(Identity::IdentityError,const QString&)));

    identity->storeCredentials();

    loop.exec();
    QVERIFY(identity->id() != SSO_NEW_IDENTITY);

    QDBusConnection conn = SIGNOND_BUS;

    QDBusMessage msg = QDBusMessage::createMethodCall(SIGNOND_SERVICE,
                                                      SIGNOND_DAEMON_OBJECTPATH,
                                                      SIGNOND_DAEMON_INTERFACE,
                                                      "registerStoredIdentity");
    QList<QVariant> args;
    args << identity->id();
    msg.setArguments(args);

    QDBusMessage reply = conn.call(msg);
    QVERIFY(reply.type() == QDBusMessage::ReplyMessage);

    QDBusObjectPath objectPath = reply.arguments()[0].value<QDBusObjectPath>();
    QString path = objectPath.path();
    qDebug() << "Got path" << path;
    QVERIFY(!path.isEmpty());

    bool success;

    QTest::qSleep(100);
    success = triggerDisposableCleanup();
    QVERIFY(success);

    /* The identity object must exist now */
    QVERIFY(identityAlive(path));

    QTest::qSleep(6 * 1000);
    /* now we register the same identity again. The expected behavior is that
     * the registration succeeds, possibly returning the same object path as
     * before.
     * This is to test a regression (NB#182914) which was happening because
     * signond was deleting the expired Identity immediately after returning
     * its object path to the client.
     */
    reply = conn.call(msg);
    QVERIFY(reply.type() == QDBusMessage::ReplyMessage);

    objectPath = reply.arguments()[0].value<QDBusObjectPath>();
    path = objectPath.path();
    qDebug() << "Got path" << path;
    QVERIFY(!path.isEmpty());

    QVERIFY(identityAlive(path));
}

void TimeoutsTest::identityError(Identity::IdentityError code,
                                 const QString &message)
{
    qDebug() << Q_FUNC_INFO << message;
    QFAIL("Unexpected error!");
    emit finished();

    Q_UNUSED(code);
}

bool TimeoutsTest::triggerDisposableCleanup()
{
    QDBusConnection conn = SIGNOND_BUS;

    /* create a new identity just to trigger the cleanup of disposable
     * objects */
    QDBusMessage msg = QDBusMessage::createMethodCall(SIGNOND_SERVICE,
                                                      SIGNOND_DAEMON_OBJECTPATH,
                                                      SIGNOND_DAEMON_INTERFACE,
                                                      "registerNewIdentity");
    QDBusMessage reply = conn.call(msg);
    return (reply.type() == QDBusMessage::ReplyMessage);
}

bool TimeoutsTest::identityAlive(const QString &path)
{
    QDBusConnection conn = SIGNOND_BUS;

    QString interface = QLatin1String("com.nokia.SingleSignOn.Identity");
    QDBusMessage msg = QDBusMessage::createMethodCall(SIGNOND_SERVICE,
                                                      path,
                                                      interface,
                                                      "queryInfo");
    QDBusMessage reply = conn.call(msg);
    return (reply.type() == QDBusMessage::ReplyMessage);
}

void TimeoutsTest::credentialsStored(const quint32 id)
{
    QVERIFY(id != 0);
    emit finished();
}

void TimeoutsTest::runAllTests()
{
    initTestCase();

    init();
    identityTimeout();
    identityRegisterTwice();

    cleanupTestCase();
}
