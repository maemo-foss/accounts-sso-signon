/*
 * This file is part of signon
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 *
 * Contact: Aurel Popirtac <mailto:ext-Aurel.Popirtac@nokia.com>
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

#define SIGNON_ENABLE_UNSTABLE_APIS
#include "credentialsaccessmanager.h"

#include "default-key-authorizer.h"
#include "signond-common.h"

#include "SignOn/ExtensionInterface"
#include "SignOn/misc.h"

#include <QFile>
#include <QBuffer>


#define RETURN_IF_NOT_INITIALIZED(return_value)                  \
    do {                                                         \
        if (!m_isInitialized) {                                  \
            m_error = NotInitialized;                            \
            TRACE() << "CredentialsAccessManager not initialized."; \
            return return_value;                                \
        }                                                       \
    } while (0)

using namespace SignonDaemonNS;
using namespace SignOn;

/* ---------------------- CAMConfiguration ---------------------- */

CAMConfiguration::CAMConfiguration()
        : m_storagePath(QLatin1String(signonDefaultStoragePath)),
          m_dbName(QLatin1String(signonDefaultDbName)),
          m_useEncryption(signonDefaultUseEncryption),
          m_fileSystemType(QLatin1String(signonDefaultFileSystemType)),
          m_fileSystemSize(signonMinumumDbSize),
          m_encryptionPassphrase(QByteArray())
{}

void CAMConfiguration::serialize(QIODevice *device)
{
    if (device == NULL)
        return;

    if (!device->open(QIODevice::ReadWrite)) {
        return;
    }

    QString buffer;
    QTextStream stream(&buffer);
    stream << "\n\n====== Credentials Access Manager Configuration ======\n\n";
    stream << "File system mount name " << encryptedFSPath() << '\n';
    stream << "File system format: " << m_fileSystemType << '\n';
    stream << "File system size:" << m_fileSystemSize << "megabytes\n";

    const char *usingEncryption = m_useEncryption ? "true" : "false";
    stream << "Using encryption: " << usingEncryption << '\n';
    stream << "Credentials database name: " << m_dbName << '\n';
    stream << "======================================================\n\n";
    device->write(buffer.toUtf8());
    device->close();
}

QString CAMConfiguration::metadataDBPath() const
{
    return m_storagePath + QDir::separator() + m_dbName;
}

QString CAMConfiguration::encryptedFSPath() const
{
    return m_storagePath +
        QDir::separator() +
        QLatin1String(signonDefaultFileSystemName);
}

/* ---------------------- CredentialsAccessManager ---------------------- */

CredentialsAccessManager *CredentialsAccessManager::m_pInstance = NULL;

CredentialsAccessManager::CredentialsAccessManager(QObject *parent)
        : QObject(parent),
          m_isInitialized(false),
          m_systemOpened(false),
          m_error(NoError),
          keyManagers(),
          m_pCredentialsDB(NULL),
          m_pCryptoFileSystemManager(NULL),
          m_keyHandler(NULL),
          m_keyAuthorizer(NULL),
          m_CAMConfiguration(CAMConfiguration())
{
    m_keyHandler = new SignOn::KeyHandler(this);
}

CredentialsAccessManager::~CredentialsAccessManager()
{
    closeCredentialsSystem();

    m_pInstance = NULL;
}

CredentialsAccessManager *CredentialsAccessManager::instance(QObject *parent)
{
    if (!m_pInstance)
        m_pInstance = new CredentialsAccessManager(parent);

    return m_pInstance;
}

void CredentialsAccessManager::finalize()
{
    if (m_systemOpened)
        closeCredentialsSystem();

    if (m_pCryptoFileSystemManager)
        delete m_pCryptoFileSystemManager;

    // Disconnect all key managers
    foreach (SignOn::AbstractKeyManager *keyManager, keyManagers)
        keyManager->disconnect();

    m_isInitialized = false;
    m_error = NoError;
}

bool CredentialsAccessManager::init(const CAMConfiguration &camConfiguration)
{
    if (m_isInitialized) {
        TRACE() << "CAM already initialized.";
        m_error = AlreadyInitialized;
        return false;
    }

    m_CAMConfiguration = camConfiguration;

    QBuffer config;
    m_CAMConfiguration.serialize(&config);
    TRACE() << "\n\nInitualizing CredentialsAccessManager with configuration: " << config.data();

    if (!createStorageDir()) {
        BLAME() << "Failed to create storage directory.";
        return false;
    }

    if (!openMetaDataDB()) {
        BLAME() << "Failed to create metadata DB!!!";
        return false;
    }

    if (m_CAMConfiguration.m_useEncryption) {
        //Initialize CryptoManager
        m_pCryptoFileSystemManager = new SignOn::CryptoManager(this);
        QObject::connect(m_pCryptoFileSystemManager, SIGNAL(fileSystemMounted()),
                         this, SLOT(onEncryptedFSMounted()),
                         Qt::UniqueConnection);
        QObject::connect(m_pCryptoFileSystemManager, SIGNAL(fileSystemUnmounting()),
                         this, SLOT(onEncryptedFSUnmounting()),
                         Qt::UniqueConnection);

        m_pCryptoFileSystemManager->setFileSystemPath(m_CAMConfiguration.encryptedFSPath());

        m_pCryptoFileSystemManager->setFileSystemSize(m_CAMConfiguration.m_fileSystemSize);
        m_pCryptoFileSystemManager->setFileSystemType(m_CAMConfiguration.m_fileSystemType);

#ifdef SIGNON_AEGISFS
        m_pCryptoFileSystemManager->setAegisFSFileSystemPath(m_CAMConfiguration.m_aegisPath);
#endif

        if (m_keyAuthorizer == 0) {
            TRACE() << "No key authorizer set, using default";
            m_keyAuthorizer = new DefaultKeyAuthorizer(m_keyHandler, this);
        }

        QObject::connect(m_keyAuthorizer,
                         SIGNAL(keyAuthorizationQueried(const SignOn::Key,int)),
                         this,
                         SLOT(onKeyAuthorizationQueried(const SignOn::Key,int)));

        /* These signal connections should be done after instantiating the
         * KeyAuthorizer, so that the KeyAuthorizer's slot will be called
         * first (or we could connect to them in queued mode)
         */

#ifndef SIGNON_AEGISFS
        QObject::connect(m_keyHandler, SIGNAL(ready()),
                         this, SIGNAL(credentialsSystemReady()));
#endif
        QObject::connect(m_keyHandler, SIGNAL(keyInserted(SignOn::Key)),
                         this, SLOT(onKeyInserted(SignOn::Key)));

        QObject::connect(m_keyHandler,
                         SIGNAL(lastAuthorizedKeyRemoved(SignOn::Key)),
                         this,
                         SLOT(onLastAuthorizedKeyRemoved(SignOn::Key)));

        QObject::connect(m_keyHandler, SIGNAL(keyRemoved(SignOn::Key)),
                         this, SLOT(onKeyRemoved(SignOn::Key)));

#ifdef SIGNON_AEGISFS
        QObject::connect(m_keyHandler, SIGNAL(ready()),
                         this, SLOT(onKeyHandlerReady()),
                         Qt::QueuedConnection);
#endif

        m_keyHandler->initialize(m_pCryptoFileSystemManager, keyManagers);
    }

    m_isInitialized = true;
    m_error = NoError;

    TRACE() << "CredentialsAccessManager successfully initialized...";
    return true;
}

void CredentialsAccessManager::addKeyManager(
    SignOn::AbstractKeyManager *keyManager)
{
    if (keyManager) {
        keyManagers.append(keyManager);
    }
}

bool CredentialsAccessManager::initExtension(QObject *plugin, bool isDefaultKey)
{
    bool extensionInUse = false;
    bool defaultKeyExtension = false;

#ifdef SIGNON_AEGISFS
    defaultKeyExtension = isDefaultKey;
    TRACE() << "default key " << isDefaultKey;
#endif

    SignOn::ExtensionInterface *extension;
    SignOn::ExtensionInterface2 *extension2;

    extension2 = qobject_cast<SignOn::ExtensionInterface2 *>(plugin);
    if (extension2 != 0)
        extension = extension2;
    else
        extension = qobject_cast<SignOn::ExtensionInterface *>(plugin);

    if (extension == 0) {
        qWarning() << "Plugin instance is not an ExtensionInterface";
        return false;
    }

    SignOn::AbstractKeyManager *keyManager = extension->keyManager(this);
    if (keyManager) {
        if (!defaultKeyExtension) {
            keyManagerExtensions.append(extension);
            keyManagers.append(keyManager);
        } else {
            keyManagerExtensions.prepend(extension);
            keyManagers.prepend(keyManager);
        }

        extensionInUse = true;
    }

    /* Check if the extension implements the new interface and provides a key
     * authorizer. */
    if (extension2 != 0) {
        SignOn::AbstractKeyAuthorizer *keyAuthorizer =
            extension2->keyAuthorizer(m_keyHandler, this);
        if (keyAuthorizer != 0) {
            if (m_keyAuthorizer == 0) {
                m_keyAuthorizer = keyAuthorizer;
                extensionInUse = true;
            } else {
                TRACE() << "Key authorizer already set";
            }
        }
    }

    return extensionInUse;
}

bool CredentialsAccessManager::openSecretsDB()
{
    QString dbPath;

    if (m_CAMConfiguration.m_useEncryption) {

#ifndef SIGNON_AEGISFS
        if (!m_pCryptoFileSystemManager->fileSystemIsMounted()) {
            /* Do not attempt to mount the FS; we know that it will be mounted
             * automatically, as soon as some encryption keys are provided */
            m_error = CredentialsDbNotMounted;
            return false;
        }
#endif
       QString luksDBPath = m_pCryptoFileSystemManager->fileSystemMountPath()
                            + QDir::separator()
                            + m_CAMConfiguration.m_dbName;
       dbPath = luksDBPath;

#ifdef SIGNON_AEGISFS
        QString aegisDBName = m_CAMConfiguration.m_aegisPath
                              + QDir::separator()
                              + m_CAMConfiguration.m_dbName;

        QFile restoreFile(restoreFilePath());
        if (restoreFile.exists() == true)
        {
            QString luksKeychainName = m_CAMConfiguration.m_encryptedStoragePath
                                       + QDir::separator()
                                       + QLatin1String("keychain");

            QString aegisKeychainName = m_CAMConfiguration.m_aegisPath
                                        + QDir::separator()
                                        + QLatin1String("keychain");

            TRACE() << "RestoreFile found: copying database from " << dbPath << " to " << aegisDBName;
            m_pCredentialsDB->closeSecretsDB();

            QFile::remove(aegisDBName);
            QFile::remove(aegisKeychainName);

            if (!m_pCryptoFileSystemManager->fileSystemIsMounted()) {
                TRACE() << "File system was not mounted: removing signonfs";
                QFile::remove(m_CAMConfiguration.encryptedFSPath());
            } else {

                bool copyRes = QFile::copy(luksDBPath, aegisDBName);
                TRACE() << "Copy of database completed with result :" << copyRes;

                copyRes = QFile::copy(luksKeychainName, aegisKeychainName);
                TRACE() << "Copy of keychain completed with result :" << copyRes;

                QFile::remove(luksDBPath);
                QFile::remove(luksKeychainName);
            }

            QFile::remove(restoreFilePath());
            SignOn::AbstractKeyManager *defaultKeyManager = keyManagers.first();

            if (m_keyHandler->isKeyManagerActive(defaultKeyManager) == false) {

                TRACE() << "Restarting default-key handling";

                deleteDefaultKeyStorage();
                defaultKeyManager->disconnect();
                delete defaultKeyManager;

                keyManagers.removeFirst();

                keyManagers.prepend(keyManagerExtensions.first()->keyManager(this));
                m_keyHandler->initialize(m_pCryptoFileSystemManager, keyManagers);

                TRACE() << "Reinitialization of default key completed";
            }
        } else {
            TRACE() << "No restoreFile found";
            QFile newDbFile(aegisDBName);

            if (newDbFile.exists() == false) {
                QFile oldDbFile(luksDBPath);

                if (oldDbFile.exists() == true) {
                    TRACE() << "first start after signon update: copying of old DB into new location";

                    QFile::copy(luksDBPath, aegisDBName);
                    QFile::remove(luksDBPath);
                }
            }
        }

        dbPath = aegisDBName;
#endif
    } else {
        dbPath = m_CAMConfiguration.metadataDBPath() + QLatin1String(".creds");
    }

    TRACE() << "Database name: [" << dbPath << "]";

#ifndef SIGNON_AEGISFS
    if (!m_pCredentialsDB->openSecretsDB(dbPath))
        return false;
#else
    if (!isSecretsDBOpen() && !m_pCredentialsDB->openSecretsDB(dbPath)) {
        //a workaround aimed on solving possible problems with aegisfs
        QFile::remove(dbPath);
        if (!m_pCredentialsDB->openSecretsDB(dbPath))
            return false;
    }
#endif

    m_error = NoError;
    return true;
}

bool CredentialsAccessManager::isSecretsDBOpen() const
{
    return m_pCredentialsDB->isSecretsDBOpen();
}

bool CredentialsAccessManager::closeSecretsDB()
{
    m_pCredentialsDB->closeSecretsDB();

    if (m_CAMConfiguration.m_useEncryption) {
        if (!m_pCryptoFileSystemManager->unmountFileSystem()) {
            m_error = CredentialsDbUnmountFailed;
            return false;
        }
    }

    return true;
}

bool CredentialsAccessManager::createStorageDir()
{
    QString dbPath = m_CAMConfiguration.metadataDBPath();

    QFileInfo fileInfo(dbPath);
    if (!fileInfo.exists()) {
        QDir storageDir(fileInfo.dir());
        if (!storageDir.mkpath(storageDir.path())) {
            BLAME() << "Could not create storage directory:" <<
                storageDir.path();
            m_error = CredentialsDbSetupFailed;
            return false;
        }
        setUserOwnership(storageDir.path());
    }
    return true;
}

bool CredentialsAccessManager::openMetaDataDB()
{
    if (m_pCredentialsDB)
        return true;

    QString dbPath = m_CAMConfiguration.metadataDBPath();

    m_pCredentialsDB = new CredentialsDB(dbPath);

    if (!m_pCredentialsDB->init()) {
        m_error = CredentialsDbConnectionError;
        delete m_pCredentialsDB;
        m_pCredentialsDB = NULL;

        return false;
    }

    return true;
}

void CredentialsAccessManager::closeMetaDataDB()
{
    if (m_pCredentialsDB) {
        delete m_pCredentialsDB;
        m_pCredentialsDB = NULL;
    }
}

bool CredentialsAccessManager::openCredentialsSystem()
{
    RETURN_IF_NOT_INITIALIZED(false);

    if (!openMetaDataDB()) {
        BLAME() << "Couldn't open metadata DB!";
        return false;
    }

    m_systemOpened = true;

    if (m_pCryptoFileSystemManager == 0 ||
        m_pCryptoFileSystemManager->fileSystemIsMounted()) {
        if (!isSecretsDBOpen() && !openSecretsDB()) {
            BLAME() << "Failed to open secrets DB.";
            /* Even if the secrets DB couldn't be opened, signond is still
             * usable: that's why we return "true" anyways. */
        }
    } else {
        /* The secrets DB will be re-opened as soon as the encrypted FS is
         * mounted.
         */
        m_pCryptoFileSystemManager->mountFileSystem();
    }

    return true;
}

bool CredentialsAccessManager::closeCredentialsSystem()
{
    RETURN_IF_NOT_INITIALIZED(false);

    if (!credentialsSystemOpened())
        return true;

    bool allClosed = true;
    if (isSecretsDBOpen() && !closeSecretsDB())
        allClosed = false;

    closeMetaDataDB();

    m_error = NoError;
    m_systemOpened = false;
    return allClosed;
}

bool CredentialsAccessManager::deleteCredentialsSystem()
{
    RETURN_IF_NOT_INITIALIZED(false);

    if (m_systemOpened && !closeCredentialsSystem()) {
        /* The close operation failed: we cannot proceed */
        return false;
    }

    m_error = NoError;

    if (m_CAMConfiguration.m_useEncryption) {
        if (!m_pCryptoFileSystemManager->deleteFileSystem())
            m_error = CredentialsDbDeletionFailed;
    } else {
        QFile dbFile(m_CAMConfiguration.m_dbName);
        if (dbFile.exists()) {
            if (!dbFile.remove())
                m_error = CredentialsDbDeletionFailed;
        }
    }

#ifdef SIGNON_AEGISFS
        QString aegisDBName = m_CAMConfiguration.m_aegisPath
                              + QDir::separator()
                              + m_CAMConfiguration.m_dbName;

        QString aegisKeychainName = m_CAMConfiguration.m_aegisPath
                                    + QDir::separator()
                                    + QLatin1String("keychain");

        QFile::remove(aegisDBName);
        QFile::remove(aegisKeychainName);
#endif

    return m_error == NoError;
}

CredentialsDB *CredentialsAccessManager::credentialsDB() const
{
    RETURN_IF_NOT_INITIALIZED(NULL);

    return m_pCredentialsDB;
}

bool CredentialsAccessManager::isCredentialsSystemReady() const
{
#ifdef SIGNON_AEGISFS
    return (m_keyHandler != 0) ? (m_keyHandler->isReady() || isSecretsDBOpen()) : true;
#else
    return (m_keyHandler != 0) ? m_keyHandler->isReady() : true;
#endif
}

void CredentialsAccessManager::onKeyInserted(const SignOn::Key key)
{
    TRACE() << "Key inserted.";

    if (!m_keyHandler->keyIsAuthorized(key))
        m_keyAuthorizer->queryKeyAuthorization(
            key, AbstractKeyAuthorizer::KeyInserted);
}

#ifdef SIGNON_AEGISFS
void CredentialsAccessManager::onKeyHandlerReady()
{
    TRACE();

    if (!isSecretsDBOpen())
        openSecretsDB();

    emit credentialsSystemReady();
}
#endif

void CredentialsAccessManager::onLastAuthorizedKeyRemoved(const SignOn::Key key)
{
    //Would everything be ok for now
    //this event would never be handled
    //as we always have the default key

    Q_UNUSED(key);
    TRACE() << "All keys disabled. Closing secure storage.";
#ifndef SIGNON_AEGISFS
    if (isSecretsDBOpen() || m_pCryptoFileSystemManager->fileSystemIsMounted())
        if (!closeSecretsDB())
            BLAME() << "Error occurred while closing secure storage.";
#endif
}

void CredentialsAccessManager::onKeyRemoved(const SignOn::Key key)
{
    TRACE() << "Key removed.";

    if (m_keyHandler->keyIsAuthorized(key)) {
        if (!m_keyHandler->revokeKeyAuthorization(key)) {
            BLAME() << "Revoking key authorization failed";
        }
    }
}

void CredentialsAccessManager::onKeyAuthorizationQueried(const SignOn::Key key,
                                                         int result)
{
    TRACE() << "result:" << result;

    if (result != AbstractKeyAuthorizer::Denied) {
        KeyHandler::AuthorizeFlags flags = KeyHandler::None;
        if (result == AbstractKeyAuthorizer::Exclusive) {
            TRACE() << "Reformatting secure storage.";
            flags |= KeyHandler::FormatStorage;
        }

        if (!m_keyHandler->authorizeKey(key, flags)) {
            BLAME() << "Authorization failed";
        }
    }

    replyToSecureStorageEventNotifiers();
}

bool CredentialsAccessManager::keysAvailable() const
{
    if (m_keyHandler == 0) return false;
    return !m_keyHandler->insertedKeys().isEmpty();
}

void CredentialsAccessManager::replyToSecureStorageEventNotifiers()
{
    TRACE();
    //Notify secure storage notifiers if any.
    int eventType = SIGNON_SECURE_STORAGE_NOT_AVAILABLE;
    if ((m_pCredentialsDB != 0) && m_pCredentialsDB->isSecretsDBOpen())
        eventType = SIGNON_SECURE_STORAGE_AVAILABLE;

    // Signal objects that posted secure storage not available events
    foreach (EventSender object, m_secureStorageEventNotifiers) {
        if (object.isNull())
            continue;

        SecureStorageEvent *secureStorageEvent =
            new SecureStorageEvent((QEvent::Type)eventType);

        QCoreApplication::postEvent(
            object.data(),
            secureStorageEvent,
            Qt::HighEventPriority);
    }

    m_secureStorageEventNotifiers.clear();
}

void CredentialsAccessManager::customEvent(QEvent *event)
{
    TRACE() << "Custom event received.";
    if (event->type() != SIGNON_SECURE_STORAGE_NOT_AVAILABLE) {
        QObject::customEvent(event);
        return;
    }

    SecureStorageEvent *localEvent =
        static_cast<SecureStorageEvent *>(event);

    /* All senders of this event will receive a reply when
     * the secure storage becomes available or an error occurs. */
    m_secureStorageEventNotifiers.append(localEvent->m_sender);

    TRACE() << "Processing secure storage not available event.";
    if ((localEvent == 0) || (m_pCredentialsDB == 0)) {
        replyToSecureStorageEventNotifiers();
        QObject::customEvent(event);
        return;
    }

    //Double check if the secrets DB is indeed unavailable
    if (m_pCredentialsDB->isSecretsDBOpen()) {
        replyToSecureStorageEventNotifiers();
        QObject::customEvent(event);
        return;
    }

    SignOn::Key key; /* we don't specity any key */
    m_keyAuthorizer->queryKeyAuthorization(key,
                                           AbstractKeyAuthorizer::StorageNeeded);

    QObject::customEvent(event);
}

void CredentialsAccessManager::onEncryptedFSMounted()
{
    TRACE();
    if (!credentialsSystemOpened()) return;

    if (!isSecretsDBOpen()) {
        if (openSecretsDB()) {
            TRACE() << "Secrets DB opened.";
        } else {
            BLAME() << "Failed to open secrets DB.";
        }
    } else {
        BLAME() << "Secrets DB already opened?";
    }
}

void CredentialsAccessManager::onEncryptedFSUnmounting()
{
    TRACE();

    if (!credentialsSystemOpened()) return;

#ifndef SIGNON_AEGISFS
    //We do not need to unmount anything here if we're using aegisfs
    if (isSecretsDBOpen()) {
        m_pCredentialsDB->closeSecretsDB();
    }
#endif
}

const QString CredentialsAccessManager::restoreFilePath() const
{
    return QLatin1String(signonDefaultStoragePath)
           + QDir::separator()
           + QLatin1String(signonRestoreFileName);
}

void CredentialsAccessManager::deleteDefaultKeyStorage() const {
    //TODO: remove this ugly hack later
    QString defaultCodePath(QLatin1String("/home/user/.aegis/ps/Pe/signon_aegis_default_key_storage"));
    TRACE() << "Removing old default code: " << defaultCodePath;
    QFile::remove(defaultCodePath);
}
