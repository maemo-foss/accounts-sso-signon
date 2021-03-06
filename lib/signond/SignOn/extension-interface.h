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
/*!
 * @copyright Copyright (C) 2009-2011 Nokia Corporation.
 * @license LGPL
 */

#ifndef SIGNON_EXTENSION_INTERFACE_H
#define SIGNON_EXTENSION_INTERFACE_H

#include <SignOn/export.h>

#include <QObject>
#include <QtPlugin>

namespace SignOn {

class AbstractKeyAuthorizer;
class AbstractKeyManager;
class KeyHandler;

/*!
 * @class ExtensionInterface.
 * Interface definition for signond extensions.
 */
class SIGNON_EXPORT ExtensionInterface
{
public:
    virtual ~ExtensionInterface() {}

    /*!
     * Gets the KeyManager object.
     *
     * @return A key manager object, or 0 if none is provided by this plugin
     */
    virtual AbstractKeyManager *keyManager(QObject *parent = 0) const = 0;
};

/*!
 * @class ExtensionInterface2.
 * Interface definition for signond extensions.
 */
class SIGNON_EXPORT ExtensionInterface2: public ExtensionInterface
{
public:
    virtual ~ExtensionInterface2() {}

    /*!
     * Gets the KeyAuthorizer object.
     *
     * @return A key authorizer object, or 0 if none is provided by this plugin
     */
    virtual AbstractKeyAuthorizer *keyAuthorizer(KeyHandler *keyHandler,
                                                 QObject *parent = 0) const = 0;
};

} // namespace

Q_DECLARE_INTERFACE(SignOn::ExtensionInterface,
                    "com.nokia.SingleSignOn.ExtensionInterface/1.0")
Q_DECLARE_INTERFACE(SignOn::ExtensionInterface2,
                    "com.nokia.SingleSignOn.ExtensionInterface/2.0")

#endif // SIGNON_EXTENSION_INTERFACE_H
