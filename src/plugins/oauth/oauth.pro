include( ../../../common-project-config.pri )
include( ../../../common-vars.pri )

TEMPLATE = lib
TARGET = oauthplugin
DESTDIR = ../../lib/signon
QT += core
QT -= gui

CONFIG += plugin \
        debug_and_release \
        build_all \
        warn_on \
        link_pkgconfig

HEADERS += oauthplugin.h \
           oauthdata.h \
           oauth-accountplugin.h \
           oauth-account-utils.h \
           oauth-util.h \
        ../../../include/authpluginif.h \
        ../../../include/signoncommon.h \
        ../../../include/sessiondata.h

SOURCES += oauthplugin.cpp \
           oauth-accountplugin.c \
           oauth-account-utils.c \
           oauth-util.c

INCLUDEPATH += . \
               ../ \
               ../../../include

QMAKE_CXXFLAGS += -fno-exceptions \
    -fno-rtti \
    -Wno-write-strings \
    -Wunused

PKGCONFIG += glib-2.0 \
             gobject-2.0 \
             libcurl \
             openssl

QMAKE_CLEAN += liboauth.so
headers.files = $$HEADERS
include( ../../../common-installs-config.pri )
target.path  = $${INSTALL_PREFIX}/lib/signon
INSTALLS = target
headers.path = $${INSTALL_PREFIX}/include/signon-plugins
INSTALLS += headers
pkgconfig.files = signon-oauthplugin.pc
pkgconfig.path = $${INSTALL_PREFIX}/lib/pkgconfig
INSTALLS += pkgconfig
