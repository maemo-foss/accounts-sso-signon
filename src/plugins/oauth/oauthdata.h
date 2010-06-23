#ifndef OAUTHDATA_H
#define OAUTHDATA_H

#include "sessiondata.h"

namespace OAuthPluginNS {

enum OAuthSignatureType
{
    HMACSHA1,
    PLAINTEXT,
    RSASHA1
};

/*!
 * @class OAuthData
 * Data container to hold values for authentication session.
 */
class OAuthData : public SignOn::SessionData
{
public:
    /*!
     * Declare property Example setter and getter
     */
    SIGNON_SESSION_DECLARE_PROPERTY(QByteArray, Token);
    SIGNON_SESSION_DECLARE_PROPERTY(QString, Server);
    SIGNON_SESSION_DECLARE_PROPERTY(QString, Proxy);
    SIGNON_SESSION_DECLARE_PROPERTY(OAuthSignatureType, SignatureMethod);
    SIGNON_SESSION_DECLARE_PROPERTY(QString, ConsumerKey);
    SIGNON_SESSION_DECLARE_PROPERTY(QString, ConsumerSecret);
    SIGNON_SESSION_DECLARE_PROPERTY(int, Error);
};
/*
  #consumer key:     =digest
  #consumer secret:  =digest
  #token:
  token secret:
  #signature method:
  #server endpoint:
  #server proxy:
*/

/*
    info.setProxy(QString("http://172.16.42.133:8080"));
    info.setServer(QString("http://term.ie/oauth/example/"));
    info.setConsumerKey( QString("key"));
    info.setConsumerSecret( QString("secret"));

    info.setUserName(QString("idmtestuser"));  =from base interface
    info.setSecret(QString("secret"));         =from base interface
*/

} // namespace OAuthPluginNS

#endif // OAUTHDATA_H
