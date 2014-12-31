<?php
/**
 * User: Brian Schantz
 * Date: 12/22/14
 * Time: 7:27 PM
 */

namespace OAuth2\ServerBundle\OpenID\Storage;


use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIdAuthCodeInterface;
use OAuth2\ServerBundle\Storage\AuthorizationCode as BaseAuthorizationCode;

class AuthorizationCode extends BaseAuthorizationCode implements OpenIdAuthCodeInterface
{
    public function setAuthorizationCode(
            $code,
            $client_id,
            $user_id,
            $redirect_uri,
            $expires,
            $scope = null,
            $id_token = null
    ) {
        parent::setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope);
    }

}
