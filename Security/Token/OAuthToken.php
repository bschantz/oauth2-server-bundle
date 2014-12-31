<?php
/**
 * User: Brian Schantz
 * Date: 12/8/14
 * Time: 1:27 PM
 */

namespace OAuth2\ServerBundle\Security\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;


/**
 * Class OAuthToken
 * @package OAuth2\ServerBundle\Security
 */
class OAuthToken extends AbstractToken
{
    private $token;

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @param string $token
     * @return OAuthToken
     */
    public function setToken($token)
    {
        $this->token = $token;
        return $this;
    }

    /**
     * Returns the user credentials.
     *
     * @return string The user credentials (token)
     */
    public function getCredentials()
    {
        return $this->getToken();
    }

}
 