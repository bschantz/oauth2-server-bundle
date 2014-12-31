<?php
/**
 * User: Brian Schantz
 * Date: 12/17/14
 * Time: 8:45 AM
 */
namespace OAuth2\ServerBundle\Security\Authentication\Provider;

use OAuth2\Encryption\Jwt;
use OAuth2\Server;
use OAuth2\ServerBundle\Security\Token\JwtOAuthToken;
use OAuth2\Storage\PublicKeyInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class OAuthIdTokenProvider implements AuthenticationProviderInterface
{
    /** @var $userProvider UserProviderInterface */
    protected $userProvider;

    /** @var $server Server */
    protected $server;

    /** @var $publicKey PublicKeyInterface */
    protected $publicKey;

    public function __construct(UserProviderInterface $userProvider, Server $oauthServer, PublicKeyInterface $publicKey)
    {
        $this->userProvider = $userProvider;
        $this->server = $oauthServer;
        $this->publicKey = $publicKey;
    }

    /**
     * Attempts to authenticate a TokenInterface object.
     *
     * @param TokenInterface $token The TokenInterface instance to authenticate
     * @return TokenInterface An authenticated TokenInterface instance, never null
     * @throws AuthenticationException if the authentication fails
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$token instanceof JwtOAuthToken) {
            throw new AuthenticationException("Invalid token");
        }
        $jwt = $token->getToken();
        // decode token
        $j = new Jwt();

        if (!($decodedToken = $j->decode($jwt, $this->publicKey->getPublicKey()))) {
            throw new AuthenticationException("Could not decode token");
        }
        $user = $this->userProvider->loadUserByUsername($decodedToken['sub']);
        if (!$user) {
            throw new AuthenticationException("Invalid subject");
        }
        $authenticatedToken = new JwtOAuthToken($user->getRoles());
        $authenticatedToken->setUser($user);
        $authenticatedToken->setAuthenticated(true);
        return $authenticatedToken;
    }

    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token A TokenInterface instance
     * @return bool true if the implementation supports the Token, false otherwise
     */
    public function supports(TokenInterface $token)
    {
        return ($token instanceof JwtOAuthToken);
    }
}
