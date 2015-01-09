<?php
/**
 * User: Brian Schantz
 * Date: 1/9/15
 * Time: 11:59 AM
 */

namespace OAuth2\ServerBundle\Security\Authentication\Provider;


use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\SimplePreAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Authenticate via username and password in request parameters.
 *
 * Allows authentication by passing username and password in request parameters. Required for
 * OpenID Connect Resource Owner Credentials flow. Obviously, this should only be used over HTTPS!
 *
 * Based on APIKeyAuthenticator described at {@link http://symfony.com/doc/current/cookbook/security/api_key_authentication.html}
 *
 * @package OAuth2\ServerBundle\Security\Authentication\Provider
 */
class UsernamePasswordRequestProvider implements SimplePreAuthenticatorInterface
{

    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * @param UserProviderInterface $userProvider
     */
    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    /**
     * @param Request $request
     * @param string $providerKey
     * @return UsernamePasswordToken
     */
    public function createToken(Request $request, $providerKey)
    {
        if (!$userName = $request->get('username')) {
            throw new BadCredentialsException('Request parameter \'username\' not given.');
        }
        if (!$password = $request->get('password')) {
            throw new BadCredentialsException('Request parameter \'password\' not given.');
        }
        return new UsernamePasswordToken($userName, $password, $providerKey);
    }

    /**
     * @param TokenInterface $token
     * @param UserProviderInterface $userProvider
     * @param string $providerKey
     * @return UsernamePasswordToken
     */
    public function authenticateToken(TokenInterface $token, UserProviderInterface $userProvider, $providerKey)
    {
        if ($user = $token->getUser()) {
            if ($user instanceof UserInterface) {
                return new UsernamePasswordToken(
                        $user,
                        $token->getCredentials(),
                        $providerKey,
                        $user->getRoles()
                );
            }
        }
        $user = $userProvider->loadUserByUsername($token->getUsername());
        if (!$user) {
            throw new AuthenticationException("Cannot find user '{$token->getUsername()}.'");
        }

        return new UsernamePasswordToken(
                $user,
                $token->getCredentials(),
                $providerKey,
                $user->getRoles()
        );
    }

    /**
     * @param TokenInterface $token
     * @param string $providerKey
     * @return bool
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey() === $providerKey;
    }
}
