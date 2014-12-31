<?php
/**
 * User: Brian Schantz
 * Date: 12/22/14
 * Time: 5:00 PM
 */

namespace OAuth2\ServerBundle\Storage;


use OAuth2\OpenID\Storage\UserClaimsInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

abstract class UserClaims implements UserClaimsInterface
{

    protected $userProvider;

    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    /**
     * Return claims about the provided user id.
     *
     * Groups of claims are returned based on the requested scopes. No group
     * is required, and no claim is required.
     *
     * @param $user_id
     * The id of the user for which claims should be returned.
     * @param $scope
     * The requested scope.
     * Scopes with matching claims: profile, email, address, phone.
     *
     * @return array
     * An array in the claim => value format.
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
     */
    public abstract function getUserClaims($user_id, $scope);
}
