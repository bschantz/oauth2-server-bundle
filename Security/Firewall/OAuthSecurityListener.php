<?php
/**
 * User: bschantz
 * Date: 12/8/14
 * Time: 1:22 PM
 */
namespace OAuth2\ServerBundle\Security\Firewall;

use OAuth2\Encryption\Jwt;
use OAuth2\ServerBundle\Security\OAuthToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Csrf\TokenStorage\TokenStorageInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class OAuthSecurityListener implements ListenerInterface
{

    protected $securityContext;

    protected $tokenStorage;

    public function __construct(
            SecurityContext $context,
            TokenStorageInterface $storage,
            AuthenticationManagerInterface $authenticationManager
    ) {
        $this->securityContext = $context;
        $this->tokenStorage = $storage;
        $this->authenticationManager = $authenticationManager;
    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        $auth = explode(' ', $request->headers->get('Authorization'));
        if ($auth[0] == 'Bearer') {
            $jwt = $auth[1];
        } else {
            return;
        }

        $token = new OAuthToken();

        // verify token
        try {
            $this->authenticationManager->authenticate($token);
        } catch (AuthenticationException $exc) {
            throw $exc;
        }
    }

    /**
     * Performs authentication.
     *
     * @param Request $request A Request instance
     *
     * @return TokenInterface|Response|null The authenticated token, null if full authentication is not possible, or a Response
     *
     * @throws AuthenticationException if the authentication fails
     */
    protected function attemptAuthentication(Request $request)
    {

    }
}
 