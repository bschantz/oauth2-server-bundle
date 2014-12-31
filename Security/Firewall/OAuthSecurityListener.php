<?php
/**
 * User: Brian Schantz
 * Date: 12/8/14
 * Time: 1:22 PM
 */
namespace OAuth2\ServerBundle\Security\Firewall;

use OAuth2\HttpFoundationBridge\Request as BridgeRequest;
use OAuth2\ServerBundle\Security\Token\JwtOAuthToken;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class OAuthSecurityListener implements ListenerInterface
{

    protected $securityContext;
    protected $authenticationManager;

    public function __construct(
            SecurityContext $context,
            AuthenticationManagerInterface $authenticationManager
    ) {
        $this->securityContext = $context;
        $this->authenticationManager = $authenticationManager;
    }

    /**
     * This interface must be implemented by firewall listeners.
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        $request = BridgeRequest::createFromGlobals();
        $auth = explode(' ', $request->headers->get('Authorization'));
        if ($auth[0] == 'Bearer') {
            $tokenString = $auth[1];
        } else {
            return;
        }

        $token = new JwtOAuthToken();
        $token->setToken($tokenString);

        // verify token
        try {
            $authToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authToken);
            return;
        } catch (AuthenticationException $exc) {
            throw $exc;
        }
    }

}
 