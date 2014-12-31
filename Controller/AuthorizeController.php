<?php

namespace OAuth2\ServerBundle\Controller;

use OAuth2\Server;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;

class AuthorizeController extends Controller
{
    /**
     * @Route("/authorize", name="_authorize_validate")
     * @Method({"GET"})
     * @Template("OAuth2ServerBundle:Authorize:authorize.html.twig")
     */
    public function validateAuthorizeAction()
    {
        $server = $this->get('oauth2.server');

        if (!$server->validateAuthorizeRequest($this->get('oauth2.request'), $this->get('oauth2.response'))) {
            return $server->getResponse();
        }

        // Get descriptions for scopes if available
        $scopes = array();
        $scopeStorage = $this->get('oauth2.storage.scope');
        foreach (explode(' ', $this->get('oauth2.request')->query->get('scope')) as $scope) {
            $scopes[] = $scopeStorage->getDescriptionForScope($scope);
        }

        return array('request' => $this->get('oauth2.request')->query->all(), 'scopes' => $scopes);
    }

    /**
     * @Route("/authorize", name="_authorize_handle")
     * @Method({"POST"})
     */
    public function handleAuthorizeAction()
    {
        /** @var Server $server */
        $server = $this->get('oauth2.server');

        // get the logged-in user -- this will be the subject if an id_token is issued
        $user = $this->get('security.context')->getToken()->getUser();
        $userId = $user ? $user->getEmailCanonical() : null;

        return $server->handleAuthorizeRequest($this->get('oauth2.request'), $this->get('oauth2.response'), true, $userId);
    }
}
