<?php

namespace OAuth2\ServerBundle\Manager;

use Doctrine\ORM\EntityManager;
use OAuth2\ServerBundle\Entity\Client;
use OAuth2\ServerBundle\Exception\ScopeNotFoundException;
use OAuth2\ServerBundle\Security\Token\OAuthAccessToken;

class ClientManager
{
    private $em;

    /**
     * @var ScopeManagerInterface
     */
    private $sm;

    public function __construct(EntityManager $entityManager, ScopeManagerInterface $scopeManager)
    {
        $this->em = $entityManager;
        $this->sm = $scopeManager;
    }

    /**
     * Creates a new client
     *
     * @param string $identifier
     * @param array $redirect_uris
     * @param array $grant_types
     * @param array $scopes
     *
     * @return Client
     * @throws ScopeNotFoundException
     * @internal param array $grant_type
     *
     */
    public function createClient($identifier, array $redirect_uris = array(), array $grant_types = array(), array $scopes = array())
    {
        $client = new Client();
        $client->setClientId($identifier);
        $client->setClientSecret($this->generateSecret());
        $client->setRedirectUri($redirect_uris);
        $client->setGrantTypes($grant_types);

        // Verify scopes
        foreach ($scopes as $scope) {
            // Get Scope
            $scopeObject = $this->sm->findScopeByScope($scope);
            if (!$scopeObject) {
                throw new ScopeNotFoundException();
            }
        }

        $client->setScopes($scopes);

        // Store Client
        $this->em->persist($client);
        $this->em->flush();

        return $client;
    }

    /**
     * Creates a secret for a client
     *
     * @return A secret
     */
    protected function generateSecret()
    {
        return base_convert(sha1(uniqid(mt_rand(), true)), 16, 36);
    }

    /**
     * @param string $tokenString
     * @return null|Client
     */
    public function findClientByAccessToken($tokenString)
    {
        $repo = $this->em->getRepository('OAuth2ServerBundle:Client');
        $client = $repo->findOneBy(array('token' => $tokenString));
        return $client;
    }
}
