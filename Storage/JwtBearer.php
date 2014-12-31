<?php
/**
 * User: Brian Schantz
 * Date: 12/4/14
 * Time: 10:14 AM
 */

namespace OAuth2\ServerBundle\Storage;


use Doctrine\ORM\EntityManager;
use OAuth2\Storage\JwtBearerInterface;

class JwtBearer implements JwtBearerInterface
{

    private $em;

    /**
     * @param EntityManager $em
     */
    public function __construct(EntityManager $em)
    {
        $this->em = $em;
    }

    /**
     * Get the public key associated with a client_id
     *
     * @param string $client_id
     * Client identifier to be checked with.
     *
     * @param string $subject
     *
     * @return string
     * STRING Return the public key for the client_id if it exists, and MUST return FALSE if it doesn't.
     */
    public function getClientKey($client_id, $subject)
    {
        $repo = $this->em->getRepository('OAuth2ServerBundle:ClientPublicKey');

        $key = $repo->find($client_id);

        // return public key || false
        if ($key) {
            return $key->getPublicKey();
        } else {
            return false;
        }
    }

    /**
     * Get a jti (JSON token identifier) by matching against the client_id, subject, audience and expiration.
     *
     * @param $client_id
     * Client identifier to match.
     *
     * @param $subject
     * The subject to match.
     *
     * @param $audience
     * The audience to match.
     *
     * @param $expiration
     * The expiration of the jti.
     *
     * @param $jti
     * The jti to match.
     *
     * @return array|null
     * An associative array as below, and return NULL if the jti does not exist.
     * - issuer: Stored client identifier.
     * - subject: Stored subject.
     * - audience: Stored audience.
     * - expires: Stored expiration in unix timestamp.
     * - jti: The stored jti.
     */
    public function getJti($client_id, $subject, $audience, $expiration, $jti)
    {
        // get jwt repository
        $repo = $this->em->getRepository('OAuth2ServerBundle:Entity:JwtBearer');
    }

    /**
     * Store a used jti so that we can check against it to prevent replay attacks.
     * @param $client_id
     * Client identifier to insert.
     *
     * @param $subject
     * The subject to insert.
     *
     * @param $audience
     * The audience to insert.
     *
     * @param $expiration
     * The expiration of the jti.
     *
     * @param $jti
     * The jti to insert.
     */
    public function setJti($client_id, $subject, $audience, $expiration, $jti)
    {
        // TODO: Implement setJti() method.
    }
}
 