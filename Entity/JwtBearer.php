<?php
/**
 * User: Brian Schantz
 * Date: 12/3/14
 * Time: 2:16 PM
 */

namespace OAuth2\ServerBundle\Entity;


class JwtBearer
{

    /** @var string $client */
    protected $client;

    /** @var string $jwt */
    private $jwt;

    /** @var string $jti */
    private $jti;

    /** @var int $notBefore */
    private $notBefore;

    /** @var int $issuedAt */
    private $issuedAt;

    /** @var int $expires */
    private $expires;

    /** @var string $audience */
    private $audience;

    /** @var string $scope */
    private $scope;

    /**
     * @return string
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @param string $scope
     * @return JwtBearer
     */
    public function setScope($scope)
    {
        $this->scope = $scope;
        return $this;
    }

    /**
     * @return string
     */
    public function getJti()
    {
        return $this->jti;
    }

    /**
     * @param string $jti
     * @return JwtBearer
     */
    public function setJti($jti)
    {
        $this->jti = $jti;
        return $this;
    }

    /**
     * @return string
     */
    public function getAudience()
    {
        return $this->audience;
    }

    /**
     * @param string $audience
     * @return JwtBearer
     */
    public function setAudience($audience)
    {
        $this->audience = $audience;
        return $this;
    }

    /**
     * @return int
     */
    public function getNotBefore()
    {
        return $this->notBefore;
    }

    /**
     * @param int $notBefore
     * @return JwtBearer
     */
    public function setNotBefore($notBefore)
    {
        $this->notBefore = $notBefore;
        return $this;
    }

    /**
     * @return string
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * @param string $client
     * @return JwtBearer
     */
    public function setClient($client)
    {
        $this->client = $client;
        return $this;
    }

    /**
     * @return int
     */
    public function getExpires()
    {
        return $this->expires;
    }

    /**
     * @param int $expires
     * @return JwtBearer
     */
    public function setExpires($expires)
    {
        $this->expires = $expires;
        return $this;
    }

    /**
     * @return \DateTime
     */
    public function getIssuedAt()
    {
        return $this->issuedAt;
    }

    /**
     * @param \DateTime $issuedAt
     * @return JwtBearer
     */
    public function setIssuedAt($issuedAt)
    {
        $this->issuedAt = $issuedAt;
        return $this;
    }

    /**
     * @return string
     */
    public function getJwt()
    {
        return $this->jwt;
    }

    /**
     * @param string $jwt
     * @return JwtBearer
     */
    public function setJwt($jwt)
    {
        $this->jwt = $jwt;
        return $this;
    }

}
 