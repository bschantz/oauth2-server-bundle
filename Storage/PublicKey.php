<?php
/**
 * User: Brian Schantz
 * Date: 12/22/14
 * Time: 3:39 PM
 */

namespace OAuth2\ServerBundle\Storage;


use OAuth2\Storage\PublicKeyInterface;
use Symfony\Component\HttpFoundation\File\Exception\FileNotFoundException;

class PublicKey implements PublicKeyInterface
{
    private $publicKey;
    private $privateKey;
    private $algorithm;

    public function __construct($publicKeyFile, $privateKeyFile, $algorithm)
    {
        if (!file_exists($publicKeyFile)) {
            throw new FileNotFoundException('Public key file not found.');
        }
        $this->publicKey = file_get_contents($publicKeyFile);
        if (!file_exists($privateKeyFile)) {
            throw new FileNotFoundException('Private key file not found.');
        }
        $this->privateKey = file_get_contents($privateKeyFile);
        $this->algorithm = $algorithm;
    }

    public function getPublicKey($client_id = null)
    {
        return $this->publicKey;
    }

    public function getPrivateKey($client_id = null)
    {
        return $this->privateKey;
    }

    public function getEncryptionAlgorithm($client_id = null)
    {
        return $this->algorithm;
    }
}
